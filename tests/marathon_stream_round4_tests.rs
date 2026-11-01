//! I-13 round 4: stream lifetime, framing edge cases and delta limits.

use active_infinity::stream::{
    encode_stream, DeltaOp, Frame, FrameKind, StreamDecoder, StreamEncoder, MAX_FRAME_PAYLOAD,
};
use active_infinity::{encode, Error, InfinityModule, Inode, Limits};

fn base_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("gateway".to_string()));
    let port = module.push(Inode::Int(8080));
    let root = module.push(Inode::Table {
        fields: vec![("name".to_string(), name), ("port".to_string(), port)],
    });
    module.set_root(Some(root));
    module.bind("gateway", root);
    let image = encode(&module).expect("encode");
    active_infinity::decode(&image).expect("decode")
}

fn replay(frames: &[Frame]) -> StreamDecoder {
    let mut decoder = StreamDecoder::new();
    for frame in frames {
        decoder.push(frame).expect("frame");
    }
    decoder
}

/// A repeat `End` with no delta re-encodes and re-validates the whole module:
/// 20 bare frames measured 22 s from 800 wire bytes.
#[test]
fn a_repeated_end_without_a_delta_is_refused() {
    let base = base_module();
    let frames = encode_stream(&base, 4096).expect("frames");
    let mut decoder = replay(&frames);
    let mut repeated = frames.last().expect("end").clone();
    repeated.sequence = decoder.frames();
    let error = decoder.push(&repeated).expect_err("a bare end is refused");
    assert_eq!(error.code(), "infinity/stream-state", "{error}");
}

/// A zero-op delta opens a generation for nothing; the closing `End` would then
/// re-encode the module.
#[test]
fn an_empty_delta_is_refused() {
    let base = base_module();
    let frames = encode_stream(&base, 4096).expect("frames");
    let mut decoder = replay(&frames);
    let empty = Frame {
        kind: FrameKind::Delta,
        sequence: decoder.frames(),
        payload: 0u32.to_le_bytes().to_vec(),
    };
    let error = decoder.push(&empty).expect_err("empty delta");
    assert_eq!(error.code(), "infinity/stream-delta", "{error}");
}

/// A frame past the wire ceiling is permanent: it can never become valid.
#[test]
fn a_frame_past_the_ceiling_is_not_incomplete() {
    let error = Error::StreamFrameLen {
        declared: MAX_FRAME_PAYLOAD + 1,
        available: 40,
    };
    assert!(!error.is_incomplete(), "{error}");
    assert!(error.is_fatal(), "{error}");
}

/// Fewer than four bytes cannot identify the format: a network reader must wait
/// instead of reporting corruption on its first read.
#[test]
fn a_short_magic_read_is_incomplete() {
    for len in 0..4 {
        let error = Frame::parse(&vec![b'A'; len]).expect_err("short buffer");
        assert_eq!(error.code(), "infinity/truncated", "{len}: {error}");
        assert!(error.is_incomplete(), "{len}: {error}");
    }
    let error = Frame::parse(b"XXXX").expect_err("wrong magic");
    assert_eq!(error.code(), "infinity/stream-magic", "{error}");
}

/// A refused batch must not advance the section cursor, or the next frame jumps
/// a section and leaves a hole that only surfaces at `End`.
#[test]
fn a_refused_batch_does_not_advance_the_section_cursor() {
    let base = base_module();
    let frames = encode_stream(&base, 4096).expect("frames");
    let mut decoder = StreamDecoder::new();
    decoder.push(&frames[0]).expect("begin");
    decoder.push(&frames[1]).expect("section 0");

    // A section-1 batch that overflows the declared generation size.
    let mut oversize = frames[2].clone();
    oversize.payload[0] = 1;
    oversize.payload.extend_from_slice(&vec![0u8; 1 << 20]);
    let len = u32::try_from(oversize.payload.len() - 9).expect("len");
    oversize.payload[5..9].copy_from_slice(&len.to_le_bytes());
    let error = decoder.push(&oversize).expect_err("size ceiling");
    assert_eq!(error.code(), "infinity/limit", "{error}");

    // Section 2 would leave section 1 unseen: the cursor is still at 0.
    let mut jump = frames[2].clone();
    jump.payload[0] = 2;
    jump.sequence = decoder.frames();
    let error = decoder.push(&jump).expect_err("a hole is refused");
    assert_eq!(error.code(), "infinity/stream-state", "{error}");
}

/// A decoder with a strict node ceiling merges a delta under that ceiling, not
/// the defaults.
#[test]
fn a_delta_merges_under_the_decoders_node_ceiling() {
    let base = base_module();
    let root = base.root().expect("root");
    let mut fragment = InfinityModule::new();
    let value = fragment.push(Inode::Str("replacement".into()));
    let table = fragment.push(Inode::Table {
        fields: vec![("value".into(), value)],
    });
    fragment.set_root(Some(table));

    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder
        .push_delta(
            &base,
            &[DeltaOp::PutNode {
                target: root,
                fragment: Box::new(fragment),
            }],
        )
        .expect("delta frames");

    let mut decoder = StreamDecoder::new().with_limits(Limits {
        max_nodes: 4,
        ..Limits::default()
    });
    let mut result = Ok(());
    for frame in encoder.frames() {
        result = decoder.push(&frame);
        if result.is_err() {
            break;
        }
    }
    let error = result.expect_err("the arena ceiling must fire during the merge");
    assert_eq!(error.code(), "infinity/limit", "{error}");
    assert!(
        error.to_string().contains("stream arena nodes"),
        "the merge ceiling must fire before validation: {error}"
    );
}

/// `Frame` fields are public, so `push` enforces the wire ceiling itself.
#[test]
fn push_refuses_a_frame_past_the_wire_ceiling() {
    let mut decoder = StreamDecoder::new();
    let frame = Frame {
        kind: FrameKind::Batch,
        sequence: 0,
        payload: vec![0u8; MAX_FRAME_PAYLOAD as usize + 1],
    };
    let error = decoder.push(&frame).expect_err("ceiling");
    assert_eq!(error.code(), "infinity/stream-frame-len", "{error}");
}

/// An oversized delta is "send another generation", a stream fault, not
/// `infinity/too-large` (an image-address-space answer).
#[test]
fn an_oversize_delta_is_a_stream_fault() {
    let base = base_module();
    let root = base.root().expect("root");
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    let mut fragment = InfinityModule::new();
    let big = fragment.push(Inode::Str("x".repeat(MAX_FRAME_PAYLOAD as usize + 64)));
    fragment.set_root(Some(big));
    let error = encoder
        .push_delta(
            &base,
            &[DeltaOp::PutNode {
                target: root,
                fragment: Box::new(fragment),
            }],
        )
        .expect_err("the frame ceiling");
    assert_eq!(error.code(), "infinity/stream-delta", "{error}");
}

/// Every completed generation re-encodes and re-validates the module; an endless
/// run of tiny generations must hit a work ceiling.
#[test]
fn an_endless_run_of_generations_hits_the_work_ceiling() {
    let base = base_module();
    let size = encode(&base).expect("encode").len() as u64;
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    let mut decoder = StreamDecoder::new().with_limits(Limits {
        max_total_bytes: size + 4096,
        ..Limits::default()
    });
    for frame in encoder.frames() {
        decoder.push(&frame).expect("first generation");
    }
    for tick in 1..=5_000u64 {
        // A no-op delta is refused now, so every generation changes the module.
        encoder
            .push_delta(
                &base,
                &[DeltaOp::SetProvenance(Some(active_infinity::Provenance {
                    timestamp_ms: tick,
                    ..active_infinity::Provenance::default()
                }))],
            )
            .expect("delta");
        let all = encoder.frames();
        let mut result = Ok(());
        for frame in &all[all.len() - 2..] {
            result = decoder.push(frame);
            if result.is_err() {
                break;
            }
        }
        if let Err(error) = result {
            assert_eq!(error.code(), "infinity/limit", "{error}");
            assert!(error.to_string().contains("generation work"), "{error}");
            return;
        }
    }
    panic!("no work ceiling was reached");
}
