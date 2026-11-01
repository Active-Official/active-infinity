//! I-13 round 7: pending-fragment work, decoded fragment memory and the frame
//! buffer ceiling.

use active_infinity::stream::{DeltaOp, Frame, FrameKind, StreamDecoder, StreamEncoder};
use active_infinity::{encode, InfinityModule, Inode};

fn base_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(0));
    module.set_root(Some(root));
    let image = encode(&module).expect("encode");
    active_infinity::decode(&image).expect("decode")
}

/// A `PutNode` whose expensive nodes are bound but not reachable: the merge still
/// copies them, and a wrong-hash `End` retry must be charged for that work.
#[test]
fn a_wrong_hash_end_with_a_pending_putnode_cannot_be_replayed_free() {
    let base = base_module();
    let root = base.root().expect("root");
    let mut fragment = InfinityModule::new();
    let small = fragment.push(Inode::Int(0));
    fragment.set_root(Some(small));
    let value = fragment.push(Inode::Int(1));
    let mut fields = Vec::with_capacity(20_000);
    for field in 0..20_000 {
        fields.push((format!("field{field:05}"), value));
    }
    let table = fragment.push(Inode::Table { fields });
    // Reachable only through a binding, which `PutNode` does not graft.
    fragment.bind("big", table);

    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder
        .push_delta(
            &base,
            &[
                DeltaOp::SetBinding {
                    name: "anchor".into(),
                    node: root,
                },
                DeltaOp::PutNode {
                    target: root,
                    fragment: Box::new(fragment),
                },
            ],
        )
        .expect("delta");
    let frames = encoder.frames();
    let ceiling = 3 * 1024 * 1024u64;
    let mut decoder = StreamDecoder::new().with_limits(active_infinity::Limits {
        max_total_bytes: ceiling,
        ..active_infinity::Limits::default()
    });
    for frame in &frames[..frames.len() - 1] {
        decoder.push(frame).expect("frames before end");
    }
    let mut end = frames.last().expect("end").clone();
    end.payload[0] ^= 0xFF; // wrong hash

    let mut accepted = 0usize;
    loop {
        match decoder.push(&end) {
            Ok(()) => panic!("a wrong hash must never be accepted"),
            Err(error) if error.code() == "infinity/limit" => break,
            Err(error) => {
                assert_eq!(error.code(), "infinity/stream-hash", "{error}");
                accepted += 1;
            }
        }
        assert!(accepted < 10_000, "no latch after {accepted} replays");
    }
    // The charge is the pending fragment bytes, so the bound is ~64x the
    // ceiling divided by them. Charging only the base image would allow ~25x
    // more retries.
    let pending = frames[frames.len() - 2].payload.len() as u64 + 32;
    let predicted = (ceiling.saturating_mul(64) / pending) + 8;
    assert!(
        accepted as u64 <= predicted,
        "a decoy fragment bought {accepted} merges; predicted at most {predicted}"
    );
}

/// A `PutNode` fragment's decoded nodes are memory the wire must pay for.
#[test]
fn a_putnode_fragment_is_bounded_by_decoded_bytes() {
    let base = base_module();
    let root = base.root().expect("root");
    let mut fragment = InfinityModule::new();
    let placeholder = fragment.push(Inode::Int(0));
    fragment.set_root(Some(placeholder));
    let value = fragment.push(Inode::Int(1));
    let mut fields = Vec::with_capacity(1_000_000);
    for field in 0..1_000_000 {
        fields.push((format!("f{field:07}"), value));
    }
    let table = fragment.push(Inode::Table { fields });
    // Reachable in the fragment's own image (bindings are roots), but not under
    // the grafted root.
    fragment.bind("big", table);
    let size = encode(&base).expect("encode").len() as u64;
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder
        .push_delta(
            &base,
            &[
                DeltaOp::SetBinding {
                    name: "anchor".into(),
                    node: root,
                },
                DeltaOp::PutNode {
                    target: root,
                    fragment: Box::new(fragment),
                },
            ],
        )
        .expect("delta");
    let frames = encoder.frames();
    let mut decoder = StreamDecoder::new().with_limits(active_infinity::Limits {
        max_total_bytes: size + 32 * 1024 * 1024,
        ..active_infinity::Limits::default()
    });
    let mut error = None;
    for frame in &frames[..frames.len() - 1] {
        if let Err(found) = decoder.push(frame) {
            error = Some(found);
            break;
        }
    }
    let error = error.expect("a field-heavy fragment exceeds the decoded ceiling");
    assert_eq!(error.code(), "infinity/limit", "{error}");
    assert!(error.to_string().contains("decoded bytes"), "{error}");
}

/// A decoder never buffers more than its declared ceiling, whatever a frame
/// header claims.
#[test]
fn a_strict_decoder_bounds_the_frame_buffer() {
    let mut decoder = StreamDecoder::new().with_limits(active_infinity::Limits {
        max_total_bytes: 1024,
        ..active_infinity::Limits::default()
    });
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AINS");
    bytes.push(1); // version
    bytes.push(2); // Batch
    bytes.extend_from_slice(&0u16.to_le_bytes()); // flags
    bytes.extend_from_slice(&0u64.to_le_bytes()); // sequence
    bytes.extend_from_slice(&16_777_216u32.to_le_bytes()); // declared length
    bytes.extend_from_slice(&0u32.to_le_bytes()); // reserved
    bytes.extend_from_slice(&[0u8; 8]); // checksum
    bytes.extend_from_slice(&vec![0u8; 1 << 21]);
    let error = decoder
        .push_bytes(&bytes)
        .expect_err("the ceiling bounds the buffer");
    assert_eq!(error.code(), "infinity/limit", "{error}");
    assert!(error.to_string().contains("frame bytes"), "{error}");
}

/// A `Frame` built by a caller is also refused when its payload exceeds the
/// wire ceiling (unchanged from round 4).
#[test]
fn a_caller_built_frame_past_the_ceiling_is_refused() {
    let mut decoder = StreamDecoder::new();
    let frame = Frame {
        kind: FrameKind::Batch,
        sequence: 0,
        payload: vec![0u8; 64 * 1024 * 1024 + 1],
    };
    let error = decoder.push(&frame).expect_err("ceiling");
    assert_eq!(error.code(), "infinity/stream-frame-len", "{error}");
}
