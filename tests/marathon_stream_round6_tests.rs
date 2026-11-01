//! I-13 round 6: the work ceiling must be charged from the accumulated bytes and
//! the decoded delta state, not from peer-declared numbers.

use active_infinity::stream::{
    encode_stream, DeltaOp, Frame, FrameKind, StreamDecoder, StreamEncoder,
};
use active_infinity::{encode, InfinityModule, Inode};

fn wide_base(fields: usize) -> InfinityModule {
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Int(1));
    let mut entries = Vec::with_capacity(fields);
    for field in 0..fields {
        entries.push((format!("field{field:05}"), value));
    }
    let root = module.push(Inode::Table { fields: entries });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode");
    active_infinity::decode(&image).expect("decode")
}

/// `End.size` is peer-controlled. A lie must not buy an assembly: the charge is
/// the accumulated length, and a disagreement is a hash fault.
#[test]
fn a_first_generation_end_size_lie_cannot_buy_free_assembly() {
    let base = wide_base(5_000);
    let size = encode(&base).expect("encode").len() as u64;
    let frames = encode_stream(&base, 4096).expect("frames");
    let limits = active_infinity::Limits {
        max_total_bytes: size + 4096,
        ..active_infinity::Limits::default()
    };
    let mut decoder = StreamDecoder::new().with_limits(limits);
    for frame in &frames[..frames.len() - 1] {
        decoder.push(frame).expect("begin and batches");
    }
    let mut end = frames.last().expect("end").clone();
    end.payload[32..40].copy_from_slice(&224u64.to_le_bytes()); // lie
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
    // The charge is ~the accumulated size, so only ~64 replays fit.
    assert!(
        accepted <= 128,
        "a size lie bought {accepted} assemblies; the charge used the peer's number"
    );
}

/// One delta frame cannot buy 54x its wire bytes in decoded state.
#[test]
fn a_delta_frame_cannot_buy_more_than_its_wire_bytes() {
    let base = wide_base(10);
    let size = encode(&base).expect("encode").len() as u64;
    let frames = encode_stream(&base, 4096).expect("frames");
    let mut decoder = StreamDecoder::new().with_limits(active_infinity::Limits {
        max_total_bytes: size + 4096,
        ..active_infinity::Limits::default()
    });
    for frame in &frames {
        decoder.push(frame).expect("base generation");
    }

    // 64 KiB of five-byte `SetRoot` ops: ~13k ops, 1.9 MB decoded.
    let ops = (64 * 1024) / 5;
    let mut payload = Vec::with_capacity(4 + ops * 5);
    payload.extend_from_slice(&u32::try_from(ops).expect("count").to_le_bytes());
    for _ in 0..ops {
        payload.push(0); // SetRoot
        payload.push(0); // Some
        payload.extend_from_slice(&0u32.to_le_bytes());
    }
    let frame = Frame {
        kind: FrameKind::Delta,
        sequence: decoder.frames(),
        payload,
    };
    let error = decoder.push(&frame).expect_err("decoded state is bounded");
    assert_eq!(error.code(), "infinity/limit", "{error}");
    assert!(error.to_string().contains("delta decoded bytes"), "{error}");
}

/// A refused delta frame is charged, so replaying it cannot buy free decoding.
#[test]
fn a_replayed_delta_frame_is_charged() {
    let base = wide_base(10);
    let size = encode(&base).expect("encode").len() as u64;
    let frames = encode_stream(&base, 4096).expect("frames");
    let mut decoder = StreamDecoder::new().with_limits(active_infinity::Limits {
        max_total_bytes: size + 4096,
        ..active_infinity::Limits::default()
    });
    for frame in &frames {
        decoder.push(frame).expect("base generation");
    }
    // A structurally invalid frame: one op, then trailing bytes.
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.push(0); // SetRoot
    payload.push(0); // Some
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&[0u8; 512]); // trailing
    let frame = Frame {
        kind: FrameKind::Delta,
        sequence: decoder.frames(),
        payload,
    };
    let mut refused = 0usize;
    loop {
        match decoder.push(&frame) {
            Ok(()) => panic!("trailing bytes must be refused"),
            Err(error) if error.code() == "infinity/limit" => break,
            Err(error) => {
                assert_eq!(error.code(), "infinity/stream-delta", "{error}");
                refused += 1;
            }
        }
        assert!(refused < 100_000, "no latch after {refused} replays");
    }
    assert!(refused > 0);
}

/// A semantic fault ends the byte stream: the buffered tail cannot be delivered,
/// so `push_bytes` drops it. A single frame stays retryable through `push`.
#[test]
fn a_refused_frame_ends_the_buffered_stream() {
    let base = wide_base(10);
    let frames = encode_stream(&base, 4096).expect("frames");
    // [Begin][batch0][bad batch (seq 2)][batch1 (seq 3)]
    let mut buffer = Vec::new();
    for frame in &frames[..2] {
        buffer.extend_from_slice(&frame.to_bytes());
    }
    let mut bad = frames[2].clone();
    bad.sequence = 2;
    bad.payload[0] = 99; // unknown section
    buffer.extend_from_slice(&bad.to_bytes());
    let mut tail = frames[3].clone();
    tail.sequence = 3;
    buffer.extend_from_slice(&tail.to_bytes());

    let mut decoder = StreamDecoder::new();
    let error = decoder
        .push_bytes(&buffer)
        .expect_err("the bad batch is refused");
    assert_eq!(error.code(), "infinity/stream-state", "{error}");
    // The tail is gone: flushing the buffer delivers nothing, then the corrected
    // seq-2 frame and its successor are accepted.
    decoder.push_bytes(&[]).expect("nothing buffered");
    let mut corrected = frames[2].clone();
    corrected.sequence = 2;
    decoder.push(&corrected).expect("corrected frame");
    let mut next = frames[3].clone();
    next.sequence = 3;
    decoder.push(&next).expect("following frame");
}

/// Generation 1's size disagreement is the same hash fault as the incremental
/// path, not a second classification.
#[test]
fn a_first_generation_size_mismatch_is_a_hash_fault() {
    let base = wide_base(10);
    let frames = encode_stream(&base, 4096).expect("frames");
    let mut decoder = StreamDecoder::new();
    for frame in &frames[..frames.len() - 1] {
        decoder.push(frame).expect("begin and batches");
    }
    let mut end = frames.last().expect("end").clone();
    let size = u64::from_le_bytes(end.payload[32..40].try_into().expect("size"));
    end.payload[32..40].copy_from_slice(&(size + 1).to_le_bytes());
    let error = decoder.push(&end).expect_err("size mismatch");
    assert_eq!(error.code(), "infinity/stream-hash", "{error}");
}

/// The encoder refuses to emit a delta its own decoder would reject as a no-op.
#[test]
fn the_encoder_refuses_a_no_op_delta() {
    let base = wide_base(10);
    let root = base.root().expect("root");
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    let error = encoder
        .push_delta(&base, &[DeltaOp::SetRoot(Some(root))])
        .expect_err("a no-op delta is a producer bug");
    assert_eq!(error.code(), "infinity/stream-delta", "{error}");
}
