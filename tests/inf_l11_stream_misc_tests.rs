//! INF-L11 stream miscellany: DeltaOp tag 2, `Frame` fallibility,
//! `decode_stream_with_limits`, the `push_bytes` fault contract, and
//! `StreamedModule` summary `Debug`.
//!
//! The probe tests below were written first and run against the
//! unmodified `src/stream.rs` (fail-before); see the INF-L11 record.

use active_infinity::stream::{
    decode_stream, decode_stream_with_limits, encode_stream, DeltaOp, Frame, FrameKind,
    StreamDecoder, StreamEncoder, MAX_FRAME_PAYLOAD,
};
use active_infinity::{InfinityModule, Inode};

/// A base whose ids are already canonical, which is what a stream carries.
fn base_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("gateway".to_string()));
    let port = module.push(Inode::Int(8080));
    let root = module.push(Inode::Table {
        fields: vec![("name".to_string(), name), ("port".to_string(), port)],
    });
    module.set_root(Some(root));
    module.bind("gateway", root);
    active_infinity::decode(&active_infinity::encode(&module).expect("encode")).expect("decode")
}

/// The base generation pushed frame by frame, ready for a delta.
fn decoder_with_base(base: &InfinityModule) -> (StreamDecoder, Vec<Frame>) {
    let frames = encode_stream(base, 4096).expect("frames");
    let mut decoder = StreamDecoder::new();
    for frame in &frames {
        decoder.push(frame).expect("base generation");
    }
    (decoder, frames)
}

/// Tag 2 is retired, not unknown: the spec (§3) reserves it for the
/// retired `PushNode` op, so the decoder must refuse it with its own
/// message instead of the catch-all "unknown delta operation".
#[test]
fn tag_2_delta_op_is_refused_as_retired_not_unknown() {
    let base = base_module();
    let (mut decoder, frames) = decoder_with_base(&base);
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.push(2); // retired PushNode tag
    let delta = Frame::new(FrameKind::Delta, frames.len() as u64, payload);
    let error = decoder.push(&delta).expect_err("tag 2 is refused");
    assert_eq!(error.code(), "infinity/stream-delta", "{error}");
    assert!(
        format!("{error}").contains("retired"),
        "tag 2 must name its retired status, not the catch-all: {error}"
    );
}

/// `try_to_bytes` is the fallible form for a frame a caller built by
/// hand: the public fields let a caller assemble an oversized frame,
/// and serializing it must fail instead of panicking.
#[test]
fn try_to_bytes_refuses_a_hand_built_oversized_frame() {
    let frame = Frame {
        kind: FrameKind::Batch,
        sequence: 0,
        payload: vec![0u8; MAX_FRAME_PAYLOAD as usize + 1],
    };
    let error = frame.try_to_bytes().expect_err("oversized frame");
    assert_eq!(error.code(), "infinity/too-large", "{error}");
}

/// `to_bytes` still panics on a hand-built oversized frame, and the
/// panic names the fallible form.
#[test]
#[should_panic(expected = "try_to_bytes")]
fn to_bytes_panics_on_a_hand_built_oversized_frame() {
    let frame = Frame {
        kind: FrameKind::Batch,
        sequence: 0,
        payload: vec![0u8; MAX_FRAME_PAYLOAD as usize + 1],
    };
    let _ = frame.to_bytes();
}

/// `decode_stream_with_limits` decodes under the caller's limits: a
/// strict profile decodes a small stream, and a ceiling below the
/// declared image size refuses it.
#[test]
fn decode_stream_with_limits_uses_the_callers_limits() {
    let base = base_module();
    let mut bytes = Vec::new();
    for frame in &encode_stream(&base, 4096).expect("frames") {
        bytes.extend_from_slice(&frame.to_bytes());
    }
    let streamed = decode_stream_with_limits(&bytes, active_infinity::Limits::strict())
        .expect("strict limits decode a small stream");
    assert_eq!(
        streamed.image,
        active_infinity::encode(&base).expect("encode")
    );
    let tiny = active_infinity::Limits {
        max_total_bytes: 64,
        ..active_infinity::Limits::default()
    };
    let error =
        decode_stream_with_limits(&bytes, tiny).expect_err("the image exceeds the tiny ceiling");
    assert_eq!(error.code(), "infinity/limit", "{error}");
}

/// A limits value with a zero ceiling is an argument error at
/// construction, not a limit discovered on a hostile frame.
#[test]
fn decode_stream_with_limits_validates_the_limits() {
    let base = base_module();
    let mut bytes = Vec::new();
    for frame in &encode_stream(&base, 4096).expect("frames") {
        bytes.extend_from_slice(&frame.to_bytes());
    }
    let zero = active_infinity::Limits {
        max_total_bytes: 0,
        ..active_infinity::Limits::default()
    };
    let error = decode_stream_with_limits(&bytes, zero).expect_err("a zero ceiling is refused");
    assert_eq!(error.code(), "infinity/invalid-argument", "{error}");
}

/// `try_new` is the fallible form for a payload size a caller cannot
/// prove; it already refused oversized payloads before this fix.
#[test]
fn try_new_refuses_an_oversized_payload() {
    let error = Frame::try_new(
        FrameKind::Batch,
        0,
        vec![0u8; MAX_FRAME_PAYLOAD as usize + 1],
    )
    .expect_err("oversized payload");
    assert_eq!(error.code(), "infinity/too-large", "{error}");
}

/// `new` panics on an oversized payload, and the panic must name the
/// fallible form so a caller passing an untrusted length finds it.
#[test]
#[should_panic(expected = "try_new")]
fn new_panics_on_an_oversized_payload_and_names_try_new() {
    let _ = Frame::new(
        FrameKind::Batch,
        0,
        vec![0u8; MAX_FRAME_PAYLOAD as usize + 1],
    );
}

/// A parse fault must not poison the byte stream: a checksum fault on
/// one frame is per-frame recoverable, so the caller corrects that
/// frame and resends from it (spec §4, INF-L11(e), W7-NF-01).
#[test]
fn a_checksum_fault_does_not_poison_the_byte_stream() {
    let base = base_module();
    let frames = encode_stream(&base, 4096).expect("frames");
    // Corrupt the serialized bytes, not the payload: flipping the
    // payload and re-serializing would recompute a valid checksum.
    let mut bad = frames[1].to_bytes();
    let last = bad.len() - 1;
    bad[last] ^= 0xFF;
    let mut buffer = frames[0].to_bytes();
    buffer.extend_from_slice(&bad);
    let mut decoder = StreamDecoder::new();
    let error = decoder.push_bytes(&buffer).expect_err("bad checksum");
    assert_eq!(error.code(), "infinity/stream-checksum", "{error}");
    // The corrected frames, resent from the failed one, must decode.
    let mut good = Vec::new();
    for frame in &frames[1..] {
        good.extend_from_slice(&frame.to_bytes());
    }
    decoder
        .push_bytes(&good)
        .expect("retry after checksum fault");
    let streamed = decoder.finish().expect("finish after retry");
    assert_eq!(
        streamed.image,
        active_infinity::encode(&base).expect("encode"),
        "the retried stream reassembles byte-exactly"
    );
}

/// A bad-magic fault is a parse fault too: the faulting bytes are
/// dropped and a fresh call with the good stream decodes.
#[test]
fn a_bad_magic_does_not_poison_the_byte_stream() {
    let base = base_module();
    let frames = encode_stream(&base, 4096).expect("frames");
    let mut all = Vec::new();
    for frame in &frames {
        all.extend_from_slice(&frame.to_bytes());
    }
    let mut decoder = StreamDecoder::new();
    let error = decoder.push_bytes(b"XXXXXXXX").expect_err("wrong magic");
    assert_eq!(error.code(), "infinity/stream-magic", "{error}");
    decoder.push_bytes(&all).expect("retry after bad magic");
    let streamed = decoder.finish().expect("finish after retry");
    assert_eq!(
        streamed.image,
        active_infinity::encode(&base).expect("encode"),
        "the retried stream reassembles byte-exactly"
    );
}

/// The tail parsed against a failed frame is dropped with it, so the
/// caller resends from the failed frame — including a good frame that
/// arrived in the same call as the fault.
#[test]
fn a_parse_fault_drops_the_tail_with_it() {
    let base = base_module();
    let frames = encode_stream(&base, 4096).expect("frames");
    let mut bad = frames[1].to_bytes();
    let last = bad.len() - 1;
    bad[last] ^= 0xFF;
    let mut buffer = frames[0].to_bytes();
    buffer.extend_from_slice(&bad);
    buffer.extend_from_slice(&frames[2].to_bytes());
    let mut decoder = StreamDecoder::new();
    let error = decoder
        .push_bytes(&buffer)
        .expect_err("bad checksum ends the call");
    assert_eq!(error.code(), "infinity/stream-checksum", "{error}");
    // The good seq-2 frame rode in with the fault and was dropped; the
    // resend starts at the failed frame, not after it.
    let mut good = Vec::new();
    for frame in &frames[1..] {
        good.extend_from_slice(&frame.to_bytes());
    }
    decoder.push_bytes(&good).expect("retry after fault");
    decoder.finish().expect("finish after retry");
}

/// The semantic half, already true before this fix and locked here:
/// a refused batch rolls the decoder back, and the corrected frames
/// are accepted through a fresh `push_bytes` call (corrected f6).
#[test]
fn a_semantic_fault_is_retryable_through_push_bytes() {
    let base = base_module();
    let frames = encode_stream(&base, 4096).expect("frames");
    let mut head = Vec::new();
    for frame in &frames[..2] {
        head.extend_from_slice(&frame.to_bytes());
    }
    let mut decoder = StreamDecoder::new();
    decoder.push_bytes(&head).expect("begin and first batch");
    let mut bad = frames[2].clone();
    bad.payload[0] = 99; // no such section
    let error = decoder
        .push_bytes(&bad.to_bytes())
        .expect_err("the bad batch is refused");
    assert_eq!(error.code(), "infinity/stream-state", "{error}");
    let mut good = Vec::new();
    for frame in &frames[2..] {
        good.extend_from_slice(&frame.to_bytes());
    }
    decoder
        .push_bytes(&good)
        .expect("retry after semantic fault");
    let streamed = decoder.finish().expect("finish after retry");
    assert_eq!(
        streamed.image,
        active_infinity::encode(&base).expect("encode"),
        "the retried stream reassembles byte-exactly"
    );
}

/// `StreamedModule` Debug is a summary: it must never print module
/// contents (the old form formatted the whole module, clone+redact).
#[test]
fn streamed_module_debug_is_a_summary() {
    let mut module = InfinityModule::new();
    let marker = module.push(Inode::Str("inf-l11-debug-marker-7f3a9".to_string()));
    let root = module.push(Inode::Table {
        fields: vec![("marker".to_string(), marker)],
    });
    module.set_root(Some(root));
    let mut bytes = Vec::new();
    for frame in &encode_stream(&module, 4096).expect("frames") {
        bytes.extend_from_slice(&frame.to_bytes());
    }
    let streamed = decode_stream(&bytes).expect("decode");
    let text = format!("{streamed:?}");
    assert!(
        !text.contains("inf-l11-debug-marker-7f3a9"),
        "Debug must not print module contents: {text}"
    );
    assert!(text.contains("node_count"), "{text}");
    assert!(text.contains("image_len"), "{text}");
    assert!(
        text.len() < 512,
        "a summary fits in a log line, not a dump: {text}"
    );
}

/// The one-frame path is retryable too: a sequence mismatch rolls the
/// decoder back instead of ending the stream (INF-L11(e)).
#[test]
fn a_sequence_mismatch_is_retryable_through_push() {
    let base = base_module();
    let frames = encode_stream(&base, 4096).expect("frames");
    let mut decoder = StreamDecoder::new();
    decoder.push(&frames[0]).expect("begin");
    let mut skipped = frames[2].clone();
    skipped.sequence = 2;
    let error = decoder.push(&skipped).expect_err("sequence gap");
    assert_eq!(error.code(), "infinity/stream-sequence", "{error}");
    decoder.push(&frames[1]).expect("the skipped frame retries");
    decoder.push(&frames[2]).expect("the following frame");
    for frame in &frames[3..] {
        decoder.push(frame).expect("rest of the stream");
    }
    decoder.finish().expect("finish after retry");
}

/// The delta encoder never emits the retired tag: every op encodes
/// to an assigned tag, so no well-formed stream can carry tag 2.
#[test]
fn the_encoder_never_emits_tag_2() {
    let base = base_module();
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder
        .push_delta(
            &base,
            &[DeltaOp::RemoveBinding {
                name: "gateway".to_string(),
            }],
        )
        .expect("delta");
    let mut saw_delta = false;
    for frame in encoder.frames() {
        if frame.kind == FrameKind::Delta {
            saw_delta = true;
            // op_count u32, then the first op tag.
            assert_eq!(frame.payload[4], 4, "RemoveBinding encodes as tag 4");
        }
    }
    assert!(saw_delta, "the encoder emitted a delta frame");
}
