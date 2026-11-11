//! Marathon I-13: error codes are stable, documented and classified.
//!
//! The unit tests in `src/error.rs` pin uniqueness and the spec gate; these
//! tests drive the shipped paths that used to report a misleading code.

use active_infinity::layout::Header;
use active_infinity::stream::{
    apply_delta, decode_stream, encode_stream, DeltaOp, Frame, FrameKind, StreamEncoder,
};
use active_infinity::{encode, AnnotationKind, InfinityModule, Inode};

fn module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Str("code".into()));
    let root = module.push(Inode::Table {
        fields: vec![("value".into(), value)],
    });
    module.set_root(Some(root));
    module
}

/// A delta annotation whose text does not fit the u16 length space is a delta
/// fault (`infinity/stream-delta`), not an image address-space fault — and
/// it stays one when the stream cannot widen: the width is stream-wide, so
/// a stream that already carries narrow `Delta` frames refuses a late wide
/// delta instead of emitting a stream its own decoder would misread
/// (INF-L12). A first wide delta upgrades the stream instead; see
/// `inf_l12_delta_strings_tests::a_70kib_annotation_delta_round_trips`.
#[test]
fn an_oversized_delta_annotation_is_a_stream_delta() {
    let base = module();
    let root = base.root().expect("root");
    let narrow = vec![DeltaOp::SetAnnotation {
        node: root,
        kind: AnnotationKind::Intent("note".into()),
    }];
    let updated = apply_delta(&base, &narrow).expect("apply");
    let ops = vec![DeltaOp::SetAnnotation {
        node: root,
        kind: AnnotationKind::Intent("x".repeat(70_000)),
    }];
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder.push_delta(&base, &narrow).expect("narrow delta");
    let error = encoder
        .push_delta(&updated, &ops)
        .expect_err("the delta string cannot be encoded");
    assert_eq!(error.code(), "infinity/stream-delta", "{error}");
}

/// Invalid UTF-8 in a delta binding name is a delta fault, not a string-heap
/// fault: a caller must not route it to the image validator.
#[test]
fn invalid_utf8_in_a_delta_string_is_a_stream_delta() {
    let base = module();
    let frames = encode_stream(&base, 4096).expect("stream");
    let last = frames.last().expect("frames").sequence;
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.push(3); // SetBinding
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.push(0xFF);
    payload.extend_from_slice(&0u32.to_le_bytes());
    let delta = Frame::new(FrameKind::Delta, last + 1, payload);

    let mut bytes = Vec::new();
    for frame in &frames {
        bytes.extend_from_slice(&frame.to_bytes());
    }
    bytes.extend_from_slice(&delta.to_bytes());
    let error = decode_stream(&bytes).expect_err("the delta is refused");
    assert_eq!(error.code(), "infinity/stream-delta", "{error}");
}

#[test]
fn a_short_header_buffer_is_an_invalid_argument() {
    let image = encode(&module()).expect("encode");
    let header = Header::parse(&image).expect("header");
    let mut out = [0u8; 8];
    let error = header.try_write(&mut out).expect_err("short buffer");
    assert_eq!(error.code(), "infinity/invalid-argument", "{error}");
}

/// A code is never a message: the evaluator's class is available without
/// parsing `Display`.
#[test]
fn an_evaluation_sub_code_is_available_without_the_message() {
    let error = active_infinity::Error::Evaluation {
        code: "T001",
        line: 2,
        column: 14,
        message: "type error".to_string(),
    };
    assert_eq!(error.code(), "infinity/evaluation");
    assert_eq!(error.sub_code(), Some("T001"));
    assert!(!error.is_fatal(), "the module itself is valid");
}

#[test]
fn the_fatal_flag_does_not_mark_a_limit_a_corrupt_buffer() {
    let limit = active_infinity::Error::Limit {
        kind: "nodes",
        limit: 10,
    };
    assert!(!limit.is_fatal(), "raising the ceiling may succeed");
    assert!(active_infinity::Error::Magic.is_fatal());
}
