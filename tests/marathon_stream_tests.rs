//! Marathon section I-06: the stream and delta codec.

use active_infinity::stream::{
    apply_delta, decode_stream, encode_stream, DeltaOp, Frame, FrameKind, StreamDecoder,
    StreamEncoder, MAX_FRAME_PAYLOAD,
};
use active_infinity::{encode, AnnotationKind, InfinityModule, Inode, NodeId};

/// A base whose ids are already canonical, which is what a stream carries: the
/// delta ops refer to the reassembled arena, so they must be computed against it.
fn base_module() -> InfinityModule {
    let module = raw_base_module();
    active_infinity::decode(&encode(&module).expect("encode")).expect("decode")
}

fn raw_base_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("gateway".to_string()));
    let port = module.push(Inode::Int(8080));
    let root = module.push(Inode::Table {
        fields: vec![("name".to_string(), name), ("port".to_string(), port)],
    });
    module.set_root(Some(root));
    module.bind("gateway", root);
    module
}

#[test]
fn a_failed_frame_does_not_consume_its_sequence_number() {
    // `push` incremented the expected sequence before processing, so one bad frame
    // wedged the decoder: the retry reported `stream-sequence` instead of the
    // real fault.
    let base = base_module();
    let frames = active_infinity::stream::encode_stream(&base, 4096).expect("frames");
    let mut decoder = active_infinity::stream::StreamDecoder::new();
    decoder.push(&frames[0]).expect("begin");
    let mut broken = frames[1].clone();
    assert_eq!(broken.kind, active_infinity::stream::FrameKind::Batch);
    broken.payload[0] = 99; // no such section
    let error = decoder.push(&broken).expect_err("the bad frame is refused");
    assert_eq!(error.code(), "infinity/stream-state", "{error:?}");
    // The retry with the real frame must be accepted, not reported as a sequence
    // error.
    decoder
        .push(&frames[1])
        .expect("the retried frame is accepted");
}

#[test]
fn a_generation_must_start_at_section_zero() {
    // Starting at section 1 left a hole that only failed at `End`, with a worse
    // code and after the bytes were buffered.
    let base = base_module();
    let frames = active_infinity::stream::encode_stream(&base, 4096).expect("frames");
    let mut decoder = active_infinity::stream::StreamDecoder::new();
    decoder.push(&frames[0]).expect("begin");
    let mut out_of_order = frames[1].clone();
    out_of_order.payload[0] = 1;
    let error = decoder
        .push(&out_of_order)
        .expect_err("a batch that skips section 0 is refused");
    assert_eq!(error.code(), "infinity/stream-state", "{error:?}");
}

#[test]
fn a_fragment_without_a_root_is_refused() {
    let base = base_module();
    let mut fragment = InfinityModule::new();
    let _leaf = fragment.push(Inode::Int(7));
    let ops = vec![DeltaOp::PutNode {
        target: NodeId(0),
        fragment: Box::new(fragment),
    }];
    let error = apply_delta(&base, &ops).expect_err("a rootless fragment cannot be placed");
    assert_eq!(error.code(), "infinity/stream-delta", "{error:?}");
}

#[test]
fn a_delta_provenance_block_is_bounded_by_its_entry_ceiling() {
    let base = base_module();
    let entries: Vec<active_infinity::ProvEntry> = (0..16)
        .map(|index| active_infinity::ProvEntry {
            key: format!("k{index}"),
            value: active_infinity::ProvValue::Int(index as i64),
        })
        .collect();
    let ops = vec![DeltaOp::SetProvenance(Some(active_infinity::Provenance {
        producer: Some("marathon".to_string()),
        entries,
        ..active_infinity::Provenance::default()
    }))];
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder.push_delta(&base, &ops).expect("delta");
    let bytes = encoder.to_bytes();
    let limits = active_infinity::Limits {
        max_prov_entries: 4,
        ..Default::default()
    };
    let mut decoder = active_infinity::stream::StreamDecoder::new().with_limits(limits);
    let error = decoder
        .push_bytes(&bytes)
        .expect_err("the entry ceiling fires before the loop");
    assert_eq!(error.code(), "infinity/limit", "{error:?}");
    assert!(
        format!("{error}").contains("delta provenance"),
        "the delta decoder is what refused it, got {error}"
    );
}

#[test]
fn binding_deltas_round_trip() {
    // The encoder wrote the binding name length as u32 while the decoder (and the
    // spec, §4) read u16, so every binding delta was misparsed on the wire.
    let base = base_module();
    let ops = vec![
        DeltaOp::SetBinding {
            name: "primary".to_string(),
            node: NodeId(0),
        },
        DeltaOp::SetAnnotation {
            node: NodeId(0),
            kind: AnnotationKind::Intent("note".to_string()),
        },
        DeltaOp::RemoveBinding {
            name: "gateway".to_string(),
        },
    ];
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder.push_delta(&base, &ops).expect("delta frame");
    let bytes = encoder.to_bytes();
    let streamed = decode_stream(&bytes).unwrap_or_else(|error| panic!("decode: {error:?}"));
    let expected = apply_delta(&base, &ops).expect("apply");
    assert_eq!(streamed.image, encode(&expected).expect("encode"));
    assert_eq!(
        streamed.content_hash,
        active_infinity::content_hash(&encode(&expected).expect("encode")).expect("hash")
    );
}

#[test]
fn an_incremental_generation_resets_its_delta_budget() {
    // `pending_delta_bytes` accumulated across generations, so an honest
    // multi-generation stream eventually failed with `infinity/limit`.
    let base = base_module();
    // One long binding reset to alternating nodes: the image keeps its size, so
    // each generation is a legal incremental stream.
    let name = "b".repeat(120);
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    for step in 0..40u32 {
        let ops = vec![DeltaOp::SetBinding {
            name: name.clone(),
            node: NodeId(step % 2),
        }];
        encoder.push_delta(&base, &ops).expect("delta");
    }
    let bytes = encoder.to_bytes();
    // Each generation is a few hundred bytes; the total is well over this budget,
    // so the counter has to be per generation rather than cumulative.
    let limits = active_infinity::Limits {
        max_total_bytes: 4 << 10,
        ..Default::default()
    };
    let mut decoder = active_infinity::stream::StreamDecoder::new().with_limits(limits);
    decoder.push_bytes(&bytes).expect("the stream decodes");
    decoder.finish().expect("the stream finishes");
}

#[test]
fn a_split_frame_is_truncated_not_over_limit() {
    let frame = Frame::new(FrameKind::Batch, 0, vec![0u8; 100]);
    let bytes = frame.to_bytes();
    // Complete header, partial payload: a reader must wait for the rest rather
    // than treat an honest split as a fatal frame-length fault.
    let error = Frame::parse(&bytes[..40]).expect_err("a partial payload is truncated");
    assert_eq!(error.code(), "infinity/truncated", "{error}");
}

#[test]
fn a_failed_incremental_end_keeps_its_pending_deltas() {
    let base = base_module();
    let root = base.root().expect("root");
    let ops = vec![DeltaOp::SetAnnotation {
        node: root,
        kind: AnnotationKind::Intent("kept".into()),
    }];
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder.push_delta(&base, &ops).expect("delta");
    let frames = encoder.frames();
    let end = frames.last().expect("end frame").clone();

    let mut decoder = StreamDecoder::new();
    for frame in &frames[..frames.len() - 1] {
        decoder.push_bytes(&frame.to_bytes()).expect("frame");
    }
    // A wrong declared size must not consume the pending delta.
    let mut payload = end.payload.clone();
    payload[32] ^= 0xFF;
    let bad = Frame::new(FrameKind::End, end.sequence, payload);
    let error = decoder.push_bytes(&bad.to_bytes()).expect_err("bad end");
    assert!(error.code().starts_with("infinity/"), "{error}");

    // The corrected end now succeeds and the annotation is present.
    decoder
        .push_bytes(&end.to_bytes())
        .expect("a corrected end applies the pending delta");
    let streamed = decoder.finish().expect("finish");
    assert!(
        streamed.module.annotations().iter().any(
            |annotation| matches!(&annotation.kind, AnnotationKind::Intent(text) if text == "kept")
        ),
        "the pending annotation was lost"
    );
}

#[test]
fn a_dangling_annotation_expression_is_a_stream_delta() {
    let base = base_module();
    let root = base.root().expect("root");
    let error = apply_delta(
        &base,
        &[DeltaOp::SetAnnotation {
            node: root,
            kind: AnnotationKind::Constraint {
                source: "x".into(),
                expr: NodeId(9_999),
            },
        }],
    )
    .expect_err("a dangling constraint expression is refused");
    assert_eq!(error.code(), "infinity/stream-delta", "{error}");
}

#[test]
fn a_chunk_that_cannot_fit_a_frame_is_refused() {
    let base = base_module();
    let error = encode_stream(&base, MAX_FRAME_PAYLOAD as usize)
        .expect_err("a batch payload would exceed the frame ceiling");
    assert_eq!(error.code(), "infinity/invalid-argument", "{error}");
}

#[test]
fn a_delta_immutable_flag_of_two_is_refused() {
    let base = base_module();
    let frames = encode_stream(&base, 4096).expect("stream");
    let last = frames.last().expect("frames").sequence;
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.push(5); // SetAnnotation
    payload.extend_from_slice(&0u32.to_le_bytes()); // node 0
    payload.push(2); // AiImmutable
    payload.push(2); // out of range
    let delta = Frame::new(FrameKind::Delta, last + 1, payload);
    let mut bytes = Vec::new();
    for frame in &frames {
        bytes.extend_from_slice(&frame.to_bytes());
    }
    bytes.extend_from_slice(&delta.to_bytes());
    let error = decode_stream(&bytes).expect_err("flag 2 is not canonical");
    assert_eq!(error.code(), "infinity/stream-delta", "{error}");
}

#[test]
fn a_newer_minor_generation_is_a_minor_version_error() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&active_infinity::FORMAT_MAJOR.to_le_bytes());
    payload.extend_from_slice(&(active_infinity::FORMAT_MINOR + 1).to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&active_infinity::dialect_hash().to_le_bytes());
    payload.extend_from_slice(&224u64.to_le_bytes());
    let begin = Frame::new(FrameKind::Begin, 0, payload);
    let mut decoder = StreamDecoder::new();
    let error = decoder
        .push_bytes(&begin.to_bytes())
        .expect_err("a newer minor is refused");
    assert_eq!(error.code(), "infinity/version-minor", "{error}");
}
