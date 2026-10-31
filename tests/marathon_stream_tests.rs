//! Marathon section I-06: the stream and delta codec.

use active_infinity::stream::{apply_delta, decode_stream, DeltaOp, StreamEncoder};
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
