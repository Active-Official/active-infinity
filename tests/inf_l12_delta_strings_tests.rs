//! INF-L12: delta strings are capped at 64 KiB (`u16`), undocumented.
//!
//! The image format allows 64 MiB strings (`Limits::max_string_bytes`),
//! so a module with a 70 KiB binding name encodes whole without issue —
//! but `write_string` / `write_delta_string` refused any delta string
//! over `u16::MAX` with `infinity/stream-delta`, so a stream could not
//! express a legitimate update to a large-text field. The fix gates a
//! `u32` length prefix on a `Begin` stream-flags bit (spec §2/§3): a
//! stream whose first wide delta needs it upgrades its `Begin` frame,
//! and the decoder reads `u32` lengths for every delta string in a
//! flagged stream. Narrow streams are byte-identical to v1.
//!
//! Stage 1 (fail-before at HEAD `7889dd9`): the six round-trip tests
//! fail with `delta string exceeds the u16 length space`; the five
//! control tests already pass. Stage 2 adds the wide-against-narrow
//! refusal and the builder tests, which need the new API, and pins the
//! two refusal messages.

use active_infinity::stream::{
    apply_delta, decode_stream, DeltaOp, FrameKind, StreamDecoder, StreamEncoder,
};
use active_infinity::{
    encode, AnnotationKind, InfinityModule, Inode, NodeId, ProvEntry, ProvValue, Provenance,
};

fn base_module() -> (InfinityModule, NodeId) {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("gateway".into()));
    let port = module.push(Inode::Int(8080));
    let root = module.push(Inode::Table {
        fields: vec![("name".into(), name), ("port".into(), port)],
    });
    module.set_root(Some(root));
    // A stream carries the canonical arena: delta ops refer to the
    // reassembled ids, so the base must be the encode/decode round-trip
    // (marathon_stream_tests.rs `base_module`). The port node is located
    // by content, not by its raw-arena id.
    let module = active_infinity::decode(&encode(&module).expect("encode")).expect("decode");
    let port = module
        .nodes()
        .iter()
        .position(|node| matches!(node, Inode::Int(8080)))
        .map(|index| NodeId(index as u32))
        .expect("the port node survives canonicalization");
    (module, port)
}

/// Encode `ops` against `base` as a one-generation stream and decode it.
fn round_trip(base: &InfinityModule, ops: &[DeltaOp]) -> active_infinity::stream::StreamedModule {
    let mut encoder = StreamEncoder::new(base, 4096).expect("encoder");
    encoder.push_delta(base, ops).expect("delta");
    let bytes = encoder.to_bytes();
    decode_stream(&bytes).expect("decode")
}

#[test]
fn a_70kib_binding_name_delta_round_trips() {
    // Audit probe P-G: a 70 KiB binding-name delta was refused with
    // `infinity/stream-delta`. The same module encodes whole without
    // issue, so the refusal is the finding, not the module.
    let (base, port) = base_module();
    let wide = "b".repeat(70 * 1024);
    let mut whole = base.clone();
    whole.bind(wide.clone(), port);
    encode(&whole).expect("a 70 KiB binding name encodes whole");
    let ops = vec![DeltaOp::SetBinding {
        name: wide.clone(),
        node: port,
    }];
    let expected = apply_delta(&base, &ops).expect("in-memory delta");
    let streamed = round_trip(&base, &ops);
    assert_eq!(streamed.module, expected);
    assert!(
        streamed
            .module
            .bindings()
            .iter()
            .any(|(name, node)| name == &wide && *node == port),
        "the wide binding must land in the decoded module"
    );
}

#[test]
fn a_70kib_annotation_delta_round_trips() {
    // Audit probe P-G, second half: a 70 KiB annotation delta.
    let (base, port) = base_module();
    let text = "a".repeat(70 * 1024);
    let ops = vec![DeltaOp::SetAnnotation {
        node: port,
        kind: AnnotationKind::Intent(text.clone()),
    }];
    let expected = apply_delta(&base, &ops).expect("in-memory delta");
    let streamed = round_trip(&base, &ops);
    assert_eq!(streamed.module, expected);
    assert!(
        streamed.module.annotations().iter().any(|annotation| {
            annotation.node == port
                && matches!(&annotation.kind, AnnotationKind::Intent(found) if found == &text)
        }),
        "the wide annotation must land in the decoded module"
    );
}

#[test]
fn a_70kib_provenance_text_delta_round_trips() {
    // The provenance path writes strings through `write_string` too
    // (producer, model, tool, entry keys and `Text` values).
    let (base, _port) = base_module();
    let wide = "p".repeat(70 * 1024);
    let ops = vec![DeltaOp::SetProvenance(Some(Provenance {
        producer: Some(wide.clone()),
        timestamp_ms: 0,
        model: None,
        tool: None,
        parent: None,
        entries: vec![ProvEntry {
            key: "note".into(),
            value: ProvValue::Text(wide.clone()),
        }],
    }))];
    let expected = apply_delta(&base, &ops).expect("in-memory delta");
    let streamed = round_trip(&base, &ops);
    assert_eq!(streamed.module, expected);
    let provenance = streamed.module.provenance().expect("provenance lands");
    assert_eq!(provenance.producer.as_deref(), Some(wide.as_str()));
    assert!(
        provenance.entries.iter().any(|entry| matches!(
            &entry.value,
            ProvValue::Text(found) if found == &wide
        )),
        "the wide provenance entry must land in the decoded module"
    );
}

#[test]
fn a_1mib_binding_name_delta_round_trips() {
    // The ceiling moves well past 64 KiB: a 1 MiB binding name is still
    // far below the image format's 64 MiB string ceiling and the 64 MiB
    // frame ceiling.
    let (base, port) = base_module();
    let wide = "b".repeat(1 << 20);
    let ops = vec![DeltaOp::SetBinding {
        name: wide.clone(),
        node: port,
    }];
    let expected = apply_delta(&base, &ops).expect("in-memory delta");
    let streamed = round_trip(&base, &ops);
    assert_eq!(streamed.module, expected);
    assert!(
        streamed
            .module
            .bindings()
            .iter()
            .any(|(name, _)| name == &wide),
        "the 1 MiB binding must land in the decoded module"
    );
}

#[test]
fn a_65535_byte_string_stays_narrow() {
    // The boundary: exactly `u16::MAX` bytes still fits the narrow form,
    // so the encoder must not widen the stream for it.
    let (base, port) = base_module();
    let name = "b".repeat(u16::MAX as usize);
    let ops = vec![DeltaOp::SetBinding {
        name: name.clone(),
        node: port,
    }];
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder.push_delta(&base, &ops).expect("delta");
    let frames = encoder.frames();
    assert_eq!(
        frames[0].payload[6..8],
        [0, 0],
        "a 65535-byte string must not set the wide-strings Begin flag"
    );
    let bytes = encoder.to_bytes();
    let streamed = decode_stream(&bytes).expect("decode");
    assert_eq!(streamed.module, apply_delta(&base, &ops).expect("delta"));
}

#[test]
fn a_65536_byte_string_widens_the_stream() {
    // One byte past the boundary: the encoder upgrades the stream.
    let (base, port) = base_module();
    let wide = "b".repeat(u16::MAX as usize + 1);
    let ops = vec![DeltaOp::SetBinding {
        name: wide.clone(),
        node: port,
    }];
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder.push_delta(&base, &ops).expect("delta");
    let frames = encoder.frames();
    assert_eq!(
        frames[0].payload[6] & 1,
        1,
        "a 65536-byte string must set the wide-strings Begin flag"
    );
    let bytes = encoder.to_bytes();
    let streamed = decode_stream(&bytes).expect("decode");
    assert_eq!(streamed.module, apply_delta(&base, &ops).expect("delta"));
}

#[test]
fn a_narrow_stream_is_byte_identical_to_v1() {
    // A stream with no wide string must be exactly what a v1 encoder
    // produced: `Begin` flag word zero and a `u16` length prefix on the
    // delta string.
    let (base, port) = base_module();
    let name = "short-name".to_string();
    let ops = vec![DeltaOp::SetBinding {
        name: name.clone(),
        node: port,
    }];
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder.push_delta(&base, &ops).expect("delta");
    let frames = encoder.frames();
    assert_eq!(
        frames[0].payload[6..8],
        [0, 0],
        "a narrow stream must carry a zero Begin flag word"
    );
    let delta = frames
        .iter()
        .find(|frame| frame.kind == FrameKind::Delta)
        .expect("a delta frame");
    assert_eq!(delta.payload[4], 3, "first op is SetBinding (tag 3)");
    assert_eq!(
        delta.payload[5..7],
        (name.len() as u16).to_le_bytes(),
        "the binding name carries a u16 length prefix"
    );
    let bytes = encoder.to_bytes();
    let streamed = decode_stream(&bytes).expect("decode");
    assert_eq!(streamed.module, apply_delta(&base, &ops).expect("delta"));
}

#[test]
fn a_second_generation_cannot_widen_a_narrow_stream() {
    // The width is stream-wide: once a narrow `Delta` frame exists, a
    // later wide delta cannot rewrite it, so the encoder refuses instead
    // of emitting a stream its own decoder would misread.
    let (base, port) = base_module();
    let narrow = vec![DeltaOp::SetBinding {
        name: "small".into(),
        node: port,
    }];
    let updated = apply_delta(&base, &narrow).expect("in-memory delta");
    let wide = vec![DeltaOp::SetBinding {
        name: "b".repeat(70 * 1024),
        node: port,
    }];
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder.push_delta(&base, &narrow).expect("narrow delta");
    let frames_before = encoder.frames().len();
    let error = encoder
        .push_delta(&updated, &wide)
        .expect_err("a late wide delta on a narrow stream is refused");
    assert_eq!(error.code(), "infinity/stream-delta");
    assert!(
        format!("{error}").contains("narrow delta frames"),
        "the refusal must name the cause: {error}"
    );
    assert_eq!(
        encoder.frames().len(),
        frames_before,
        "a refused push_delta appends no frames"
    );
}

#[test]
fn a_serialized_stream_refuses_a_late_wide_delta() {
    // The `Begin` frame may already be on the wire: once the encoder has
    // been serialized, a first wide delta cannot upgrade the `Begin` the
    // peer already holds, so the encoder refuses locally instead of
    // letting the peer fail on the mismatch.
    let (base, port) = base_module();
    let wide = vec![DeltaOp::SetBinding {
        name: "b".repeat(70 * 1024),
        node: port,
    }];
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    let _ = encoder.to_bytes();
    let error = encoder
        .push_delta(&base, &wide)
        .expect_err("a wide delta after serialization is refused");
    assert_eq!(error.code(), "infinity/stream-delta");
    assert!(
        format!("{error}").contains("already serialized"),
        "the refusal must name the cause: {error}"
    );
    // Control: the same pattern with a narrow delta still works — the
    // guard only fires when widening is actually needed.
    let narrow = vec![DeltaOp::SetBinding {
        name: "small".into(),
        node: port,
    }];
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    let _ = encoder.to_bytes();
    encoder.push_delta(&base, &narrow).expect("narrow delta");
}

#[test]
fn an_unknown_begin_reserved_bit_is_still_refused() {
    // Only bit 0 of the `Begin` stream-flags word is assigned; every
    // other bit is still reserved and refused with `infinity/reserved`.
    let (base, _port) = base_module();
    let mut frames = StreamEncoder::new(&base, 4096).expect("encoder").frames();
    frames[0].payload[6] |= 0x02;
    let mut bytes = Vec::new();
    for frame in &frames {
        bytes.extend_from_slice(&frame.to_bytes());
    }
    let mut decoder = StreamDecoder::new();
    let error = decoder
        .push_bytes(&bytes)
        .expect_err("an unknown Begin flag bit is refused");
    assert_eq!(error.code(), "infinity/reserved");
}

#[test]
fn a_wide_delta_frame_against_a_narrow_begin_is_refused() {
    // The width comes from the `Begin` frame, so a wide `Delta` frame
    // smuggled under a narrow `Begin` must not decode: the decoder reads
    // the `u32` length's low bytes as a `u16` length, the cursor lands
    // mid-string, and the frame fails its trailing-bytes check.
    let (base, port) = base_module();
    let wide = "b".repeat(70 * 1024);
    let ops = vec![DeltaOp::SetBinding {
        name: wide,
        node: port,
    }];
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder.push_delta(&base, &ops).expect("wide delta");
    let mut frames = encoder.frames();
    assert_eq!(
        frames[0].payload[6] & 1,
        1,
        "the stream under test must be wide before tampering"
    );
    frames[0].payload[6..8].copy_from_slice(&[0, 0]);
    let mut bytes = Vec::new();
    for frame in &frames {
        bytes.extend_from_slice(&frame.to_bytes());
    }
    let mut decoder = StreamDecoder::new();
    let error = decoder
        .push_bytes(&bytes)
        .expect_err("a wide delta under a narrow Begin is refused");
    assert_eq!(error.code(), "infinity/stream-delta", "{error}");
}

#[test]
fn the_builder_widens_up_front_and_later_generations_stay_wide() {
    // The opt-in path: the flag is set at construction, so a narrow
    // first generation and a wide second one both encode wide, and the
    // whole stream round-trips.
    let (base, port) = base_module();
    let narrow = vec![DeltaOp::SetBinding {
        name: "small".into(),
        node: port,
    }];
    let updated = apply_delta(&base, &narrow).expect("in-memory delta");
    let wide = vec![DeltaOp::SetBinding {
        name: "b".repeat(70 * 1024),
        node: port,
    }];
    let expected = apply_delta(&updated, &wide).expect("in-memory delta");
    let mut encoder = StreamEncoder::new(&base, 4096)
        .expect("encoder")
        .with_wide_delta_strings();
    assert_eq!(
        encoder.frames()[0].payload[6] & 1,
        1,
        "the builder must set the flag before any delta"
    );
    encoder.push_delta(&base, &narrow).expect("narrow delta");
    encoder
        .push_delta(&updated, &wide)
        .expect("wide delta in a later generation");
    let bytes = encoder.to_bytes();
    let streamed = decode_stream(&bytes).expect("decode");
    assert_eq!(streamed.module, expected);
}

#[test]
fn a_wide_binding_can_be_removed_in_a_later_generation() {
    // The `RemoveBinding` path writes the name through
    // `write_delta_string` too, and a later generation of an already
    // wide stream stays wide.
    let (base, port) = base_module();
    let wide = "b".repeat(70 * 1024);
    let set = vec![DeltaOp::SetBinding {
        name: wide.clone(),
        node: port,
    }];
    let updated = apply_delta(&base, &set).expect("in-memory delta");
    let remove = vec![DeltaOp::RemoveBinding { name: wide.clone() }];
    let expected = apply_delta(&updated, &remove).expect("in-memory delta");
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder.push_delta(&base, &set).expect("wide set");
    encoder
        .push_delta(&updated, &remove)
        .expect("wide remove in a later generation");
    let bytes = encoder.to_bytes();
    let streamed = decode_stream(&bytes).expect("decode");
    assert_eq!(streamed.module, expected);
    assert!(
        streamed
            .module
            .bindings()
            .iter()
            .all(|(name, _)| name != &wide),
        "the wide binding must be gone after the remove"
    );
}
