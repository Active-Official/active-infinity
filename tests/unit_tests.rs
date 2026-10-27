//! Unit tests for the codec core: round-trip, canonical identity, views,
//! streaming, secrets and the validator's failure classes.
//!
//! These tests drive the shipped public API only (`encode`, `decode`,
//! `validate`, `InfinityView`, `StreamEncoder`/`StreamDecoder`), never a copy
//! of the implementation.

use active_infinity::{
    content_hash, decode, encode, error::Error, hash_image, stream, validate, validate_canonical,
    AnnotationKind, Constraint, DecodeOpts, EncodeOpts, InfinityModule, InfinityView, Inode,
    Limits, PatchOp, ProvEntry, ProvValue, Provenance, SchemaFieldSpec, SecretBytes, SemanticTag,
    TypeSpec, UnitTag,
};

fn fixture() -> InfinityModule {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("api".into()));
    let port = module.push(Inode::Int(8080));
    let timeout = {
        let number = module.push(Inode::Int(30));
        module.push(Inode::Quantity {
            value: number,
            unit: UnitTag::Seconds,
        })
    };
    let flags = {
        let a = module.push(Inode::Bool(true));
        let b = module.push(Inode::Null);
        module.push(Inode::Array {
            elements: vec![a, b],
        })
    };
    let nested = module.push(Inode::Table {
        fields: vec![("timeout".into(), timeout), ("flags".into(), flags)],
    });
    let root = module.push(Inode::Table {
        fields: vec![
            ("name".into(), name),
            ("port".into(), port),
            ("nested".into(), nested),
        ],
    });
    module.set_root(Some(root));
    module.bind("root", root);
    module
}

#[test]
fn round_trip_preserves_values() {
    let module = fixture();
    let bytes = encode(&module).expect("encode");
    let decoded = decode(&bytes).expect("decode");
    assert_eq!(decoded, module);
    let reencoded = encode(&decoded).expect("re-encode");
    assert_eq!(
        reencoded, bytes,
        "canonical re-encode must be byte identical"
    );
    assert_eq!(
        content_hash(&bytes).unwrap(),
        content_hash(&reencoded).unwrap()
    );
}

#[test]
fn canonical_identity_is_independent_of_construction_order() {
    // Same logical table, children created in the opposite order.
    let mut first = InfinityModule::new();
    let a1 = first.push(Inode::Str("a".into()));
    let b1 = first.push(Inode::Int(1));
    let root1 = first.push(Inode::Table {
        fields: vec![("a".into(), a1), ("b".into(), b1)],
    });
    first.set_root(Some(root1));

    let mut second = InfinityModule::new();
    let b2 = second.push(Inode::Int(1));
    let a2 = second.push(Inode::Str("a".into()));
    let root2 = second.push(Inode::Table {
        fields: vec![("b".into(), b2), ("a".into(), a2)],
    });
    second.set_root(Some(root2));

    assert_eq!(encode(&first).unwrap(), encode(&second).unwrap());
    assert_eq!(
        content_hash(&encode(&first).unwrap()).unwrap(),
        content_hash(&encode(&second).unwrap()).unwrap()
    );
}

#[test]
fn content_hash_changes_with_any_value_change() {
    let bytes = encode(&fixture()).unwrap();
    let mut mutated = bytes.clone();
    // Flip one byte of the last string: the hash must change (and validation
    // must reject the mutated image).
    let last = mutated.len() - 1;
    mutated[last] ^= 0xff;
    let before = hash_image(&bytes).unwrap();
    let after = hash_image(&mutated).unwrap();
    assert_ne!(before, after);
}

#[test]
fn every_node_kind_round_trips() {
    let mut module = InfinityModule::new();
    let mut ids = vec![
        module.push(Inode::Null),
        module.push(Inode::Bool(false)),
        module.push(Inode::Int(-42)),
        module.push(Inode::Float(2.5)),
        module.push(Inode::Str("text".into())),
        module.push(Inode::DurationMs(1500)),
    ];
    let value = module.push(Inode::Int(7));
    ids.push(module.push(Inode::Quantity {
        value,
        unit: UnitTag::Named("widgets".into()),
    }));
    let element = module.push(Inode::Int(1));
    ids.push(module.push(Inode::Array {
        elements: vec![element, element],
    }));
    let field = module.push(Inode::Str("k".into()));
    ids.push(module.push(Inode::Table {
        fields: vec![("k".into(), field)],
    }));
    ids.push(module.push(Inode::Secret(SecretBytes::from("hunter2"))));
    ids.push(module.push(Inode::SecretRef { locator: value }));
    ids.push(module.push(Inode::Ref(value)));
    ids.push(module.push(Inode::Env {
        name: "HOME".into(),
        default: Some(value),
    }));
    ids.push(module.push(Inode::Ident("unresolved".into())));
    ids.push(module.push(Inode::Interpolate {
        parts: vec![
            active_infinity::InterpPart::Literal("v=".into()),
            active_infinity::InterpPart::Expr(value),
        ],
    }));
    ids.push(module.push(Inode::Binary {
        op: active_infinity::BinOp::Add,
        lhs: value,
        rhs: element,
    }));
    ids.push(module.push(Inode::Unary {
        op: active_infinity::UnOp::Neg,
        expr: value,
    }));
    ids.push(module.push(Inode::Constrained {
        target: value,
        constraint: Constraint::MinMax {
            min: Some(0),
            max: Some(10),
        },
    }));
    ids.push(module.push(Inode::Patch(PatchOp::Set {
        path: "a.b".into(),
        value,
    })));
    ids.push(module.push(Inode::SchemaField(SchemaFieldSpec {
        typ: TypeSpec::Enum(vec!["a".into(), "b".into()]),
        min: Some(value),
        max: None,
        min_len: None,
        max_len: None,
        pattern: None,
        default: Some(value),
        deprecated: Some("use b".into()),
    })));
    ids.push(module.push(Inode::SchemaTable {
        fields: vec![("k".into(), field)],
        closed: true,
    }));
    ids.push(module.push(Inode::SchemaArray { element: value }));
    ids.push(module.push(Inode::Semantic {
        tag: SemanticTag::Prompt,
        inner: field,
    }));
    ids.push(module.push(Inode::ContentAddressed {
        media_type: field,
        data: value,
    }));
    let payload = b"payload".to_vec();
    let hash = *blake3::hash(&payload).as_bytes();
    ids.push(module.push(Inode::Blob {
        hash,
        size: payload.len() as u64,
        tainted: false,
        media_type: "text/plain".into(),
        payload: Some(payload),
    }));
    let root = module.push(Inode::Array {
        elements: ids.clone(),
    });
    module.set_root(Some(root));

    let bytes = encode(&module).expect("encode");
    let decoded = decode(&bytes).expect("decode");
    assert_eq!(decoded.node_count(), module.node_count());
    assert_eq!(encode(&decoded).unwrap(), bytes);
    // Module equality blinds secret payloads (anti-oracle) but compares the
    // structure, so a canonical round trip is equal.
    assert_eq!(decoded, module);
    let mut kinds: Vec<u8> = module.nodes().iter().map(|node| node.kind_code()).collect();
    let mut decoded_kinds: Vec<u8> = decoded
        .nodes()
        .iter()
        .map(|node| node.kind_code())
        .collect();
    kinds.sort_unstable();
    decoded_kinds.sort_unstable();
    assert_eq!(
        kinds, decoded_kinds,
        "every node kind survives a round trip"
    );
}

#[test]
fn annotations_and_provenance_round_trip() {
    let mut module = fixture();
    let root = module.root().unwrap();
    module.annotate(root, AnnotationKind::Intent("root intent".into()));
    module.annotate(root, AnnotationKind::AiImmutable(true));
    let expr = module.push(Inode::Bool(true));
    module.annotate(
        root,
        AnnotationKind::Constraint {
            source: "value != null".into(),
            expr,
        },
    );
    let parent = [9u8; 32];
    module.set_provenance(Some(Provenance {
        producer: Some("agent-7".into()),
        timestamp_ms: 1_700_000_000_123,
        model: Some("grok".into()),
        tool: Some("active-infinity".into()),
        parent: Some(parent),
        entries: vec![
            ProvEntry {
                key: "zeta".into(),
                value: ProvValue::Int(5),
            },
            ProvEntry {
                key: "alpha".into(),
                value: ProvValue::Text("first".into()),
            },
            ProvEntry {
                key: "flag".into(),
                value: ProvValue::Flag(true),
            },
            ProvEntry {
                key: "lineage".into(),
                value: ProvValue::Hash([3u8; 32]),
            },
        ],
    }));
    let bytes = encode(&module).unwrap();
    let decoded = decode(&bytes).unwrap();
    assert_eq!(decoded.annotations().len(), 3);
    assert_eq!(decoded.provenance(), module.provenance());
    // Entries are canonicalized into key order.
    let prov = decoded.provenance().unwrap();
    let keys: Vec<&str> = prov
        .entries
        .iter()
        .map(|entry| entry.key.as_str())
        .collect();
    assert_eq!(keys, vec!["alpha", "flag", "lineage", "zeta"]);
    assert_eq!(encode(&decoded).unwrap(), bytes);
}

#[test]
fn view_borrows_from_the_buffer() {
    let mut module = fixture();
    let blob_payload = b"zero-copy-blob".to_vec();
    let blob_hash = *blake3::hash(&blob_payload).as_bytes();
    let blob = module.push(Inode::Blob {
        hash: blob_hash,
        size: blob_payload.len() as u64,
        tainted: false,
        media_type: "application/octet-stream".into(),
        payload: Some(blob_payload.clone()),
    });
    let root = module.push(Inode::Table {
        fields: vec![("blob".into(), blob)],
    });
    module.set_root(Some(root));
    let bytes = encode(&module).unwrap();

    let view = InfinityView::new(&bytes, Limits::default()).expect("view");
    let buffer_start = bytes.as_ptr() as usize;
    let buffer_end = buffer_start + bytes.len();

    let string = view.string(0).expect("string 0");
    let pointer = string.as_ptr() as usize;
    assert!(
        pointer >= buffer_start && pointer < buffer_end,
        "string must be borrowed from the buffer"
    );

    let payload = view.blob(0).expect("blob 0");
    let pointer = payload.as_ptr() as usize;
    assert_eq!(payload, blob_payload.as_slice());
    assert!(pointer >= buffer_start && pointer < buffer_end);

    assert_eq!(view.node_count(), module.node_count() as u32);
    assert_eq!(view.content_hash(), content_hash(&bytes).unwrap());
    // Modifying the buffer after a view is impossible (shared borrow), which
    // is what makes the zero-copy contract safe.
    assert!(std::ptr::eq(bytes.as_slice(), view.buf()));
}

#[test]
fn streaming_reassembles_the_identical_image() {
    let module = fixture();
    let whole = encode(&module).unwrap();
    for chunk in [1usize, 7, 64, 1 << 16] {
        let frames = stream::encode_stream(&module, chunk).expect("encode stream");
        let mut bytes = Vec::new();
        for frame in &frames {
            bytes.extend_from_slice(&frame.to_bytes());
        }
        // Feed in awkward slices too: frame boundaries must not be required.
        let mut decoder = stream::StreamDecoder::new();
        for piece in bytes.chunks(13) {
            decoder
                .push_bytes(piece)
                .unwrap_or_else(|e| panic!("push failed at chunk {chunk}: {e:?}"));
        }
        let streamed = decoder
            .finish()
            .unwrap_or_else(|e| panic!("finish failed at chunk {chunk}: {e:?}"));
        assert_eq!(streamed.image, whole, "chunk size {chunk}");
        assert_eq!(streamed.content_hash, content_hash(&whole).unwrap());
        // The canonical form renumbers the root to node 0 and keeps its shape.
        let root = streamed.module.root().expect("root");
        assert!(matches!(
            streamed.module.get(root),
            Some(Inode::Table { fields }) if fields.len() == 3
        ));
    }
}

#[test]
fn streaming_delta_produces_the_whole_module_encoding() {
    let module = fixture();
    let mut encoder = stream::StreamEncoder::new(&module, 32).unwrap();

    // The receiver holds the canonical base generation; deltas address its
    // canonical node ids.
    let base = stream::decode_stream(&encoder.to_bytes())
        .expect("base generation")
        .module;

    let target = base
        .nodes()
        .iter()
        .position(|node| matches!(node, Inode::Int(8080)))
        .map(|index| active_infinity::NodeId(index as u32))
        .expect("port node");

    let mut fragment = InfinityModule::new();
    let number = fragment.push(Inode::Int(9090));
    fragment.set_root(Some(number));

    let ops = vec![stream::DeltaOp::PutNode {
        target,
        fragment: Box::new(fragment),
    }];
    encoder.push_delta(&base, &ops).unwrap();

    let bytes = encoder.to_bytes();
    let streamed = stream::decode_stream(&bytes).unwrap_or_else(|e| panic!("decode stream: {e:?}"));

    // Expected: the same ops applied to the base, canonicalized.
    let expected = stream::apply_delta(&base, &ops).expect("apply delta");
    let expected_image = encode(&expected).unwrap();
    assert_eq!(streamed.image, expected_image);
    assert_eq!(
        streamed.content_hash,
        content_hash(&expected_image).unwrap()
    );
    assert!(streamed
        .module
        .nodes()
        .iter()
        .any(|node| matches!(node, Inode::Int(9090))));
    assert!(!streamed
        .module
        .nodes()
        .iter()
        .any(|node| matches!(node, Inode::Int(8080))));
}

#[test]
fn secrets_never_leak_through_debug_or_exports() {
    let mut module = fixture();
    let secret = module.push(Inode::Secret(SecretBytes::from("hunter2-canary")));
    let root = module.push(Inode::Array {
        elements: vec![secret],
    });
    module.set_root(Some(root));
    let bytes = encode(&module).unwrap();
    let decoded = decode(&bytes).unwrap();

    let debug = format!("{decoded:?}");
    let node_debug = format!("{:?}", decoded.nodes());
    assert!(!debug.contains("hunter2-canary"), "Debug leaked a secret");
    assert!(!node_debug.contains("hunter2-canary"), "node Debug leaked");
    assert!(debug.contains("Secret(***)"));

    let displayed = format!("{}", SecretBytes::from("hunter2-canary"));
    assert_eq!(displayed, "***SECRET***");
    let bytes_view = InfinityView::new(&bytes, Limits::default()).unwrap();
    assert!(!format!("{bytes_view:?}").contains("hunter2-canary"));
}

#[test]
fn secret_equality_is_always_false() {
    let one = SecretBytes::from("same");
    let two = SecretBytes::from("same");
    assert_ne!(one, two);
    assert_ne!(one, one.clone());
    let mut module = fixture();
    let secret = module.push(Inode::Secret(SecretBytes::from("x")));
    module.set_root(Some(secret));
    let bytes = encode(&module).unwrap();
    let decoded = decode(&bytes).unwrap();
    assert_eq!(
        decoded,
        decoded.clone(),
        "structural equality blinds secret bytes"
    );
}

#[test]
fn validator_rejects_every_declared_failure_class() {
    let bytes = encode(&fixture()).unwrap();

    let mut bad_magic = bytes.clone();
    bad_magic[0] = b'X';
    assert_eq!(validate(&bad_magic).unwrap_err().code(), "infinity/magic");

    let mut bad_major = bytes.clone();
    bad_major[4] = 9;
    assert_eq!(
        validate(&bad_major).unwrap_err().code(),
        "infinity/version-major"
    );

    let mut bad_minor = bytes.clone();
    bad_minor[6] = 9;
    assert_eq!(
        validate(&bad_minor).unwrap_err().code(),
        "infinity/version-minor"
    );

    let truncated = &bytes[..bytes.len() - 1];
    assert_eq!(
        validate(truncated).unwrap_err().code(),
        "infinity/truncated"
    );

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        validate(&trailing).unwrap_err().code(),
        "infinity/trailing-bytes"
    );

    let mut bad_hash = bytes.clone();
    bad_hash[16] ^= 0xff;
    assert_eq!(
        validate(&bad_hash).unwrap_err().code(),
        "infinity/hash-mismatch"
    );

    let mut bad_flags = bytes.clone();
    bad_flags[8] = 0xff;
    let code = validate(&bad_flags).unwrap_err().code();
    assert!(
        code == "infinity/flags" || code == "infinity/hash-mismatch",
        "unexpected code {code}"
    );

    // Count bomb: claim four million nodes in a tiny buffer.
    let mut count_bomb = bytes.clone();
    count_bomb[64..68].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    let code = validate(&count_bomb).unwrap_err().code();
    assert!(code.starts_with("infinity/"), "unexpected code {code}");
    assert_ne!(code, "infinity/hash-mismatch");

    // A limits-imposed ceiling must trip even on a well-formed image.
    let strict = Limits {
        max_nodes: 1,
        ..Limits::default()
    };
    let opts = DecodeOpts {
        limits: strict,
        verify_hash: true,
        verify_canonical: false,
    };
    assert_eq!(
        active_infinity::validate_with(&bytes, opts)
            .unwrap_err()
            .code(),
        "infinity/limit"
    );
}

#[test]
fn validator_rejects_unknown_unit_discriminant() {
    // Build a module with one quantity, then patch the unit table entry.
    let mut module = InfinityModule::new();
    let number = module.push(Inode::Int(1));
    let quantity = module.push(Inode::Quantity {
        value: number,
        unit: UnitTag::Meters,
    });
    module.set_root(Some(quantity));
    let mut bytes = encode(&module).unwrap();
    let header = active_infinity::layout::Header::parse(&bytes).unwrap();
    let unit_offset = header.span(active_infinity::Section::Units).offset as usize;
    for section in active_infinity::Section::ALL {
        let span = header.span(section);
        eprintln!(
            "{} off={} count={}",
            section.name(),
            span.offset,
            span.count
        );
    }
    eprintln!("total={} len={}", header.total_size, bytes.len());
    bytes[unit_offset..unit_offset + 4].copy_from_slice(&9999u32.to_le_bytes());
    // Recompute the hash so the only failure is the unit discriminant.
    let hash = hash_image(&bytes).unwrap();
    bytes[16..48].copy_from_slice(&hash);
    let error = validate(&bytes).unwrap_err();
    assert_eq!(error.code(), "infinity/unknown-unit", "{error:?}");
}

#[test]
fn validator_rejects_cycles_and_unreachable_nodes() {
    // Cycle: A -> B -> A.
    let mut module = InfinityModule::new();
    let a = module.push(Inode::Null);
    let b = module.push(Inode::Ref(a));
    *module.node_mut(a).unwrap() = Inode::Ref(b);
    module.set_root(Some(a));
    let error = encode(&module).unwrap_err();
    assert_eq!(error.code(), "infinity/cycle");

    // Unreachable node: canonicalization drops it from the image.
    let mut module = fixture();
    let _orphan = module.push(Inode::Str("orphan".into()));
    let previous_root = module.root().unwrap();
    let root = module.push(Inode::Table {
        fields: vec![("root".into(), previous_root)],
    });
    module.set_root(Some(root));
    let bytes = encode(&module).unwrap();
    let decoded = decode(&bytes).unwrap();
    assert!(
        decoded.node_count() < module.node_count(),
        "canonical form drops unreachable nodes"
    );
}

#[test]
fn encode_without_canonical_flag_still_validates() {
    let module = fixture();
    let bytes = encode_with_no_flags(&module);
    let meta = validate(&bytes).expect("valid image");
    assert_eq!(meta.flags & active_infinity::FLAG_CANONICAL, 0);
    assert!(meta.nodes > 0);
}

fn encode_with_no_flags(module: &InfinityModule) -> Vec<u8> {
    let mut image = encode(module).unwrap();
    image[8] &= !(active_infinity::FLAG_CANONICAL as u8);
    let hash = hash_image(&image).unwrap();
    image[16..48].copy_from_slice(&hash);
    image
}

#[test]
fn encode_options_round_trip() {
    let module = fixture();
    let bytes = active_infinity::encode_with(
        &module,
        EncodeOpts {
            write_hash: true,
            mark_canonical: true,
            streamed: true,
        },
    )
    .unwrap();
    let meta = validate(&bytes).unwrap();
    assert_ne!(meta.flags & active_infinity::layout::FLAG_STREAMED, 0);
    assert!(decode(&bytes).is_ok());
}

#[test]
fn canonical_proof_is_unconditional() {
    let bytes = encode(&fixture()).unwrap();
    validate_canonical(&bytes, Limits::default()).expect("the encoder emits canonical bytes");

    // Clear the canonical flag without touching the payload. The image stays
    // structurally valid, but it is no longer the canonical encoding of its own
    // content, so the proof must refuse it.
    let mut unflagged = bytes.clone();
    let flags = u16::from_le_bytes([unflagged[8], unflagged[9]]) & !active_infinity::FLAG_CANONICAL;
    unflagged[8..10].copy_from_slice(&flags.to_le_bytes());
    let hash = hash_image(&unflagged).unwrap();
    unflagged[16..48].copy_from_slice(&hash);

    validate(&unflagged).expect("structure is still valid");
    let error = validate_canonical(&unflagged, Limits::default())
        .expect_err("an unflagged image is not the canonical encoding");
    assert_eq!(error.code(), "infinity/not-canonical");

    // The option form and the free function agree.
    let opts = DecodeOpts {
        limits: Limits::default(),
        verify_hash: true,
        verify_canonical: true,
    };
    let error = active_infinity::validate_with(&unflagged, opts)
        .expect_err("the gated proof agrees with the free function");
    assert_eq!(error.code(), "infinity/not-canonical");
}

#[test]
fn extension_payloads_must_be_packed() {
    // The gap vector is checked in the conformance suite; this pins the rule
    // against a hand-built module as well: rewriting a middle payload offset
    // moves that payload, so the section is rejected.
    let mut module = fixture();
    module.add_extension(10, b"first".to_vec());
    module.add_extension(20, b"second".to_vec());
    module.add_extension(30, b"third".to_vec());
    let bytes = encode(&module).unwrap();
    validate(&bytes).expect("the encoder packs payloads");

    // Shifting the *middle* entry keeps the section end unchanged (the last
    // payload still ends where it did), so this is a packing fault, not a
    // layout fault.
    let header = active_infinity::layout::Header::parse(&bytes).unwrap();
    let ext = header.span(active_infinity::Section::Extensions).offset as usize;
    let mut gapped = bytes.clone();
    let middle = u32::from_le_bytes(gapped[ext + 16 + 8..ext + 16 + 12].try_into().unwrap());
    gapped[ext + 16 + 8..ext + 16 + 12].copy_from_slice(&(middle + 8).to_le_bytes());
    let hash = hash_image(&gapped).unwrap();
    gapped[16..48].copy_from_slice(&hash);
    let error = validate(&gapped).expect_err("a gap must be rejected");
    assert_eq!(error.code(), "infinity/extension");
}

#[test]
fn error_codes_are_stable_and_documented() {
    let expected = [
        (Error::Magic, "infinity/magic"),
        (Error::HashMismatch, "infinity/hash-mismatch"),
        (Error::Cycle { node: 1 }, "infinity/cycle"),
        (Error::UnknownUnit(7), "infinity/unknown-unit"),
        (Error::StreamMagic, "infinity/stream-magic"),
    ];
    for (error, code) in expected {
        assert_eq!(error.code(), code);
        assert!(!format!("{error}").is_empty());
    }
}

#[test]
fn extension_blocks_round_trip_and_are_order_independent() {
    let mut first = fixture();
    first.add_extension(7, b"seven".to_vec());
    first.add_extension(3, b"three".to_vec());
    let mut second = fixture();
    second.add_extension(3, b"three".to_vec());
    second.add_extension(7, b"seven".to_vec());

    // Canonical order makes the two construction orders one image.
    let a = encode(&first).unwrap();
    let b = encode(&second).unwrap();
    assert_eq!(a, b, "extension order must not change the image");

    let meta = validate(&a).unwrap();
    assert_eq!(meta.extensions, 2, "the directory is accounted for");

    let decoded = decode(&a).unwrap();
    let extensions = decoded.extensions();
    assert_eq!(extensions.len(), 2);
    assert_eq!(extensions[0].0, 3);
    assert_eq!(extensions[0].1, b"three".to_vec());
    assert_eq!(extensions[1].0, 7);
    assert_eq!(extensions[1].1, b"seven".to_vec());
    assert_eq!(encode(&decoded).unwrap(), a, "extensions survive a decode");

    // The zero-copy view sees the same directory.
    let validated = active_infinity::Validated::new(&a, DecodeOpts::default()).unwrap();
    let (tag, offset, len) = validated.extension_entry(1).unwrap();
    assert_eq!(tag, 7);
    assert_eq!(validated.extension_payload(offset, len).unwrap(), b"seven");
}

#[test]
fn duplicate_extension_tags_are_refused() {
    let mut module = fixture();
    module.add_extension(5, b"first".to_vec());
    module.add_extension(5, b"second".to_vec());
    let error = encode(&module).expect_err("duplicate tags must not encode");
    assert_eq!(error.code(), "infinity/encode");
    assert!(format!("{error}").contains("duplicate extension tag"));
}

#[test]
fn an_extension_flag_without_blocks_is_rejected() {
    let mut bytes = encode(&fixture()).unwrap();
    let header = active_infinity::layout::Header::parse(&bytes).unwrap();
    assert_eq!(header.span(active_infinity::Section::Extensions).count, 0);
    let flags = u16::from_le_bytes([bytes[8], bytes[9]]) | active_infinity::layout::FLAG_EXTENSIONS;
    bytes[8..10].copy_from_slice(&flags.to_le_bytes());
    let hash = hash_image(&bytes).unwrap();
    bytes[16..48].copy_from_slice(&hash);
    let error = validate(&bytes).expect_err("a flag without blocks must be rejected");
    assert_eq!(error.code(), "infinity/extension");
}
