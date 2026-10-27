//! Red-team suite: adversarial inputs against every control in
//! `docs/spec/security.md`.
//!
//! Each test names the threat it covers. A passing run means the codec rejected
//! the attack with the documented class rather than panicking, hanging,
//! over-allocating or leaking.

use std::time::Instant;

use active_infinity::interop::provenance_lines;
#[cfg(feature = "json")]
use active_infinity::interop::to_redacted_json;
use active_infinity::stream::{Frame, FrameKind, StreamDecoder};
use active_infinity::{
    decode, encode, hash_image, validate, validate_canonical, AnnotationKind, DecodeOpts,
    InfinityModule, InfinityView, Inode, Limits, ProvEntry, ProvValue, Provenance, SecretBytes,
    Section, UnitTag,
};

fn fixture() -> InfinityModule {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("svc".into()));
    let port = module.push(Inode::Int(8080));
    let q = {
        let n = module.push(Inode::Int(5));
        module.push(Inode::Quantity {
            value: n,
            unit: UnitTag::Milliseconds,
        })
    };
    let secret = module.push(Inode::Secret(SecretBytes::from("canary-0123456789")));
    let root = module.push(Inode::Table {
        fields: vec![
            ("name".into(), name),
            ("port".into(), port),
            ("q".into(), q),
            ("secret".into(), secret),
        ],
    });
    module.set_root(Some(root));
    module
}

fn header(bytes: &[u8]) -> active_infinity::layout::Header {
    active_infinity::layout::Header::parse(bytes).expect("header")
}

fn rewrite_hash(bytes: &mut [u8]) {
    let hash = hash_image(bytes).expect("hash");
    bytes[16..48].copy_from_slice(&hash);
}

#[test]
fn threat_count_bombs_in_every_section() {
    let bytes = encode(&fixture()).unwrap();
    for (index, section) in Section::ALL.iter().enumerate() {
        if *section == Section::Provenance || *section == Section::Extensions {
            continue; // byte-length sections are covered by the size checks
        }
        let mut mutated = bytes.clone();
        let count_at = 64 + index * 8 + 4;
        mutated[count_at..count_at + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let outcome = std::panic::catch_unwind(|| validate(&mutated));
        assert!(outcome.is_ok(), "{} bomb panicked", section.name());
        let error = outcome.unwrap().unwrap_err();
        assert!(
            matches!(
                error.code(),
                "infinity/limit" | "infinity/count" | "infinity/offset" | "infinity/truncated"
            ),
            "{} bomb returned {}",
            section.name(),
            error.code()
        );
    }
}

#[test]
fn threat_offset_and_overlap_attacks() {
    let bytes = encode(&fixture()).unwrap();
    // Point a section at the header itself (overlap).
    let mut overlap = bytes.clone();
    overlap[64..68].copy_from_slice(&0u32.to_le_bytes());
    assert!(validate(&overlap).is_err());

    // Point a section past the end.
    let mut past_end = bytes.clone();
    past_end[68..72].copy_from_slice(&4096u32.to_le_bytes());
    rewrite_hash(&mut past_end);
    assert!(validate(&past_end).is_err());

    // Misaligned section start.
    let mut misaligned = bytes.clone();
    let nodes = header(&bytes).span(Section::Nodes).offset;
    misaligned[64..68].copy_from_slice(&(nodes + 3).to_le_bytes());
    assert!(validate(&misaligned).is_err());
}

#[test]
fn threat_self_referential_edge_and_forged_graph() {
    let bytes = encode(&fixture()).unwrap();
    let edge_span = header(&bytes).span(Section::Edges);
    assert!(edge_span.count > 0);
    let mut forged = bytes.clone();
    let edge_at = edge_span.offset as usize;
    let to = u32::from_le_bytes(bytes[edge_at + 4..edge_at + 8].try_into().unwrap());
    // Make the edge self-referential.
    forged[edge_at..edge_at + 4].copy_from_slice(&to.to_le_bytes());
    rewrite_hash(&mut forged);
    let error = validate(&forged).unwrap_err();
    assert_eq!(error.code(), "infinity/edge");
}

#[test]
fn threat_string_heap_faults() {
    let bytes = encode(&fixture()).unwrap();
    let span = header(&bytes).span(Section::Strings);
    let table = span.offset as usize;
    // Offsets must be cumulative; break the chain.
    let mut broken = bytes.clone();
    broken[table..table + 4].copy_from_slice(&1u32.to_le_bytes());
    rewrite_hash(&mut broken);
    assert!(validate(&broken).is_err());

    // Invalid UTF-8: overwrite the heap with a standalone continuation byte.
    let mut utf8 = bytes.clone();
    let heap = table + (span.count as usize + 1) * 4;
    utf8[heap] = 0x80;
    rewrite_hash(&mut utf8);
    let code = validate(&utf8).unwrap_err().code();
    assert!(
        code == "infinity/utf8" || code == "infinity/offset",
        "unexpected {code}"
    );
}

#[test]
fn threat_blob_substitution_and_tainted_payload() {
    let mut module = InfinityModule::new();
    let payload = b"blob-body".to_vec();
    let hash = *blake3::hash(&payload).as_bytes();
    let blob = module.push(Inode::Blob {
        hash,
        size: payload.len() as u64,
        tainted: false,
        media_type: "text/plain".into(),
        payload: Some(payload.clone()),
    });
    module.set_root(Some(blob));
    let bytes = encode(&module).unwrap();
    let meta = validate(&bytes).expect("valid blob");
    assert_eq!(meta.blobs, 1);

    // Substitute the payload; the hash in the index no longer matches.
    let mut mutated = bytes.clone();
    let span = header(&bytes).span(Section::Blobs);
    let heap = span.offset as usize + span.count as usize * 40;
    mutated[heap] ^= 0xff;
    rewrite_hash(&mut mutated);
    assert_eq!(validate(&mutated).unwrap_err().code(), "infinity/blob");

    // A tainted blob with a payload is refused at encode time.
    let mut tainted = InfinityModule::new();
    let blob = tainted.push(Inode::Blob {
        hash,
        size: payload.len() as u64,
        tainted: true,
        media_type: "text/plain".into(),
        payload: Some(payload),
    });
    tainted.set_root(Some(blob));
    assert_eq!(encode(&tainted).unwrap_err().code(), "infinity/encode");
}

#[test]
fn threat_deep_and_wide_modules_hit_limits_not_the_stack() {
    // A 100k-node chain: validation must be iterative and bounded.
    let mut chain = InfinityModule::new();
    let mut current = chain.push(Inode::Int(0));
    for _ in 0..20_000 {
        current = chain.push(Inode::Ref(current));
    }
    chain.set_root(Some(current));
    let bytes = encode(&chain).unwrap();
    let deep = DecodeOpts {
        limits: Limits {
            max_depth: 100_000,
            ..Limits::default()
        },
        verify_hash: true,
        verify_canonical: false,
    };
    let outcome = std::panic::catch_unwind(|| active_infinity::validate_with(&bytes, deep));
    assert!(outcome.is_ok(), "deep chain overflowed the stack");
    assert!(
        outcome.unwrap().is_ok(),
        "a 20k-deep chain must validate with a 100k depth ceiling"
    );
    // With the shipped ceiling the same image is refused by depth.
    assert_eq!(validate(&bytes).unwrap_err().code(), "infinity/depth");

    // Depth ceiling trips with a stable code.
    let opts = DecodeOpts {
        limits: Limits {
            max_depth: 64,
            ..Limits::default()
        },
        verify_hash: true,
        verify_canonical: false,
    };
    assert_eq!(
        active_infinity::validate_with(&bytes, opts)
            .unwrap_err()
            .code(),
        "infinity/depth"
    );
}

#[test]
fn threat_size_limits_are_enforced_without_allocation() {
    let bytes = encode(&fixture()).unwrap();
    let start = Instant::now();
    for _ in 0..1000 {
        let opts = DecodeOpts {
            limits: Limits {
                max_nodes: 1,
                ..Limits::default()
            },
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
    // A thousand rejected validations must be fast: nothing is allocated.
    assert!(
        start.elapsed().as_millis() < 2_000,
        "limit rejection is doing work proportional to the declared size"
    );
}

#[test]
fn threat_secret_never_reaches_any_export_surface() {
    const CANARY: &str = "canary-0123456789";
    let mut module = fixture();
    // Attach a secret locator the way the text language does: a string
    // literal referenced only by a SecretRef.
    let locator = module.push(Inode::Str(CANARY.into()));
    let secret_ref = module.push(Inode::SecretRef { locator });
    module.annotate(secret_ref, AnnotationKind::Intent("locator".into()));
    let root = module.root().unwrap();
    if let Ok(Inode::Table { fields }) = module.node_mut(root) {
        fields.push(("locator".into(), secret_ref));
    }
    module.set_provenance(Some(Provenance {
        producer: Some(CANARY.into()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: None,
        entries: vec![ProvEntry {
            key: "note".into(),
            value: ProvValue::Text(format!("value is {CANARY}")),
        }],
    }));

    let bytes = encode(&module).unwrap();
    let decoded = decode(&bytes).unwrap();

    #[allow(unused_mut)]
    let mut surfaces: Vec<(&str, String)> = vec![
        ("module debug", format!("{decoded:?}")),
        ("node debug", format!("{:?}", decoded.nodes())),
        ("provenance debug", format!("{:?}", decoded.provenance())),
        ("provenance lines", provenance_lines(&decoded).join("\n")),
        (
            "view debug",
            format!(
                "{:?}",
                InfinityView::new(&bytes, Limits::default()).expect("view")
            ),
        ),
        ("error", format!("{}", active_infinity::Error::Magic)),
        ("secret display", format!("{}", SecretBytes::from(CANARY))),
    ];
    #[cfg(feature = "json")]
    {
        surfaces.push(("json", to_redacted_json(&decoded).unwrap()));
        surfaces.push((
            "pretty json",
            active_infinity::interop::to_redacted_json_pretty(&decoded).unwrap(),
        ));
    }
    for (name, text) in surfaces {
        assert!(
            !text.contains(CANARY),
            "{name} leaked the secret canary: {text}"
        );
    }

    // The public string heap must not hold the locator after promotion.
    let strings = header(&bytes).span(Section::Strings);
    let heap_start = strings.offset as usize + (strings.count as usize + 1) * 4;
    let heap_end = strings.offset as usize
        + (strings.count as usize + 1) * 4
        + u32::from_le_bytes(
            bytes[strings.offset as usize + strings.count as usize * 4
                ..strings.offset as usize + strings.count as usize * 4 + 4]
                .try_into()
                .unwrap(),
        ) as usize;
    let heap = &bytes[heap_start..heap_end];
    assert!(
        !heap
            .windows(CANARY.len())
            .any(|window| window == CANARY.as_bytes()),
        "secret locator stayed in the public string heap"
    );
}

#[test]
fn threat_anti_oracle_equality() {
    let one = SecretBytes::from("same");
    let two = SecretBytes::from("same");
    assert_ne!(one, two);
    let mut a = InfinityModule::new();
    let secret_a = a.push(Inode::Secret(SecretBytes::from("same")));
    a.set_root(Some(secret_a));
    let mut b = InfinityModule::new();
    let secret_b = b.push(Inode::Secret(SecretBytes::from("different")));
    b.set_root(Some(secret_b));
    // Structural equality blinds payloads: the two modules are structurally
    // identical, and comparing them reveals nothing about the contents.
    assert_eq!(a, b);
}

#[test]
fn threat_stream_frame_splicing_and_hash_substitution() {
    let module = fixture();
    let frames = active_infinity::stream::encode_stream(&module, 16).unwrap();

    // Reorder two batch frames.
    let mut reordered = frames.clone();
    reordered.swap(2, 3);
    let mut decoder = StreamDecoder::new();
    let mut error = None;
    for frame in &reordered {
        if let Err(found) = decoder.push(frame) {
            error = Some(found);
            break;
        }
    }
    assert!(error.is_some(), "reordered frames must be refused");

    // Substitute the closing hash.
    let mut decoder = StreamDecoder::new();
    for frame in frames.iter().take(frames.len() - 1) {
        decoder.push(frame).expect("frame");
    }
    let mut end = frames.last().unwrap().clone();
    end.payload[0] ^= 0xff;
    let error = decoder.push(&end).unwrap_err();
    assert_eq!(error.code(), "infinity/stream-hash");

    // A frame with a corrupted payload checksum is refused.
    let mut bytes = frames[0].to_bytes();
    bytes[FRAME_PAYLOAD_GUESS] ^= 0xff;
    assert!(Frame::parse(&bytes).is_err());

    // Unknown frame kind.
    let bad = Frame::new(FrameKind::Batch, 0, vec![0xff; 8]);
    let decoded = StreamDecoder::new().push(&bad).unwrap_err();
    assert_eq!(decoded.code(), "infinity/stream-state");
}

const FRAME_PAYLOAD_GUESS: usize = 40;

#[test]
fn threat_non_canonical_images_are_detected() {
    let module = fixture();
    // Insert fields out of key order: valid encoding, non-canonical content
    // order in the *module*, but the encoder sorts, so the image stays
    // canonical. A hand-edited field table is what `validate_canonical` catches.
    let bytes = encode(&module).unwrap();
    let mut mutated = bytes.clone();
    let fields = header(&bytes).span(Section::Fields);
    if fields.count >= 2 {
        let first = fields.offset as usize;
        let second = first + 16;
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        a.copy_from_slice(&mutated[first..first + 16]);
        b.copy_from_slice(&mutated[second..second + 16]);
        mutated[first..first + 16].copy_from_slice(&b);
        mutated[second..second + 16].copy_from_slice(&a);
        rewrite_hash(&mut mutated);
        // Either the field-order check or the canonical proof rejects it.
        let error = validate_canonical(&mutated, Limits::default()).unwrap_err();
        assert!(
            error.code() == "infinity/node" || error.code() == "infinity/not-canonical",
            "unexpected {}",
            error.code()
        );
    }
    // The untouched module still proves canonical.
    assert!(validate_canonical(&bytes, Limits::default()).is_ok());
}

#[test]
fn threat_empty_and_random_inputs_never_panic() {
    for input in [
        Vec::new(),
        b"AINF".to_vec(),
        b"AINS".to_vec(),
        vec![0u8; 224],
        vec![0xffu8; 4096],
    ] {
        let outcome = std::panic::catch_unwind(|| validate(&input));
        assert!(outcome.is_ok(), "panic on crafted input");
        assert!(outcome.unwrap().is_err(), "crafted input accepted");
    }
}

// ---------------------------------------------------------------------------
// Regressions from the independent review (2026-10-27)
// ---------------------------------------------------------------------------

#[test]
fn review_stream_finish_on_a_truncated_frame_does_not_panic() {
    let module = fixture();
    let frames = active_infinity::stream::encode_stream(&module, 32).unwrap();
    let bytes = frames[0].to_bytes();
    // Feed a prefix of the first frame (header only, then 4 payload bytes) and
    // finish: this used to index past the buffer.
    for cut in [1usize, 5, 17, 20, 24, 31] {
        let mut decoder = StreamDecoder::new();
        decoder.push_bytes(&bytes[..cut]).expect("partial push");
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decoder.finish()));
        assert!(outcome.is_ok(), "finish panicked at cut {cut}");
        assert!(outcome.unwrap().is_err(), "truncated stream accepted");
    }
}

#[test]
fn review_stream_bounds_reject_unbounded_batches() {
    // A stream that declares a small image but keeps sending batches must be
    // refused before it can allocate without bound. Sequences increase, so the
    // byte bound (not the sequence check) is what fires.
    let module = fixture();
    let frames = active_infinity::stream::encode_stream(&module, 8).unwrap();
    let begin = frames[0].clone();
    let batch = frames
        .iter()
        .find(|frame| frame.kind == FrameKind::Batch)
        .expect("a batch")
        .clone();
    let mut decoder = StreamDecoder::new();
    decoder.push(&begin).expect("begin");
    let mut refused = None;
    for sequence in 1..20_000u64 {
        let frame = Frame::new(FrameKind::Batch, sequence, batch.payload.clone());
        if let Err(error) = decoder.push(&frame) {
            refused = Some(error);
            break;
        }
    }
    let error = refused.expect("an endless batch run must be refused");
    assert_eq!(error.code(), "infinity/limit", "{error:?}");
}

#[test]
fn review_depth_ceiling_applies_to_every_root() {
    // Root A is shallow; binding `deep` is a long chain that is not reachable
    // from A. Depth must still be enforced across all roots.
    let mut module = InfinityModule::new();
    let shallow = module.push(Inode::Int(1));
    module.set_root(Some(shallow));
    let mut deep = module.push(Inode::Int(0));
    for _ in 0..200 {
        deep = module.push(Inode::Ref(deep));
    }
    module.bind("deep", deep);
    let bytes = encode(&module).unwrap();
    let limits = DecodeOpts {
        limits: Limits {
            max_depth: 64,
            ..Limits::default()
        },
        verify_hash: true,
        verify_canonical: false,
    };
    let error = active_infinity::validate_with(&bytes, limits).unwrap_err();
    assert_eq!(error.code(), "infinity/depth");
}

#[test]
fn review_limits_cover_total_bytes_and_string_heap() {
    let module = fixture();
    let bytes = encode(&module).unwrap();

    let tiny_total = DecodeOpts {
        limits: Limits {
            max_total_bytes: 128,
            ..Limits::default()
        },
        verify_hash: true,
        verify_canonical: false,
    };
    assert_eq!(
        active_infinity::validate_with(&bytes, tiny_total)
            .unwrap_err()
            .code(),
        "infinity/limit"
    );

    let mut sized = InfinityModule::new();
    let text = sized.push(Inode::Str("x".repeat(4096)));
    sized.set_root(Some(text));
    let sized_bytes = encode(&sized).unwrap();
    let tiny_strings = DecodeOpts {
        limits: Limits {
            max_string_bytes: 16,
            ..Limits::default()
        },
        verify_hash: true,
        verify_canonical: false,
    };
    assert_eq!(
        active_infinity::validate_with(&sized_bytes, tiny_strings)
            .unwrap_err()
            .code(),
        "infinity/limit"
    );
}

#[test]
fn review_provenance_is_a_map_and_reserved_kinds_are_refused() {
    // Duplicate keys collapse to the last value, so the stored form can never
    // carry the duplicates validation rejects.
    let mut module = fixture();
    module.set_provenance(Some(Provenance {
        producer: Some("agent".into()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: None,
        entries: vec![
            ProvEntry {
                key: "k".into(),
                value: ProvValue::Text("first".into()),
            },
            ProvEntry {
                key: "k".into(),
                value: ProvValue::Text("last".into()),
            },
        ],
    }));
    let bytes = encode(&module).unwrap();
    let meta = validate(&bytes).expect("duplicate keys must not reach the wire");
    assert!(meta.has_provenance());
    let decoded = decode(&bytes).unwrap();
    let entries = decoded.provenance().unwrap().entries.clone();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0].value, ProvValue::Text("last".into()));

    // Kind 4 is reserved; a hand-edited block must be refused rather than
    // decoded into something that re-encodes differently.
    let span = header(&bytes).span(Section::Provenance);
    let start = span.offset as usize;
    let entry_kind_at = start + 96;
    let mut mutated = bytes.clone();
    mutated[entry_kind_at..entry_kind_at + 4].copy_from_slice(&4u32.to_le_bytes());
    rewrite_hash(&mut mutated);
    assert_eq!(
        validate(&mutated).unwrap_err().code(),
        "infinity/provenance"
    );
}

#[cfg(feature = "json")]
#[test]
fn review_json_projection_refuses_cycles_instead_of_recursing() {
    let mut module = InfinityModule::new();
    let a = module.push(Inode::Null);
    let b = module.push(Inode::Ref(a));
    *module.node_mut(a).unwrap() = Inode::Ref(b);
    module.set_root(Some(a));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        active_infinity::interop::to_redacted_json(&module)
    }));
    assert!(outcome.is_ok(), "projection recursed on a cycle");
    assert!(outcome.unwrap().is_err(), "cyclic module projected");
}

#[test]
fn review_delta_fragments_honor_the_stream_limits() {
    // Build a fragment image with more nodes than the decoder's limit allows,
    // pack it into a Delta frame, and feed it to a decoder with strict limits.
    // A chain keeps every node reachable, so canonicalization keeps them all.
    let mut fragment = InfinityModule::new();
    let mut current = fragment.push(Inode::Int(0));
    for index in 0..128 {
        current = fragment.push(Inode::Ref(current));
        let _ = index;
    }
    fragment.set_root(Some(current));
    let fragment_bytes = encode(&fragment).unwrap();

    let mut payload = Vec::new();
    let ops = 1u32;
    payload.extend_from_slice(&ops.to_le_bytes());
    payload.push(1); // PutNode
    payload.extend_from_slice(&0u32.to_le_bytes()); // target
    payload.extend_from_slice(&(fragment_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(&fragment_bytes);
    let mut decoder = StreamDecoder::new().with_limits(Limits {
        max_nodes: 32,
        ..Limits::default()
    });
    // A generation must be open and closed first; drive the state machine with
    // the fixture's own frames, then the delta.
    let module = fixture();
    let frames = active_infinity::stream::encode_stream(&module, 1024).unwrap();
    let delta = Frame::new(FrameKind::Delta, frames.len() as u64, payload);
    for frame in &frames {
        if let Err(error) = decoder.push(frame) {
            panic!("generation frame failed: {error:?}");
        }
    }
    let error = decoder.push(&delta).unwrap_err();
    assert_eq!(error.code(), "infinity/limit", "{error:?}");
}

#[cfg(feature = "json")]
#[test]
fn review_projection_redacts_secret_copies_in_keys_and_metadata() {
    const CANARY: &str = "leak-canary-42";
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from(CANARY)));
    let one = module.push(Inode::Int(1));
    let env = module.push(Inode::Env {
        name: CANARY.into(),
        default: None,
    });
    let media = module.push(Inode::Str("text/plain".into()));
    let ca = module.push(Inode::ContentAddressed {
        media_type: media,
        data: one,
    });
    let payload = b"x".to_vec();
    let blob = module.push(Inode::Blob {
        hash: *blake3::hash(&payload).as_bytes(),
        size: payload.len() as u64,
        tainted: false,
        media_type: CANARY.into(),
        payload: Some(payload),
    });
    let quantity = {
        let number = module.push(Inode::Int(5));
        module.push(Inode::Quantity {
            value: number,
            unit: UnitTag::Named(CANARY.into()),
        })
    };
    let root = module.push(Inode::Table {
        // The key is itself a copy of the secret.
        fields: vec![
            (CANARY.into(), secret),
            ("env".into(), env),
            ("ca".into(), ca),
            ("blob".into(), blob),
            ("quantity".into(), quantity),
        ],
    });
    module.set_root(Some(root));
    module.set_provenance(Some(Provenance {
        producer: Some(CANARY.into()),
        timestamp_ms: 1,
        model: Some(CANARY.into()),
        tool: None,
        parent: None,
        entries: vec![ProvEntry {
            key: CANARY.into(),
            value: ProvValue::Text(CANARY.into()),
        }],
    }));

    let json = active_infinity::interop::to_redacted_json(&module).unwrap();
    assert!(!json.contains(CANARY), "value projection leaked: {json}");
    let pretty = active_infinity::interop::to_redacted_json_pretty(&module).unwrap();
    assert!(!pretty.contains(CANARY), "pretty projection leaked");

    let prov = active_infinity::interop::provenance_json_for(&module).expect("provenance");
    let rendered = prov.to_string();
    assert!(!rendered.contains(CANARY), "provenance projection leaked");
}

#[test]
fn review_stream_begin_uses_the_caller_limits() {
    let module = fixture();
    let frames = active_infinity::stream::encode_stream(&module, 64).unwrap();
    let mut decoder = StreamDecoder::new().with_limits(Limits {
        max_total_bytes: 64,
        ..Limits::default()
    });
    let error = decoder.push(&frames[0]).unwrap_err();
    assert_eq!(error.code(), "infinity/limit");
}

#[test]
fn review_text_projections_redact_secret_copies() {
    const CANARY: &str = "text-canary-77";
    let mut module = fixture();
    let secret = module.push(Inode::Secret(SecretBytes::from(CANARY)));
    let root = module.push(Inode::Table {
        fields: vec![("s".into(), secret)],
    });
    module.set_root(Some(root));
    module.annotate(root, AnnotationKind::Intent(format!("value is {CANARY}")));
    module.set_provenance(Some(Provenance {
        producer: None,
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: None,
        entries: vec![ProvEntry {
            key: CANARY.into(),
            value: ProvValue::Text(format!("copy: {CANARY}")),
        }],
    }));

    let lines = provenance_lines(&module).join("\n");
    assert!(!lines.contains(CANARY), "provenance_lines leaked: {lines}");
    let intents = active_infinity::interop::intents(&module, root);
    assert!(
        intents.iter().all(|text| !text.contains(CANARY)),
        "intents leaked: {intents:?}"
    );
}
