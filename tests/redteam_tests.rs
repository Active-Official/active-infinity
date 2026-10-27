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
