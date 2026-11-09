//! I-12 round 11/12 regressions: the deprecation-note redaction order, the
//! constraint-expression fragment scan, and the encoder/validator agreement
//! checks the round-11 table claimed without a test.

use active_infinity::{
    decode, encode, validate_canonical, AnnotationKind, InfinityModule, Inode, InterpPart, Limits,
    ProvValue, Provenance, SchemaFieldSpec, SecretBytes, TypeSpec,
};

fn occurrences(hay: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || hay.len() < needle.len() {
        return 0;
    }
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

fn module_with_deprecated_note(note: &str, decoy: Option<&str>) -> InfinityModule {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::new(b"hunter2".to_vec())));
    let spec = module.push(Inode::SchemaField(SchemaFieldSpec {
        typ: TypeSpec::String,
        min: None,
        max: None,
        min_len: None,
        max_len: None,
        pattern: None,
        default: None,
        deprecated: Some(note.to_string()),
    }));
    let mut fields = vec![("pw".into(), secret), ("schema".into(), spec)];
    if let Some(decoy) = decoy {
        let decoy = module.push(Inode::Str(decoy.to_string()));
        fields.push(("decoy".into(), decoy));
    }
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));
    module
}

/// A deprecation note is stored prose: the secret in it is replaced, and the
/// image keeps exactly one copy of the secret bytes (the secret heap).
///
/// Before the fix the note was redacted *after* the string heap was collected,
/// so this failed with `infinity/encode` ("string missing from heap").
#[test]
fn a_deprecated_note_is_redacted_before_the_string_heap_is_collected() {
    let module = module_with_deprecated_note("do not use hunter2 here", None);
    let image = encode(&module).expect("encode");
    validate_canonical(&image, Limits::default()).expect("canonical");
    assert_eq!(
        occurrences(&image, b"hunter2"),
        1,
        "the secret must live in the secret heap only"
    );
    let decoded = decode(&image).expect("decode");
    let note = decoded
        .nodes()
        .iter()
        .find_map(|node| match node {
            Inode::SchemaField(spec) => spec.deprecated.clone(),
            _ => None,
        })
        .expect("deprecated note");
    assert!(!note.contains("hunter2"), "{note}");
    assert_eq!(encode(&decoded).expect("re-encode"), image);
}

/// The same note, with the redacted form also present in the data. Before the
/// fix this produced an image that was *not* a fixed point (`validate_canonical`
/// refused it) and that carried the unredacted note in the string heap.
#[test]
fn a_deprecated_note_never_leaves_the_unredacted_copy_in_the_heap() {
    let module = module_with_deprecated_note(
        "do not use hunter2 here",
        Some("do not use ***SECRET*** here"),
    );
    let image = encode(&module).expect("encode");
    validate_canonical(&image, Limits::default()).expect("canonical");
    assert_eq!(
        occurrences(&image, b"hunter2"),
        1,
        "the unredacted note was interned before redaction"
    );
    let decoded = decode(&image).expect("decode");
    assert_eq!(encode(&decoded).expect("re-encode"), image);
}

/// `secret("hun" + "ter")` promotes the literal parts to secret nodes; a
/// constraint expression subtree is stored text, so containing a fragment is
/// refused. Before the fix the scan indexed the canonical node arena with the
/// original expression id and read an unrelated node, so this was accepted.
#[test]
fn a_fragment_in_a_constraint_expression_subtree_is_refused() {
    let mut module = InfinityModule::new();
    let interp = module.push(Inode::Interpolate {
        parts: vec![
            InterpPart::Literal("hun".into()),
            InterpPart::Literal("ter".into()),
        ],
    });
    let secret = module.push(Inode::SecretRef { locator: interp });
    let root = module.push(Inode::Table {
        fields: vec![("pw".into(), secret)],
    });
    module.set_root(Some(root));
    let expr = module.push(Inode::Str("hun".into()));
    module.annotate(
        root,
        AnnotationKind::Constraint {
            source: "ok".into(),
            expr,
        },
    );

    let error = encode(&module).expect_err("a fragment in an expression subtree is stored text");
    assert_eq!(error.code(), "infinity/encode", "{error}");
    assert!(error.to_string().contains("fragment"), "{error}");
}

/// A schema field can be an annotation subject without being reachable from the
/// root, and `canonical_order` keys such a subject by a render of its subtree —
/// which includes the deprecation note. Redacting the note only after the order
/// was derived let two subjects swap places, so the emitted image was not a
/// fixed point even though it looked valid.
#[test]
fn a_redacted_note_cannot_reorder_two_annotation_subjects() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::new(b"hunter2".to_vec())));
    let note = |module: &mut InfinityModule, text: &str| {
        module.push(Inode::SchemaField(SchemaFieldSpec {
            typ: TypeSpec::String,
            min: None,
            max: None,
            min_len: None,
            max_len: None,
            pattern: None,
            default: None,
            deprecated: Some(text.to_string()),
        }))
    };
    // Keys before redaction: "b aaa" < "b hunter2". After redaction the second
    // key is "b ***SECRET***", which sorts first.
    let first = note(&mut module, "b hunter2");
    let second = note(&mut module, "b aaa");
    let root = module.push(Inode::Int(1));
    let table = module.push(Inode::Table {
        fields: vec![("pw".into(), secret)],
    });
    let root = module.push(Inode::Array {
        elements: vec![root, table],
    });
    module.set_root(Some(root));
    module.annotate(first, AnnotationKind::Intent("one".into()));
    module.annotate(second, AnnotationKind::Intent("two".into()));

    let image = encode(&module).expect("encode");
    validate_canonical(&image, Limits::default()).expect("canonical");
    let decoded = decode(&image).expect("decode");
    assert_eq!(encode(&decoded).expect("re-encode"), image);
}

#[test]
fn an_empty_enum_type_and_an_empty_producer_are_refused_at_encode() {
    let mut module = InfinityModule::new();
    let field = module.push(Inode::SchemaField(SchemaFieldSpec {
        typ: TypeSpec::Enum(Vec::new()),
        min: None,
        max: None,
        min_len: None,
        max_len: None,
        pattern: None,
        default: None,
        deprecated: None,
    }));
    let table = module.push(Inode::SchemaTable {
        fields: vec![("f".into(), field)],
        closed: true,
    });
    module.set_root(Some(table));
    let error = encode(&module).expect_err("an empty enum type has no canonical form");
    assert_eq!(error.code(), "infinity/encode", "{error}");

    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(1));
    module.set_root(Some(root));
    module.set_provenance(Some(Provenance {
        producer: Some(String::new()),
        ..Provenance::default()
    }));
    let error = encode(&module).expect_err("an empty producer has no canonical form");
    assert_eq!(error.code(), "infinity/encode", "{error}");
}

/// A materialised empty payload and a detached blob of the same hash are one
/// record; keying them apart emitted duplicate records the validator refuses.
#[test]
fn an_empty_payload_and_a_detached_blob_share_one_record() {
    let hash = *blake3::hash(b"").as_bytes();
    let mut module = InfinityModule::new();
    let materialised = module.push(Inode::Blob {
        hash,
        size: 0,
        tainted: false,
        media_type: "text/plain".into(),
        payload: Some(Vec::new()),
    });
    let detached = module.push(Inode::Blob {
        hash,
        size: 0,
        tainted: false,
        media_type: "text/plain".into(),
        payload: None,
    });
    let root = module.push(Inode::Array {
        elements: vec![materialised, detached],
    });
    module.set_root(Some(root));

    let image = encode(&module).expect("encode");
    validate_canonical(&image, Limits::default()).expect("canonical");
    let decoded = decode(&image).expect("decode");
    assert_eq!(
        decoded
            .nodes()
            .iter()
            .filter(|node| matches!(node, Inode::Blob { .. }))
            .count(),
        2,
        "both nodes survive"
    );
    assert_eq!(encode(&decoded).expect("re-encode"), image);
}

/// An empty annotation is still a redaction pass over the whole secret table.
/// Before the cost floor, these were charged zero, so an image of a few MiB
/// bought 10^12 `contains` calls (10k x 10k measured 8 s in release).
#[test]
fn empty_annotations_against_a_large_secret_table_are_charged() {
    let mut module = InfinityModule::new();
    for index in 0..3_000 {
        let id = module.push(Inode::Secret(SecretBytes::new(
            format!("k{index}").into_bytes(),
        )));
        // Reachable (INF-04): the secrets are the table the redaction scan
        // charges against, so they must be roots — an unreachable secret
        // would now be refused before the scan runs.
        module.bind(format!("secret-{index}"), id);
    }
    let mut nodes = Vec::new();
    for index in 0..3_000 {
        let id = module.push(Inode::Int(index));
        module.annotate(id, AnnotationKind::Intent(String::new()));
        nodes.push(id);
    }
    let root = module.push(Inode::Array { elements: nodes });
    module.set_root(Some(root));

    let error = encode(&module).expect_err("an uncharged scan is a CPU denial of service");
    assert_eq!(error.code(), "infinity/limit", "{error}");
    assert!(
        error.to_string().contains("redaction"),
        "the diagnostic must name the budget: {error}"
    );
}

/// Provenance text is stored metadata: a secret in a producer, model, tool or
/// text entry is redacted, and a hash entry that copies one is refused.
#[test]
fn provenance_text_is_redacted_and_a_secret_hash_is_refused() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::new(b"hunter2".to_vec())));
    module.set_root(Some(secret));
    let mut prov = Provenance {
        producer: Some("tool hunter2 v1".into()),
        ..Provenance::default()
    };
    prov.entries.push(active_infinity::ProvEntry {
        key: "k".into(),
        value: ProvValue::Text("x hunter2 y".into()),
    });
    module.set_provenance(Some(prov));
    let image = encode(&module).expect("encode");
    assert_eq!(occurrences(&image, b"hunter2"), 1, "secret heap only");

    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::new([7u8; 32].to_vec())));
    module.set_root(Some(secret));
    let mut prov = Provenance::default();
    prov.entries.push(active_infinity::ProvEntry {
        key: "k".into(),
        value: ProvValue::Hash([7u8; 32]),
    });
    module.set_provenance(Some(prov));
    let error = encode(&module).expect_err("a hash entry that copies a secret publishes it");
    assert_eq!(error.code(), "infinity/encode", "{error}");
}
