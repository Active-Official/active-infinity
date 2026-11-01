//! I-12 round 10: expression locators, framed-key injectivity, marker-boundary
//! fragments, blob scan cost, label fragments and Debug hash redaction.

use active_infinity::{
    encode, validate_canonical, AnnotationKind, InfinityModule, Inode, InterpPart, Limits,
    ProvValue, Provenance, SecretBytes,
};

/// A literal inside a locator expression is secret material for stored metadata
/// too: the image must not publish it, and re-encoding must be a no-op.
#[test]
fn an_expression_locator_literal_is_redacted_from_metadata() {
    let mut module = InfinityModule::new();
    let left = module.push(Inode::Str("hun".into()));
    let right = module.push(Inode::Str("ter2".into()));
    let sum = module.push(Inode::Binary {
        op: active_infinity::BinOp::Add,
        lhs: left,
        rhs: right,
    });
    let secret = module.push(Inode::SecretRef { locator: sum });
    let root = module.push(Inode::Table {
        fields: vec![("password".into(), secret)],
    });
    module.set_root(Some(root));
    module.annotate(root, AnnotationKind::Intent("the hunter2 value".into()));

    let image = encode(&module).expect("encode");
    validate_canonical(&image, Limits::default()).expect("canonical");
    let decoded = active_infinity::decode(&image).expect("decode");
    // The secret bytes live in the secret heap by design; the *public* heap and
    // the stored metadata must not carry them.
    for node in decoded.nodes() {
        if let Inode::Str(text) | Inode::Ident(text) = node {
            assert_ne!(text, "hunter2");
        }
    }
    for annotation in decoded.annotations() {
        if let AnnotationKind::Intent(text) = &annotation.kind {
            assert!(!text.contains("hunter2"), "{text}");
        }
    }
    assert_eq!(encode(&decoded).expect("re-encode"), image);
}

/// A named unit contributes its name to the framed key; two units used to
/// collide on the shared discriminant.
#[test]
fn a_named_unit_breaks_a_key_tie_by_name() {
    let build = |reversed: bool| {
        let mut module = InfinityModule::new();
        let root = module.push(Inode::Int(0));
        module.set_root(Some(root));
        let value = module.push(Inode::Int(1));
        let (first, second) = if reversed {
            let second = module.push(Inode::Quantity {
                value,
                unit: active_infinity::UnitTag::Named("beta".into()),
            });
            let first = module.push(Inode::Quantity {
                value,
                unit: active_infinity::UnitTag::Named("alpha".into()),
            });
            (first, second)
        } else {
            let first = module.push(Inode::Quantity {
                value,
                unit: active_infinity::UnitTag::Named("alpha".into()),
            });
            let second = module.push(Inode::Quantity {
                value,
                unit: active_infinity::UnitTag::Named("beta".into()),
            });
            (first, second)
        };
        for subject in [first, second] {
            module.annotate(subject, AnnotationKind::Intent("note".into()));
        }
        module
    };
    assert_eq!(
        encode(&build(false)).expect("a"),
        encode(&build(true)).expect("b"),
        "a named unit leaked the arena order"
    );
}

/// `min` and `max` pointing at the same node used to render identically.
#[test]
fn a_schema_field_slot_tag_breaks_a_key_tie() {
    let build = |reversed: bool| {
        let mut module = InfinityModule::new();
        let root = module.push(Inode::Int(0));
        module.set_root(Some(root));
        let bound = module.push(Inode::Int(1));
        let (first, second) = if reversed {
            let second = module.push(Inode::SchemaField(active_infinity::SchemaFieldSpec {
                max: Some(bound),
                ..active_infinity::SchemaFieldSpec::bare(active_infinity::TypeSpec::Int)
            }));
            let first = module.push(Inode::SchemaField(active_infinity::SchemaFieldSpec {
                min: Some(bound),
                ..active_infinity::SchemaFieldSpec::bare(active_infinity::TypeSpec::Int)
            }));
            (first, second)
        } else {
            let first = module.push(Inode::SchemaField(active_infinity::SchemaFieldSpec {
                min: Some(bound),
                ..active_infinity::SchemaFieldSpec::bare(active_infinity::TypeSpec::Int)
            }));
            let second = module.push(Inode::SchemaField(active_infinity::SchemaFieldSpec {
                max: Some(bound),
                ..active_infinity::SchemaFieldSpec::bare(active_infinity::TypeSpec::Int)
            }));
            (first, second)
        };
        for subject in [first, second] {
            module.annotate(subject, AnnotationKind::Intent("note".into()));
        }
        module
    };
    assert_eq!(
        encode(&build(false)).expect("a"),
        encode(&build(true)).expect("b"),
        "an untagged schema slot leaked the arena order"
    );
}

/// Redaction can insert the marker, and a fragment inside the marker would slip
/// past a pre-redaction check. The stored text is what must be inspected.
#[test]
fn a_fragment_created_by_redaction_is_refused() {
    let mut module = InfinityModule::new();
    // A whole secret whose redaction inserts `***SECRET***`.
    let whole = module.push(Inode::Secret(SecretBytes::from("abc")));
    // A fragment that is a substring of the marker.
    let name = module.push(Inode::Str("svc".into()));
    let interp = module.push(Inode::Interpolate {
        parts: vec![InterpPart::Literal("S".into()), InterpPart::Expr(name)],
    });
    let fragment = module.push(Inode::SecretRef { locator: interp });
    let root = module.push(Inode::Table {
        fields: vec![("whole".into(), whole), ("fragment".into(), fragment)],
    });
    module.set_root(Some(root));
    module.annotate(root, AnnotationKind::Intent("abc note".into()));
    let error = encode(&module).expect_err("the marker reintroduces the fragment");
    assert_eq!(error.code(), "infinity/encode", "{error}");
}

/// A fragment in a structural label would sit in the public string heap.
#[test]
fn a_fragment_in_a_label_is_refused() {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("svc".into()));
    let interp = module.push(Inode::Interpolate {
        parts: vec![
            InterpPart::Literal("hunter-".into()),
            InterpPart::Expr(name),
        ],
    });
    let secret = module.push(Inode::SecretRef { locator: interp });
    let root = module.push(Inode::Table {
        fields: vec![("hunter-cfg".into(), secret), ("password".into(), secret)],
    });
    module.set_root(Some(root));
    let error = encode(&module).expect_err("a fragment in a field name is refused");
    assert_eq!(error.code(), "infinity/encode", "{error}");
    assert!(error.to_string().contains("stored text"), "{error}");
}

/// The blob scan charges a pass over the payload, not the worst-case product:
/// an ordinary large blob with a short secret must encode.
#[test]
fn a_large_blob_with_a_short_secret_encodes() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from("x".repeat(100))));
    let payload = vec![0u8; 1 << 20];
    let hash = *blake3::hash(&payload).as_bytes();
    let blob = module.push(Inode::Blob {
        hash,
        size: payload.len() as u64,
        tainted: false,
        media_type: "application/octet-stream".into(),
        payload: Some(payload),
    });
    let root = module.push(Inode::Table {
        fields: vec![("secret".into(), secret), ("blob".into(), blob)],
    });
    module.set_root(Some(root));
    encode(&module).expect("a clean 1 MiB blob encodes");
}

/// `Debug` for the public provenance and value types must not print hash bytes.
#[test]
fn debug_of_public_types_never_prints_a_hash() {
    let secret = [0xABu8; 32];
    let value = ProvValue::Hash(secret);
    let text = format!("{value:?}");
    let hex: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
    assert!(!text.contains(&hex), "{text}");
    assert!(!text.contains("171"), "{text}");

    let provenance = Provenance {
        parent: Some(secret),
        entries: vec![active_infinity::ProvEntry {
            key: "hash".into(),
            value: ProvValue::Hash(secret),
        }],
        ..Provenance::default()
    };
    let text = format!("{provenance:?}");
    assert!(!text.contains(&hex), "{text}");
    assert!(!text.contains("171"), "{text}");
}
