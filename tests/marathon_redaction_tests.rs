//! An image redacted for export carries no copy of a secret.
//!
//! The projection rule (`SECRET_MARKER` for a secret node and for any string
//! containing a secret literal) is applied to the image itself by
//! `interop::redact_module` / `interop::redact_image`. A copy written as plain
//! data, as a table field name, as an `Env` name, as an interpolated literal or
//! as a binding name is still a copy, and a redacting consumer must not read it.

use active_infinity::{
    decode, encode, interop, validate_canonical, InfinityModule, Inode, InterpPart,
};

const SECRET: &str = "hunter2-canary";

/// A module whose value plane copies the secret in every text position.
fn copied_everywhere() -> InfinityModule {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SECRET.into()));
    let copy = module.push(Inode::Str(SECRET.to_string()));
    let partial = module.push(Inode::Str(format!("prefix-{SECRET}-suffix")));
    let ident = module.push(Inode::Ident(SECRET.to_string()));
    let env = module.push(Inode::Env {
        name: SECRET.to_string(),
        default: Some(secret),
    });
    let interpolated = module.push(Inode::Interpolate {
        parts: vec![InterpPart::Literal(SECRET.to_string())],
    });
    let app = module.push(Inode::Table {
        fields: vec![
            (SECRET.to_string(), copy),
            ("partial".to_string(), partial),
            ("ident".to_string(), ident),
            ("env".to_string(), env),
            ("interpolated".to_string(), interpolated),
        ],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app), ("secret".to_string(), secret)],
    });
    module.set_root(Some(root));
    module.bind(SECRET, app);
    module
}

/// Every text a decoded image still holds.
fn texts(image: &[u8]) -> Vec<String> {
    let module = decode(image).expect("decode");
    let mut out = Vec::new();
    for index in 0..module.node_count() {
        match module.get(active_infinity::NodeId(index as u32)) {
            Some(Inode::Str(text)) | Some(Inode::Ident(text)) => out.push(text.clone()),
            Some(Inode::Env { name, .. }) => out.push(name.clone()),
            Some(Inode::Table { fields }) | Some(Inode::SchemaTable { fields, .. }) => {
                out.extend(fields.iter().map(|(name, _)| name.clone()));
            }
            Some(Inode::Interpolate { parts }) => {
                out.extend(parts.iter().filter_map(|part| match part {
                    InterpPart::Literal(text) => Some(text.clone()),
                    InterpPart::Expr(_) => None,
                }));
            }
            _ => {}
        }
    }
    out.extend(module.bindings().iter().map(|(name, _)| name.clone()));
    out
}

#[test]
fn a_redacted_image_holds_no_text_that_contains_the_secret() {
    let image = encode(&copied_everywhere()).expect("encode");
    let redacted = interop::redact_image(&image).expect("redact");
    let leaked: Vec<String> = texts(&redacted)
        .into_iter()
        .filter(|text| text.contains(SECRET))
        .collect();
    assert!(
        leaked.is_empty(),
        "redacted image still carries: {leaked:?}"
    );
    assert!(
        texts(&redacted)
            .iter()
            .any(|text| text == interop::SECRET_MARKER),
        "the marker replaces the copies"
    );
}

#[test]
fn a_redacted_image_is_canonical_and_validates() {
    let image = encode(&copied_everywhere()).expect("encode");
    let redacted = interop::redact_image(&image).expect("redact");
    validate_canonical(&redacted, Default::default()).expect("canonical");
    assert_eq!(
        encode(&decode(&redacted).expect("decode")).expect("re-encode"),
        redacted
    );
}

#[test]
fn a_module_redacted_in_memory_matches_the_byte_form() {
    let module = copied_everywhere();
    let in_memory = encode(&interop::redact_module(&module).expect("redact")).expect("encode");
    let image = encode(&module).expect("encode");
    assert_eq!(interop::redact_image(&image).expect("redact"), in_memory);
}

#[test]
fn an_image_without_a_secret_is_returned_unchanged() {
    let mut module = InfinityModule::new();
    let text = module.push(Inode::Str(SECRET.to_string()));
    let root = module.push(Inode::Table {
        fields: vec![("value".to_string(), text)],
    });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode");
    assert_eq!(interop::redact_image(&image).expect("redact"), image);
}

#[test]
fn a_field_name_that_contains_a_secret_is_replaced_not_collapsed() {
    // A name is a label: the projection replaces the occurrence, so two names
    // that differ outside the secret stay distinct. The whole-value collapse
    // belongs to data text (pass 2, #8).
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret("inner".into()));
    let left = module.push(Inode::Str("1".to_string()));
    let right = module.push(Inode::Str("2".to_string()));
    let table = module.push(Inode::Table {
        fields: vec![
            ("left-inner".to_string(), left),
            ("right-inner".to_string(), right),
        ],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), table), ("secret".to_string(), secret)],
    });
    module.set_root(Some(root));
    let redacted = interop::redact_module(&module).expect("a label, not a collision");
    let names: Vec<String> = texts(&encode(&redacted).expect("encode"));
    assert!(
        names.iter().any(|name| name == "left-***SECRET***"),
        "{names:?}"
    );
    assert!(
        names.iter().any(|name| name == "right-***SECRET***"),
        "{names:?}"
    );
    assert!(
        names.iter().all(|name| !name.contains("inner")),
        "{names:?}"
    );
}

#[test]
fn a_secret_copied_into_a_blob_payload_is_refused_not_redacted() {
    // A blob payload is opaque bytes; there is no text to substitute, so the
    // encoder refuses the image instead of publishing the copy.
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SECRET.into()));
    let blob = module.push(Inode::Blob {
        hash: [0u8; 32],
        size: SECRET.len() as u64,
        tainted: false,
        media_type: "text/plain".to_string(),
        payload: Some(SECRET.as_bytes().to_vec()),
    });
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob), ("secret".to_string(), secret)],
    });
    module.set_root(Some(root));
    assert!(interop::redact_module(&module).is_err());
}

#[test]
fn a_redactor_from_the_source_redacts_a_derived_cone() {
    // A cone is built from a subtree: the secret node is outside it, and the
    // copy inside it must still be recognised from the source's literal set.
    let module = copied_everywhere();
    let mut cone = InfinityModule::new();
    let copy = cone.push(Inode::Str(SECRET.to_string()));
    let root = cone.push(Inode::Table {
        fields: vec![("copy".to_string(), copy)],
    });
    cone.set_root(Some(root));

    let redactor = interop::Redactor::for_module(&module);
    assert!(!redactor.is_empty());
    redactor.redact(&mut cone).expect("redact");
    assert!(
        texts(&encode(&cone).expect("encode"))
            .iter()
            .all(|text| !text.contains(SECRET)),
        "the cone still carries the copy"
    );

    // No accessor returns the literals; the handle prints a count.
    let debug = format!("{redactor:?}");
    assert!(!debug.contains(SECRET), "{debug}");
}

#[test]
fn a_copy_in_a_constraint_enum_or_patch_path_is_redacted() {
    use active_infinity::{Constraint, PatchOp, TypeSpec};

    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SECRET.into()));
    let target = module.push(Inode::Int(1));
    let value = module.push(Inode::Int(2));
    let constrained = module.push(Inode::Constrained {
        target,
        constraint: Constraint::Enum(vec![SECRET.to_string(), "other".to_string()]),
    });
    let patterned = module.push(Inode::Constrained {
        target,
        constraint: Constraint::Pattern(format!("^{SECRET}$")),
    });
    let custom = module.push(Inode::Constrained {
        target,
        constraint: Constraint::Custom(SECRET.to_string()),
    });
    let field = module.push(Inode::SchemaField(active_infinity::SchemaFieldSpec {
        typ: TypeSpec::Enum(vec![SECRET.to_string()]),
        min: None,
        max: None,
        min_len: None,
        max_len: None,
        pattern: None,
        default: None,
        deprecated: Some(SECRET.to_string()),
    }));
    let patch = module.push(Inode::Patch(PatchOp::Rename {
        from: SECRET.to_string(),
        to: "public".to_string(),
    }));
    let root = module.push(Inode::Table {
        fields: vec![
            ("constrained".to_string(), constrained),
            ("field".to_string(), field),
            ("patch".to_string(), patch),
            ("patterned".to_string(), patterned),
            ("custom".to_string(), custom),
            ("value".to_string(), value),
            ("secret".to_string(), secret),
        ],
    });
    module.set_root(Some(root));

    let redacted = interop::redact_image(&encode(&module).expect("encode")).expect("redact");
    // Every text surface the codec interns, not only the value plane.
    let module = decode(&redacted).expect("decode");
    for index in 0..module.node_count() {
        let node = module.get(active_infinity::NodeId(index as u32));
        let texts: Vec<String> = match node {
            Some(Inode::Constrained { constraint, .. }) => match constraint {
                Constraint::Enum(members) => members.clone(),
                Constraint::Pattern(text) | Constraint::Custom(text) => vec![text.clone()],
                _ => Vec::new(),
            },
            Some(Inode::SchemaField(spec)) => {
                let mut out = spec.deprecated.iter().cloned().collect::<Vec<_>>();
                if let TypeSpec::Enum(members) = &spec.typ {
                    out.extend(members.iter().cloned());
                }
                out
            }
            Some(Inode::Patch(PatchOp::Set { path, .. }))
            | Some(Inode::Patch(PatchOp::Remove { path })) => {
                vec![path.clone()]
            }
            Some(Inode::Patch(PatchOp::Rename { from, to })) => vec![from.clone(), to.clone()],
            _ => Vec::new(),
        };
        for text in texts {
            assert!(
                !text.contains(SECRET),
                "a text surface still carries the copy: {text}"
            );
        }
    }
}

/// A custom unit name is text (pass 2, #1).
#[test]
fn a_unit_name_that_copies_a_secret_is_redacted() {
    use active_infinity::UnitTag;

    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SECRET.into()));
    let amount = module.push(Inode::Float(1.0));
    let quantity = module.push(Inode::Quantity {
        value: amount,
        unit: UnitTag::Named(SECRET.to_string()),
    });
    let prefixed = module.push(Inode::Quantity {
        value: amount,
        unit: UnitTag::Named(format!("{SECRET}-per-second")),
    });
    let root = module.push(Inode::Table {
        fields: vec![
            ("quantity".to_string(), quantity),
            ("prefixed".to_string(), prefixed),
            ("secret".to_string(), secret),
        ],
    });
    module.set_root(Some(root));
    let image = interop::redact_image(&encode(&module).expect("encode")).expect("redact");
    let decoded = decode(&image).expect("decode");
    for index in 0..decoded.node_count() {
        if let Some(Inode::Quantity {
            unit: UnitTag::Named(name),
            ..
        }) = decoded.get(active_infinity::NodeId(index as u32))
        {
            assert!(!name.contains(SECRET), "a unit carries the secret: {name}");
        }
    }
}

/// A caller-built deep literal is refused, not aborted (pass 2, #3).
#[cfg(feature = "active-core")]
#[test]
fn a_deep_literal_is_refused() {
    use active_core::ir::{Module as CoreModule, Node as CoreNode, Value as CoreValue};

    let mut value = CoreValue::Int(1);
    for _ in 0..400 {
        value = CoreValue::Array(vec![value]);
    }
    let mut core = CoreModule::new("deep");
    let root = core.add_node(CoreNode::Literal(value));
    core.root = Some(root);
    let error = interop::from_active_core(&core).expect_err("too deep for the bridge");
    assert_eq!(error.code(), "infinity/limit", "{error}");
}

/// A cone whose provenance copies a 32-byte secret is refused or cleansed
/// (pass 2, #4).
#[test]
fn a_cone_hash_that_copies_a_secret_is_not_kept() {
    let secret = [0x5au8; 32];
    let mut module = InfinityModule::new();
    let node = module.push(Inode::Secret(active_infinity::SecretBytes::new(secret)));
    let root = module.push(Inode::Table {
        fields: vec![("s".to_string(), node)],
    });
    module.set_root(Some(root));
    module.set_provenance(Some(active_infinity::Provenance {
        producer: Some("test".to_string()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: Some(secret),
        entries: vec![active_infinity::ProvEntry {
            key: "input".to_string(),
            value: active_infinity::ProvValue::Hash(secret),
        }],
    }));
    let redactor = interop::Redactor::for_module(&module);
    let mut cone = InfinityModule::new();
    let copy = cone.push(Inode::Str("public".to_string()));
    let root = cone.push(Inode::Table {
        fields: vec![("c".to_string(), copy)],
    });
    cone.set_root(Some(root));
    cone.set_provenance(Some(active_infinity::Provenance {
        producer: Some("test".to_string()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: Some(secret),
        entries: vec![active_infinity::ProvEntry {
            key: "input".to_string(),
            value: active_infinity::ProvValue::Hash(secret),
        }],
    }));
    redactor.redact(&mut cone).expect("redact");
    let provenance = cone
        .provenance()
        .expect("provenance survives without the hash");
    assert_eq!(provenance.parent, None, "a parent that copies the secret");
    assert!(
        provenance.entries.is_empty(),
        "a hash entry that copies the secret: {:?}",
        provenance.entries
    );
}
