//! Marathon I-12: the interop bridge and the projections must not publish a
//! secret through a surface that cannot be redacted.
//!
//! A text surface replaces an occurrence with the marker. A hash field, an
//! opaque extension payload, and the `active-core` bridge (which models a
//! secret as a plain string) have no such substitution, so the codec refuses
//! the module or the projection instead.

use active_infinity::{
    encode, Constraint, InfinityModule, Inode, InterpPart, ProvEntry, ProvValue, Provenance,
    SecretBytes,
};

/// Exactly 32 bytes, so its bytes can be confused with a content hash.
const SECRET: &str = "0123456789abcdef0123456789abcdef";

fn plain(secret: Option<&str>) -> InfinityModule {
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Str("root".into()));
    let mut fields = vec![("value".into(), value)];
    if let Some(secret) = secret {
        let node = module.push(Inode::Secret(SecretBytes::from(secret)));
        fields.push(("secret".into(), node));
    }
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));
    module
}

fn secret_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(SECRET.as_bytes());
    bytes
}

#[cfg(feature = "active-core")]
#[test]
fn the_bridge_refuses_a_secret_bearing_module() {
    let module = plain(Some("bridge-canary"));
    let error = active_infinity::interop::to_active_core(&module)
        .expect_err("the bridge must not export a structural secret");
    assert_eq!(error.code(), "infinity/encode", "{error}");
    assert!(
        active_infinity::interop::to_active_core(&plain(None)).is_ok(),
        "a module without secrets still bridges"
    );
}

#[test]
fn a_provenance_parent_equal_to_a_secret_is_refused_at_encode() {
    let mut module = plain(Some(SECRET));
    module.set_provenance(Some(Provenance {
        parent: Some(secret_bytes()),
        ..Provenance::default()
    }));
    let error = encode(&module).expect_err("a secret copy in parent is refused");
    assert_eq!(error.code(), "infinity/encode", "{error}");
    assert!(error.to_string().contains("parent"), "{error}");
}

#[test]
fn a_provenance_hash_entry_equal_to_a_secret_is_refused_at_encode() {
    let mut module = plain(Some(SECRET));
    module.set_provenance(Some(Provenance {
        entries: vec![ProvEntry {
            key: "hash".into(),
            value: ProvValue::Hash(secret_bytes()),
        }],
        ..Provenance::default()
    }));
    let error = encode(&module).expect_err("a secret copy in a hash entry is refused");
    assert_eq!(error.code(), "infinity/encode", "{error}");
    assert!(error.to_string().contains("hash"), "{error}");
}

#[test]
fn an_extension_payload_copying_a_secret_is_refused_at_encode() {
    let mut module = plain(Some("ext-canary"));
    module.set_extensions(vec![(7, b"prefix ext-canary suffix".to_vec())]);
    let error = encode(&module).expect_err("a secret copy in an extension is refused");
    assert_eq!(error.code(), "infinity/encode", "{error}");
    assert!(error.to_string().contains("extension"), "{error}");
}

#[cfg(feature = "json")]
#[test]
fn a_provenance_hash_equal_to_a_secret_is_redacted_in_json() {
    use active_infinity::interop::{provenance_json_for, SECRET_MARKER};

    // A hand-built module that was never encoded: the projection must still
    // refuse to publish the copy.
    let mut module = plain(Some(SECRET));
    module.set_provenance(Some(Provenance {
        parent: Some(secret_bytes()),
        entries: vec![ProvEntry {
            key: "hash".into(),
            value: ProvValue::Hash(secret_bytes()),
        }],
        ..Provenance::default()
    }));
    let json = provenance_json_for(&module).expect("provenance");
    assert_eq!(json["parent"], serde_json::Value::from(SECRET_MARKER));
    assert_eq!(
        json["entries"]["hash"],
        serde_json::Value::from(SECRET_MARKER)
    );
}

#[test]
fn provenance_lines_redacts_a_hash_equal_to_a_secret() {
    let mut module = plain(Some(SECRET));
    module.set_provenance(Some(Provenance {
        parent: Some(secret_bytes()),
        entries: vec![ProvEntry {
            key: "hash".into(),
            value: ProvValue::Hash(secret_bytes()),
        }],
        ..Provenance::default()
    }));
    let lines = active_infinity::interop::provenance_lines(&module);
    let joined = lines.join("\n");
    assert!(joined.contains("***SECRET***"), "{joined}");
    assert!(!joined.contains(&hex(&secret_bytes())), "{joined}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A blob hash is published verbatim by every projection, so a hash that
/// copies a 32-byte secret is refused at encode, like a provenance hash.
#[test]
fn a_blob_hash_that_copies_a_secret_is_refused() {
    let mut module = plain(Some(SECRET));
    let blob = module.push(Inode::Blob {
        hash: secret_bytes(),
        size: 32,
        tainted: false,
        media_type: "application/octet-stream".into(),
        payload: None,
    });
    let root = module.root().expect("root");
    if let Ok(Inode::Table { fields }) = module.node_mut(root) {
        fields.push(("blob".into(), blob));
    }
    let error = encode(&module).expect_err("the copy is refused");
    assert_eq!(error.code(), "infinity/encode", "{error}");
    assert!(error.to_string().contains("blob hash"), "{error}");
}

/// The marker itself contains a secret when a secret is a substring of it.
/// Inserting it would publish the secret, so the projection replaces with the
/// empty string instead.
#[cfg(feature = "json")]
#[test]
fn a_secret_inside_the_marker_is_never_published() {
    use active_infinity::interop::{to_redacted_json, SECRET_MARKER};

    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from("SECRET")));
    let text = module.push(Inode::Str("the SECRET value".into()));
    let root = module.push(Inode::Table {
        fields: vec![("text".into(), text), ("secret".into(), secret)],
    });
    module.set_root(Some(root));

    let json = to_redacted_json(&module).expect("project");
    assert!(!json.contains("SECRET"), "{json}");
    assert!(!json.contains(SECRET_MARKER), "{json}");
}

/// The projection is deterministic over content, not over the in-memory field
/// order: two modules that encode to the same image project to the same bytes.
#[cfg(feature = "json")]
#[test]
fn projection_order_follows_the_content_not_the_construction() {
    use active_infinity::interop::to_redacted_json;

    let build = |fields: &[(&str, i64)]| -> InfinityModule {
        let mut module = InfinityModule::new();
        let mut entries = Vec::new();
        for (name, value) in fields {
            let node = module.push(Inode::Int(*value));
            entries.push(((*name).to_string(), node));
        }
        let root = module.push(Inode::Table { fields: entries });
        module.set_root(Some(root));
        module
    };
    let one = build(&[("b", 2), ("a", 1)]);
    let two = build(&[("a", 1), ("b", 2)]);
    assert_eq!(
        to_redacted_json(&one).expect("json"),
        to_redacted_json(&two).expect("json")
    );
    // The emitted order is the sorted one.
    let json = to_redacted_json(&one).expect("json");
    assert!(
        json.find("\"a\"").expect("a") < json.find("\"b\"").expect("b"),
        "{json}"
    );
}

/// One projection draws every redaction from a single scan budget: a module
/// with many secrets and many strings is refused instead of spending unbounded
/// CPU.
#[cfg(feature = "json")]
#[test]
fn the_projection_redaction_budget_is_shared() {
    use active_infinity::interop::to_redacted_json;

    let mut module = InfinityModule::new();
    let mut fields = Vec::new();
    for index in 0..400 {
        let secret = module.push(Inode::Secret(SecretBytes::from(format!(
            "secret-{index:03}"
        ))));
        fields.push((format!("secret-{index:03}"), secret));
    }
    let text = "y".repeat(8 << 10);
    for index in 0..12 {
        let value = module.push(Inode::Str(text.clone()));
        fields.push((format!("text-{index:03}"), value));
    }
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));

    let error = to_redacted_json(&module).expect_err("the shared budget trips");
    assert_eq!(error.code(), "infinity/limit", "{error}");
    assert!(
        error.to_string().contains("projection redaction"),
        "{error}"
    );
}

/// A newline or `=` in provenance text must not forge a field for a
/// line-oriented consumer.
#[test]
fn provenance_lines_escape_free_text() {
    use active_infinity::interop::provenance_lines;

    let mut module = plain(None);
    module.set_provenance(Some(Provenance {
        producer: Some("agent\nparent=forged".into()),
        ..Provenance::default()
    }));
    let lines = provenance_lines(&module);
    for line in &lines {
        assert!(
            !line.starts_with("parent="),
            "a forged field appeared: {lines:?}"
        );
        assert!(!line.contains('\n'), "a newline appeared: {lines:?}");
    }
    assert!(
        lines.iter().any(|line| line.contains("\\n")),
        "the newline is escaped: {lines:?}"
    );
}

/// Taint follows transparent wrappers: a secret reached through a `Ref` of a
/// `Constrained` node must redact the interpolation, not print its shape.
#[cfg(feature = "json")]
#[test]
fn a_secret_behind_a_wrapper_taints_the_interpolation() {
    use active_infinity::interop::{to_redacted_json, SECRET_MARKER};

    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from("wrapper-canary")));
    let constrained = module.push(Inode::Constrained {
        target: secret,
        constraint: Constraint::MinMax {
            min: None,
            max: None,
        },
    });
    let reference = module.push(Inode::Ref(constrained));
    let text = module.push(Inode::Interpolate {
        parts: vec![
            InterpPart::Literal("value=".into()),
            InterpPart::Expr(reference),
        ],
    });
    module.set_root(Some(text));

    let json = to_redacted_json(&module).expect("project");
    assert!(!json.contains("wrapper-canary"), "{json}");
    assert!(json.contains(SECRET_MARKER), "{json}");
}
