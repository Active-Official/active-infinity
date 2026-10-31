//! Marathon I-12: the interop bridge and the projections must not publish a
//! secret through a surface that cannot be redacted.
//!
//! A text surface replaces an occurrence with the marker. A hash field, an
//! opaque extension payload, and the `active-core` bridge (which models a
//! secret as a plain string) have no such substitution, so the codec refuses
//! the module or the projection instead.

use active_infinity::{
    encode, InfinityModule, Inode, ProvEntry, ProvValue, Provenance, SecretBytes,
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
