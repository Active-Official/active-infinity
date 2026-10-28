#![no_main]

//! Secrets in every metadata position: no export path may carry the literal.
//!
//! Invariants under test (I-1, I-3):
//!
//! 1. A secret in a binding name, a table key, an annotation, provenance text
//!    and a tainted interpolation is redacted on every export path.
//! 2. `Debug`, the redacted JSON projection, the Protobuf projection, the
//!    provenance lines and the value paths agree: none contains the literal.
//! 3. Redaction is a fixpoint: a second projection of the same module is
//!    identical.
//!
//! Run with `cargo +nightly fuzz run fuzz_secret_positions -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_infinity::interop::{
    provenance_lines, secret_tainted_paths, to_redacted_json, value_paths,
};
use active_infinity::{
    AnnotationKind, InfinityModule, Inode, ProvEntry, ProvValue, Provenance, SecretBytes,
};

#[path = "common.rs"]
mod common;

fn build(literal: &str) -> InfinityModule {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from(literal)));
    let number = module.push(Inode::Int(7));
    let root = module.push(Inode::Table {
        fields: vec![(format!("key-{literal}"), secret), ("n".into(), number)],
    });
    module.set_root(Some(root));
    // A binding name and an annotation that both copy the literal.
    module.bind(format!("binding {literal}"), secret);
    module.annotate(secret, AnnotationKind::Intent(format!("note {literal}")));
    module.set_provenance(Some(Provenance {
        producer: Some(format!("producer {literal}")),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: None,
        entries: vec![ProvEntry {
            key: format!("entry-{literal}"),
            value: ProvValue::Text(format!("value {literal}")),
        }],
    }));
    module
}

fn assert_absent(label: &str, text: &str, literal: &str) {
    assert!(
        !text.contains(literal),
        "{label} leaked the secret literal: {text}"
    );
}

fuzz_target!(|data: &[u8]| {
    let literal = common::canary(data);
    let module = build(&literal);

    // Debug is an export path.
    assert_absent("Debug", &format!("{module:?}"), &literal);

    // JSON projection.
    if let Ok(json) = to_redacted_json(&module) {
        assert_absent("redacted JSON", &json, &literal);
        assert!(
            json.contains(active_infinity::interop::SECRET_MARKER),
            "the marker must appear when a secret is present"
        );
        let again = to_redacted_json(&module).expect("deterministic projection");
        assert_eq!(json, again, "the JSON projection is not deterministic");
    }

    // Protobuf projection.
    if let Ok(bytes) = active_infinity::to_protobuf(&module) {
        let text = String::from_utf8_lossy(&bytes);
        assert_absent("protobuf", &text, &literal);
        assert!(
            bytes
                .windows(active_infinity::interop::SECRET_MARKER.len())
                .any(|window| window == active_infinity::interop::SECRET_MARKER.as_bytes()),
            "the protobuf projection must carry the marker"
        );
        let again = active_infinity::to_protobuf(&module).expect("deterministic projection");
        assert_eq!(bytes, again, "the protobuf projection is not deterministic");
    }

    // Provenance and path labels.
    for line in provenance_lines(&module) {
        assert_absent("provenance lines", &line, &literal);
    }
    for (_, path) in value_paths(&module) {
        assert_absent("value paths", &path, &literal);
    }
    for label in secret_tainted_paths(&module) {
        assert_absent("tainted paths", &label, &literal);
    }
});
