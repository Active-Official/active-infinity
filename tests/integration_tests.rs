//! Integration tests on the real authoring path: text Active parsed by
//! `active-core`, lowered to Infinity, encoded, validated, decoded and
//! evaluated again.
//!
//! These tests are the repository's proof for acceptance criterion 1: the
//! shipped public API turns real modules into `AINF` bytes and back with equal
//! values, re-encoding is byte-identical, and the content hash is stable.

#![cfg(feature = "active-core")]

use active_infinity::interop::{
    evaluate, from_active_core, from_active_source, impact, node_label, resolve_path,
    secret_tainted_paths, to_active_core, to_redacted_json, why,
};
use active_infinity::{
    content_hash, decode, encode, validate, InfinityModule, Inode, ProvEntry, ProvValue, Provenance,
};

const SOURCE: &str = r#"
# @intent: "Service topology for the integration test"
# @ai_immutable: true
[app]
name        = "infinity-integration"
environment = env.APP_ENV ?: "test"
debug       = true

let base = "https://api.example.com"
let timeout = 1500ms
let retries = 3

[server]
host         = "127.0.0.1"
port         = 8080
read_timeout = timeout * 2
ratio        = 25%

[services]
auth_url  = "${base}/auth"
users_url = "${base}/users"
weights   = [1, 2, 3, 5, 8]

[database]
host     = "localhost"
password = secret("hunter2-canary")
pool     = 16
"#;

fn module() -> InfinityModule {
    from_active_source(SOURCE, "integration.active").expect("parse + lower")
}

#[test]
fn real_modules_round_trip_with_equal_values() {
    let module = module();
    assert!(module.node_count() > 20, "fixture must be a real module");
    let bytes = encode(&module).expect("encode");
    let meta = validate(&bytes).expect("validate");
    assert!(meta.nodes > 0);
    let decoded = decode(&bytes).expect("decode");
    assert_eq!(decoded, module, "values survive the round trip");
    assert_eq!(encode(&decoded).unwrap(), bytes, "re-encode is identical");
    assert_eq!(
        content_hash(&bytes).unwrap(),
        content_hash(&encode(&module).unwrap()).unwrap()
    );
}

#[test]
fn content_hash_is_stable_across_independent_encodes() {
    let first = encode(&module()).unwrap();
    let second = encode(&from_active_source(SOURCE, "other-name.active").unwrap()).unwrap();
    assert_eq!(first, second, "module name must not affect the image");
    let hash = content_hash(&first).unwrap();
    // Stable in-process and across runs: a changed value must change it.
    let mut other = from_active_source(SOURCE, "x.active").unwrap();
    let port = other
        .nodes()
        .iter()
        .position(|node| matches!(node, Inode::Int(8080)))
        .expect("port node");
    *other
        .node_mut(active_infinity::NodeId(port as u32))
        .unwrap() = Inode::Int(8081);
    assert_ne!(content_hash(&encode(&other).unwrap()).unwrap(), hash);
}

#[test]
fn units_annotations_and_secrets_survive_the_binary_form() {
    let module = module();
    let bytes = encode(&module).unwrap();
    let decoded = decode(&bytes).unwrap();

    // Units: read_timeout is a Duration quantity in milliseconds.
    assert!(decoded.nodes().iter().any(|node| matches!(
        node,
        Inode::Quantity {
            unit: active_infinity::UnitTag::Milliseconds,
            ..
        }
    )));
    // Annotations: intent + immutability on the root table.
    assert!(decoded
        .annotations()
        .iter()
        .any(|annotation| matches!(&annotation.kind, active_infinity::AnnotationKind::Intent(text) if text.contains("Service topology"))));
    assert!(decoded.annotations().iter().any(|annotation| matches!(
        &annotation.kind,
        active_infinity::AnnotationKind::AiImmutable(true)
    )));
    // Structured secrets: present as a kind, never as plain text in the public
    // string heap (a locator literal referenced only by a secret is promoted
    // into the secret table at canonicalization).
    assert!(decoded.has_secret());
    assert!(
        !decoded.nodes().iter().any(|node| match node {
            Inode::Str(text) => text.contains("hunter2"),
            _ => false,
        }),
        "a secret literal must not survive in the public string heap"
    );
    assert!(!format!("{decoded:?}").contains("hunter2-canary"));
    let json = to_redacted_json(&decoded).unwrap();
    assert!(
        !json.contains("hunter2-canary"),
        "projection leaked a secret"
    );
    assert!(json.contains("***SECRET***"));
    assert!(json.contains("infinity-integration"));
}

#[test]
fn lowering_is_idempotent_through_active_core() {
    let module = module();
    let core = to_active_core(&module).expect("back to active-core");
    let again = from_active_core(&core).expect("and back to infinity");
    assert_eq!(encode(&again).unwrap(), encode(&module).unwrap());
}

#[test]
fn evaluation_still_works_after_the_binary_round_trip() {
    let module = module();
    let bytes = encode(&module).unwrap();
    let decoded = decode(&bytes).unwrap();
    let (value, diagnostics) =
        evaluate(&decoded, active_core::Budget::default()).expect("evaluate");
    assert!(
        diagnostics.is_empty(),
        "unexpected diagnostics: {diagnostics:?}"
    );
    let table = match value {
        active_core::Value::Table(table) => table,
        other => panic!("expected a table, got {other:?}"),
    };
    let server = table
        .get("server")
        .and_then(|value| match value {
            active_core::Value::Table(table) => Some(table),
            _ => None,
        })
        .expect("server table");
    assert!(server.contains_key("port"));
}

#[test]
fn agents_can_ask_why_and_impact() {
    let module = module();
    let port = resolve_path(&module, "server.port").expect("server.port");
    let impacts = impact(&module, port);
    assert!(
        impacts.iter().any(|label| label == "server"),
        "impact must include the parent table: {impacts:?}"
    );

    let read_timeout = resolve_path(&module, "server.read_timeout").expect("read_timeout");
    let dependencies = why(&module, read_timeout);
    assert!(
        !dependencies.is_empty(),
        "read_timeout depends on `timeout` and a literal"
    );

    // The secret cone is labelled, and no label contains secret material.
    let tainted = secret_tainted_paths(&module);
    assert!(tainted.iter().any(|path| path.contains("password")));
    assert!(tainted.iter().all(|path| !path.contains("hunter2")));
    assert_eq!(node_label(&module, port), "server.port");
}

#[test]
fn provenance_travels_with_the_module() {
    let mut module = module();
    module.set_provenance(Some(Provenance {
        producer: Some("integration-test".into()),
        timestamp_ms: 1_700_000_000_000,
        model: Some("grok".into()),
        tool: Some("cargo test".into()),
        parent: Some([1u8; 32]),
        entries: vec![ProvEntry {
            key: "ticket".into(),
            value: ProvValue::Text("AC-1".into()),
        }],
    }));
    let bytes = encode(&module).unwrap();
    let decoded = decode(&bytes).unwrap();
    let prov = decoded.provenance().expect("provenance");
    assert_eq!(prov.producer.as_deref(), Some("integration-test"));
    assert_eq!(prov.parent, Some([1u8; 32]));
    assert_eq!(encode(&decoded).unwrap(), bytes);
}

#[test]
fn malformed_input_never_panics_and_always_fails_closed() {
    let bytes = encode(&module()).unwrap();
    // Truncate at every 32-byte boundary and in-between, plus flips.
    let mut cases = 0usize;
    for length in (0..bytes.len()).step_by(7) {
        let slice = &bytes[..length];
        let result = std::panic::catch_unwind(|| validate(slice));
        assert!(result.is_ok(), "validate panicked at length {length}");
        assert!(
            result.unwrap().is_err(),
            "truncated buffer at {length} must be rejected"
        );
        cases += 1;
    }
    for position in (0..bytes.len()).step_by(11) {
        let mut mutated = bytes.clone();
        mutated[position] ^= 0x55;
        let result = std::panic::catch_unwind(|| validate(&mutated));
        assert!(
            result.is_ok(),
            "validate panicked on flipped byte {position}"
        );
        // Either the hash catches it or a structural check does.
        assert!(
            result.unwrap().is_err(),
            "flip at {position} must be rejected"
        );
        cases += 1;
    }
    assert!(cases > 50, "mutation campaign must actually run");
}
