//! Temporary hostile-audit probe (I-12 round 6). Not part of the suite.

use active_infinity::interop::{
    intents, provenance_json_for, provenance_lines, secret_tainted_paths, to_redacted_json,
    value_paths, SECRET_MARKER,
};
use active_infinity::{AnnotationKind, InfinityModule, Inode, ProvEntry, ProvValue, Provenance};

const CANARY: &str = "hunter2";

/// A `SecretRef` locator that is promoted to a structural secret at
/// canonicalization, plus a *second*, public string node holding the same text.
fn secretref_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let locator = module.push(Inode::Str(CANARY.into()));
    let secret_ref = module.push(Inode::SecretRef { locator });
    let public_copy = module.push(Inode::Str(CANARY.into()));
    let root = module.push(Inode::Table {
        fields: vec![
            ("data".into(), public_copy),
            ("token".into(), secret_ref),
        ],
    });
    module.set_root(Some(root));
    module.bind(format!("{CANARY}-key"), public_copy);
    module.annotate(
        root,
        AnnotationKind::Intent(format!("note about {CANARY}")),
    );
    module.set_provenance(Some(Provenance {
        producer: Some(format!("{CANARY}-agent")),
        model: Some(format!("model-{CANARY}")),
        entries: vec![ProvEntry {
            key: format!("{CANARY}-key"),
            value: ProvValue::Text(format!("text-{CANARY}")),
        }],
        ..Provenance::default()
    }));
    module
}

#[test]
fn probe_projection_and_helpers() {
    let module = secretref_module();

    let image = active_infinity::encode(&module).expect("encode");
    let decoded = active_infinity::decode(&image).expect("decode");
    let kinds: Vec<String> = decoded.nodes().iter().map(|n| format!("{n:?}")).collect();
    println!("PROBE decoded nodes = {kinds:?}");
    let image_has = image
        .windows(CANARY.len())
        .any(|window| window == CANARY.as_bytes());
    println!("PROBE image contains literal = {image_has}");

    let json = to_redacted_json(&module).expect("json projection");
    println!("PROBE json = {json}");

    let proto = active_infinity::to_protobuf(&module).expect("protobuf");
    let proto_has = proto
        .windows(CANARY.len())
        .any(|window| window == CANARY.as_bytes());

    let root = module.root().expect("root");
    let intent_text = intents(&module, root).join(" | ");
    let prov_lines = provenance_lines(&module).join(" \\n ");
    let prov_json = provenance_json_for(&module)
        .map(|value| value.to_string())
        .unwrap_or_default();
    let paths = secret_tainted_paths(&module).join(" , ");
    let labels: Vec<String> = value_paths(&module).values().cloned().collect();

    println!("PROBE protobuf contains literal = {proto_has}");
    println!("PROBE intents = {intent_text}");
    println!("PROBE provenance_lines = {prov_lines}");
    println!("PROBE provenance_json = {prov_json}");
    println!("PROBE secret_tainted_paths = {paths}");
    println!("PROBE value_paths = {labels:?}");
    println!("PROBE module Debug = {module:?}");

    assert!(!json.contains(CANARY), "json projection leaked: {json}");
    assert!(!proto_has, "protobuf projection leaked");
    assert!(!intent_text.contains(CANARY), "intents leaked: {intent_text}");
    assert!(
        !prov_lines.contains(CANARY),
        "provenance_lines leaked: {prov_lines}"
    );
    assert!(
        !prov_json.contains(CANARY),
        "provenance_json leaked: {prov_json}"
    );
    assert!(!paths.contains(CANARY), "tainted paths leaked: {paths}");
    for label in &labels {
        assert!(!label.contains(CANARY), "value_paths leaked: {label}");
    }
    assert!(json.contains(SECRET_MARKER), "marker missing: {json}");
}

#[test]
fn probe_provenance_key_collision() {
    use active_infinity::interop::provenance_json;
    let secrets = vec![CANARY.to_string()];
    let prov = Provenance {
        entries: vec![
            ProvEntry {
                key: format!("{CANARY}-k"),
                value: ProvValue::Text("first".into()),
            },
            ProvEntry {
                key: format!("{SECRET_MARKER}-k"),
                value: ProvValue::Text("second".into()),
            },
        ],
        ..Provenance::default()
    };
    let json = provenance_json(&prov, &secrets);
    println!("PROBE collision json = {json}");
    let entries = json["entries"].as_object().expect("entries");
    println!("PROBE collision entry count = {}", entries.len());
}
