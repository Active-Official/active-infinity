//! Temporary hostile-audit probe (I-12 round 6), part 3.

use active_infinity::interop::{intents, to_redacted_json, value_paths, SECRET_MARKER};
use active_infinity::{InfinityModule, Inode, SecretBytes};

#[test]
fn probe_public_redact_text_marker_collision() {
    let secrets = vec!["SECRET".to_string()];
    let out = active_infinity::interop::redact_text("the SECRET value", &secrets);
    println!("PROBE redact_text = {out}");
    assert!(
        !out.contains("SECRET"),
        "public helper re-published the secret: {out}"
    );
}

#[cfg(feature = "active-core")]
#[test]
fn probe_authoring_path_intents() {
    const SRC: &str = r#"
# @intent: "rotation note: hunter2-canary"
[database]
password = secret("hunter2-canary")
"#;
    let module = active_infinity::interop::from_active_source(SRC, "probe.active").expect("parse");
    println!("PROBE has_secret = {}", module.has_secret());
    for annotation in module.annotations() {
        println!("PROBE annotation node={} kind={:?}", annotation.node.0, annotation.kind);
    }
    for annotation in module.annotations() {
        let text = intents(&module, annotation.node).join(" | ");
        println!("PROBE intents(node {}) = {text}", annotation.node.0);
    }
    let decoded = active_infinity::decode(&active_infinity::encode(&module).unwrap()).unwrap();
    for annotation in decoded.annotations() {
        let text = intents(&decoded, annotation.node).join(" | ");
        println!("PROBE decoded intents(node {}) = {text}", annotation.node.0);
    }
}

#[test]
fn probe_shared_locator_shape() {
    let mut module = InfinityModule::new();
    let shared = module.push(Inode::Str("hunter2".into()));
    let secret_ref = module.push(Inode::SecretRef { locator: shared });
    let root = module.push(Inode::Table {
        fields: vec![
            ("data".into(), shared),
            ("token".into(), secret_ref),
        ],
    });
    module.set_root(Some(root));
    let image = active_infinity::encode(&module).expect("encode");
    let decoded = active_infinity::decode(&image).expect("decode");
    println!(
        "PROBE shared decoded = {:?}",
        decoded.nodes().iter().map(|n| format!("{n:?}")).collect::<Vec<_>>()
    );
    println!(
        "PROBE shared json = {}",
        to_redacted_json(&module).expect("json")
    );
    println!("PROBE shared value_paths = {:?}", value_paths(&module));
}

#[test]
fn probe_placeholder_scan_cost() {
    // Many secrets and many non-text nodes: the placeholder scan runs once per
    // visited node and is charged to no budget.
    let mut module = InfinityModule::new();
    let mut elements = Vec::new();
    for index in 0..30_000i64 {
        elements.push(module.push(Inode::Secret(SecretBytes::from(format!(
            "{index:05}"
        )))));
        elements.push(module.push(Inode::Int(index)));
    }
    let root = module.push(Inode::Array { elements });
    module.set_root(Some(root));
    let start = std::time::Instant::now();
    let json = to_redacted_json(&module);
    println!(
        "PROBE 30k secrets x 30k ints json ok={} took {:?}",
        json.is_ok(),
        start.elapsed()
    );
    let _ = SECRET_MARKER;
}
