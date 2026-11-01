//! Temporary hostile-audit probe (I-12 round 6), part 2.

use active_infinity::interop::{intents, secret_tainted_paths, value_paths, SECRET_MARKER};
use active_infinity::{InfinityModule, Inode, SecretBytes};

#[test]
fn probe_public_redact_text_marker_collision() {
    let secrets = vec!["SECRET".to_string()];
    let out = active_infinity::interop::redact_text("the value is hunter2", &secrets);
    println!("PROBE redact_text = {out}");
    println!("PROBE contains SECRET = {}", out.contains("SECRET"));
    assert!(!out.contains("SECRET"), "public helper leaked: {out}");
}

#[cfg(feature = "active-core")]
#[test]
fn probe_authoring_path() {
    const SRC: &str = r#"
# @intent: "rotation note: hunter2-canary"
[database]
password = secret("hunter2-canary")
"#;
    let module = active_infinity::interop::from_active_source(SRC, "probe.active").expect("parse");
    let kinds: Vec<String> = module.nodes().iter().map(|n| format!("{n:?}")).collect();
    println!("PROBE parsed nodes = {kinds:?}");
    println!("PROBE has_secret = {}", module.has_secret());
    let root = module.root().expect("root");
    let intent_text = intents(&module, root).join(" | ");
    println!("PROBE parsed intents = {intent_text}");
    let labels: Vec<String> = value_paths(&module).values().cloned().collect();
    println!("PROBE parsed value_paths = {labels:?}");
    let tainted = secret_tainted_paths(&module).join(" , ");
    println!("PROBE parsed tainted = {tainted}");
    assert!(!intent_text.contains("hunter2"), "intents leaked: {intent_text}");
}

#[test]
fn probe_tainted_paths_cost() {
    // A deep chain: taint must travel one level per fixpoint pass.
    let depth = 3000usize;
    let mut module = InfinityModule::new();
    let mut current = module.push(Inode::Secret(SecretBytes::from("canary")));
    for _ in 0..depth {
        current = module.push(Inode::Ref(current));
    }
    module.set_root(Some(current));
    let start = std::time::Instant::now();
    let paths = secret_tainted_paths(&module);
    println!(
        "PROBE chain depth {depth} took {:?}, {} paths",
        start.elapsed(),
        paths.len()
    );
}

#[test]
fn probe_placeholder_scan_cost() {
    // S secrets, N nodes: the placeholder scan runs once per visited node.
    let mut module = InfinityModule::new();
    let mut fields = Vec::new();
    for index in 0..8000 {
        let secret = module.push(Inode::Secret(SecretBytes::from(format!("{index:04}"))));
        fields.push((format!("s{index:05}"), secret));
    }
    for index in 0..8000 {
        let value = module.push(Inode::Int(index as i64));
        fields.push((format!("v{index:05}"), value));
    }
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));
    let start = std::time::Instant::now();
    let json = active_infinity::interop::to_redacted_json(&module);
    println!(
        "PROBE 8k secrets x 8k nodes json ok={} took {:?}",
        json.is_ok(),
        start.elapsed()
    );
    assert!(json.is_ok());
    let _ = SECRET_MARKER;
}
