//! Marathon I-12 round 7: the non-projection exports and the canonical ordering
//! keys must be bounded.
//!
//! `provenance_lines`, `provenance_json_for`, `value_paths` and `intents` hand
//! text to logs and agents. They cannot refuse a call, so they saturate to the
//! hiding placeholder once one shared scan budget is spent; a wire projection
//! refuses instead. The ordering keys for annotation subjects are rendered once
//! per distinct subject and bounded in total.

use active_infinity::interop::{intents, provenance_lines, secret_tainted_paths, value_paths};
use active_infinity::{
    encode, validate_canonical, AnnotationKind, InfinityModule, Inode, Provenance, SecretBytes,
};

#[cfg(feature = "json")]
use active_infinity::interop::{provenance_json_for, SECRET_MARKER};

/// A secret-bearing module with `count` secrets and a root `Int(0)`.
fn many_secrets(count: usize) -> InfinityModule {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(0));
    module.set_root(Some(root));
    for index in 0..count {
        module.push(Inode::Secret(SecretBytes::from(format!(
            "SECRET{index:05}"
        ))));
    }
    module
}

/// Every ordering key is a full render of its subject. One subject may be
/// annotated any number of times, but the keys of *distinct* subjects are
/// bounded in total: 90 subjects that each render ~820 KiB exceed the 64 MiB
/// ceiling and are refused instead of driving peak memory to the sum.
#[test]
fn annotation_ordering_keys_are_bounded_in_total() {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(0));
    module.set_root(Some(root));
    let leaf = module.push(Inode::Str("z".repeat(900)));
    for _ in 0..90 {
        let fields: Vec<(String, active_infinity::NodeId)> = (0..900)
            .map(|field| (format!("f{field:04}"), leaf))
            .collect();
        let subject = module.push(Inode::Table { fields });
        module.annotate(subject, AnnotationKind::Intent("note".into()));
    }
    let error = encode(&module).expect_err("the total key bytes must be bounded");
    assert_eq!(error.code(), "infinity/limit", "{error}");
    assert!(error.to_string().contains("annotation key"), "{error}");
}

/// One subject annotated 200 000 times renders its key once. Charging per
/// annotation would refuse this module (200 000 × ~100 KiB is far past the
/// budget), so this guards the dedupe in `canonical_order`.
#[test]
fn many_annotations_on_one_subject_share_one_ordering_key() {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(0));
    module.set_root(Some(root));
    let leaf = module.push(Inode::Str("y".repeat(900)));
    let mut fields = Vec::new();
    for field in 0..100 {
        fields.push((format!("f{field:03}"), leaf));
    }
    let subject = module.push(Inode::Table { fields });
    for _ in 0..200_000 {
        module.annotate(subject, AnnotationKind::Intent("note".into()));
    }
    let image = encode(&module).expect("one render per subject");
    validate_canonical(&image, active_infinity::Limits::default()).expect("canonical");
}

/// A provenance text whose scan would cost 3000 × 4096 × 8 bytes — past the
/// export budget — is replaced by the placeholder instead of scanned.
#[test]
fn a_provenance_text_is_redacted_when_the_export_budget_is_spent() {
    let mut module = many_secrets(3000);
    let text = "z".repeat(4096);
    module.set_provenance(Some(Provenance {
        producer: Some(text.clone()),
        ..Provenance::default()
    }));
    let lines = provenance_lines(&module);
    let producer = lines
        .iter()
        .find(|line| line.starts_with("producer="))
        .expect("producer line");
    assert_eq!(producer, "producer=***SECRET***", "{}", producer.len());
}

#[cfg(feature = "json")]
#[test]
fn a_provenance_json_text_is_redacted_when_the_export_budget_is_spent() {
    let mut module = many_secrets(3000);
    let text = "z".repeat(4096);
    module.set_provenance(Some(Provenance {
        producer: Some(text.clone()),
        ..Provenance::default()
    }));
    let json = provenance_json_for(&module).expect("provenance");
    assert_eq!(json["producer"], serde_json::Value::from(SECRET_MARKER));
}

/// Field-name redaction draws on the same budget: past it a key saturates to
/// the placeholder rather than scanning 3000 secrets for every field.
#[test]
fn value_paths_saturate_after_the_export_budget() {
    let mut module = many_secrets(3000);
    let mut fields = Vec::new();
    for field in 0..3000 {
        let value = module.push(Inode::Int(field));
        fields.push((format!("field{field:04}"), value));
    }
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));
    let paths = value_paths(&module);
    let saturated = paths
        .values()
        .filter(|path| path.as_str() == "***SECRET***")
        .count();
    assert!(
        saturated > 1000,
        "only {saturated} of {} paths saturated",
        paths.len()
    );
}

/// Intent text redaction shares the budget across the annotations of one call.
#[test]
fn intents_saturate_after_the_export_budget() {
    let mut module = many_secrets(1000);
    let root = module.push(Inode::Int(0));
    module.set_root(Some(root));
    for _ in 0..40 {
        module.annotate(root, AnnotationKind::Intent("z".repeat(4096)));
    }
    let texts = intents(&module, root);
    assert_eq!(texts.len(), 40);
    let saturated = texts
        .iter()
        .filter(|text| text.as_str() == "***SECRET***")
        .count();
    assert!(saturated >= 30, "only {saturated} intents saturated");
}

/// Two provenance keys that redact to one must not produce two conflicting
/// exports: the JSON projection refuses, the line codec keeps the first entry.
#[cfg(feature = "json")]
#[test]
fn a_redacted_key_collision_is_refused_in_provenance() {
    use active_infinity::{ProvEntry, ProvValue};

    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from("hunter2")));
    module.set_root(Some(secret));
    module.set_provenance(Some(Provenance {
        entries: vec![
            ProvEntry {
                key: "hunter2".into(),
                value: ProvValue::Text("first".into()),
            },
            ProvEntry {
                key: "***SECRET***".into(),
                value: ProvValue::Text("second".into()),
            },
        ],
        ..Provenance::default()
    }));
    assert!(
        provenance_json_for(&module).is_none(),
        "a collision must refuse rather than drop an entry"
    );
    let lines = provenance_lines(&module);
    // `set_provenance` stores entries in raw-key order, so `***SECRET***`
    // precedes `hunter2`; the line codec keeps the first of the collision.
    assert_eq!(lines, vec!["***SECRET***=second".to_string()]);
}

/// A secret under a subtree that only an annotation names still taints that
/// subtree; otherwise an agent is told a secret-bearing module has no secret
/// paths.
#[test]
fn a_secret_under_an_annotation_only_subject_is_reported() {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(0));
    module.set_root(Some(root));
    let secret = module.push(Inode::Secret(SecretBytes::from("hidden")));
    let holder = module.push(Inode::Table {
        fields: vec![("pw".into(), secret)],
    });
    module.annotate(holder, AnnotationKind::Intent("note".into()));
    let paths = secret_tainted_paths(&module);
    assert!(!paths.is_empty(), "the annotation-only subtree is tainted");
    assert!(
        paths.iter().any(|path| path.contains("pw")),
        "the secret's own path is missing: {paths:?}"
    );
}

/// A locator behind 64 references is still resolved, so every export redacts
/// the literal. The walk is bounded by the node count, not by a hop constant.
#[cfg(feature = "json")]
#[test]
fn a_long_locator_chain_stays_redacted() {
    let literal = "deep-canary";
    let mut module = InfinityModule::new();
    let mut current = module.push(Inode::Str(literal.into()));
    for _ in 0..64 {
        current = module.push(Inode::Ref(current));
    }
    let secret = module.push(Inode::SecretRef { locator: current });
    let root = module.push(Inode::Table {
        fields: vec![("s".into(), secret)],
    });
    module.set_root(Some(root));
    module.set_provenance(Some(Provenance {
        producer: Some(literal.into()),
        ..Provenance::default()
    }));
    let lines = provenance_lines(&module).join("\n");
    assert!(!lines.contains(literal), "{lines}");
    let json = provenance_json_for(&module).expect("provenance");
    assert!(!json.to_string().contains(literal), "{json}");
}
