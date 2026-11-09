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
    encode, validate_canonical, AnnotationKind, InfinityModule, Inode, InterpPart, Provenance,
    SecretBytes,
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
///
/// A saturated key is not a unique name, so every path after the first one is
/// the id label instead: two nodes must never answer one label (cross-cutting
/// pass 1, #8).
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
    assert!(
        paths.values().any(|path| path.as_str() == "***SECRET***"),
        "no key saturated"
    );
    let unique: std::collections::HashSet<&str> = paths.values().map(String::as_str).collect();
    assert_eq!(
        unique.len(),
        paths.len(),
        "two nodes share one label: {} of {}",
        unique.len(),
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

// ---------------------------------------------------------------------------
// Round 8: deeper locator shapes, the spent-budget path, and pathological
// path text.
// ---------------------------------------------------------------------------

/// A locator may be an expression, not just a literal: `secret(pw + "-suffix")`
/// keeps its `Str` and its interpolated part in the public string heap unless
/// the whole locator subtree is promoted.
#[cfg(feature = "json")]
#[test]
fn a_binary_wrapped_interpolated_locator_is_promoted() {
    use active_infinity::interop::to_redacted_json;

    let literal = "-canary-";
    let mut module = InfinityModule::new();
    let pw = module.push(Inode::Str("hunter2".into()));
    let name = module.push(Inode::Str("svc".into()));
    let interp = module.push(Inode::Interpolate {
        parts: vec![InterpPart::Expr(name), InterpPart::Literal(literal.into())],
    });
    let sum = module.push(Inode::Binary {
        op: active_infinity::BinOp::Add,
        lhs: pw,
        rhs: interp,
    });
    let secret = module.push(Inode::SecretRef { locator: sum });
    let root = module.push(Inode::Table {
        fields: vec![("password".into(), secret)],
    });
    module.set_root(Some(root));

    // The literal must leave the public string heap: `secret(pw + "-canary-${name}")`
    // hides every string in the locator subtree, not only a resolved endpoint.
    // (The bytes still exist in the image's secret section, by design.)
    let image = encode(&module).expect("encode");
    let decoded = active_infinity::decode(&image).expect("decode");
    for node in decoded.nodes() {
        match node {
            Inode::Str(text) => assert!(!text.contains(literal), "public string: {text}"),
            Inode::Interpolate { parts } => {
                for part in parts {
                    if let InterpPart::Literal(text) = part {
                        assert!(!text.contains(literal), "interpolated part: {text}");
                    }
                }
            }
            _ => {}
        }
    }

    // A public copy of the fragment is redacted by every export, because the
    // in-memory secret table resolves the whole locator subtree. The copy is
    // added to the existing root table in place (INF-04): pushing a second
    // root table would orphan the first one, and encode now refuses
    // unreachable nodes.
    let copy = module.push(Inode::Str(format!("copy {literal} here")));
    if let Inode::Table { fields } = module.node_mut(root).expect("root table") {
        fields.push(("copy".into(), copy));
    } else {
        panic!("root is not a table");
    }
    let json = to_redacted_json(&module).expect("project");
    assert!(!json.contains(literal), "{json}");
    let lines = provenance_lines(&module).join("\n");
    assert!(!lines.contains(literal), "{lines}");
    let notes = intents(&module, root).join(" ");
    assert!(!notes.contains(literal), "{notes}");
}

/// Once the export budget is spent, the saturating path must not rescan the
/// secret table per value: 200 000 secrets and 5 000 fields measured 16 s
/// before the placeholder was computed once per export.
#[test]
fn a_spent_export_budget_does_not_rescan_the_secret_table() {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(0));
    module.set_root(Some(root));
    for index in 0..200_000 {
        module.push(Inode::Secret(SecretBytes::from(format!(
            "SECRET{index:06}"
        ))));
    }
    let mut fields = Vec::new();
    for field in 0..5_000 {
        let value = module.push(Inode::Int(field));
        fields.push((format!("field{field:05}"), value));
    }
    let table = module.push(Inode::Table { fields });
    module.set_root(Some(table));

    let start = std::time::Instant::now();
    let paths = value_paths(&module);
    let elapsed = start.elapsed();
    assert_eq!(paths.len(), 5_001);
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "value_paths took {elapsed:?}"
    );
    assert!(
        paths.values().any(|path| path == "***SECRET***"),
        "the budget never saturated a key"
    );
}

/// A dotted path copies its parent's prefix, so a deep comb builds quadratic
/// text (depth 400 measured 480 800 bytes, longest 2 399). Past the cap a node
/// gets a short identity label instead.
#[test]
fn a_deep_path_chain_stays_bounded() {
    let mut module = InfinityModule::new();
    let mut current = module.push(Inode::Int(1));
    for _ in 0..400 {
        current = module.push(Inode::Table {
            fields: vec![("field".into(), current)],
        });
    }
    module.set_root(Some(current));
    let paths = value_paths(&module);
    let total: usize = paths.values().map(|path| path.len()).sum();
    let longest = paths.values().map(|path| path.len()).max().unwrap_or(0);
    assert!(
        paths.len() <= 500,
        "{} paths for a depth-400 comb",
        paths.len()
    );
    assert!(total < 64 * 1024, "{total} bytes of path text");
    assert!(longest < 1024, "longest path is {longest} bytes");
    assert!(
        paths.values().any(|path| path.starts_with("@node[")),
        "deep nodes must keep an identity label"
    );
}

/// The module root wins over an annotation's synthetic label: a real dotted
/// path is what an agent needs, and the root's own path stays empty.
#[test]
fn an_annotated_subtree_keeps_its_real_path() {
    let mut module = InfinityModule::new();
    let leaf = module.push(Inode::Int(1));
    let inner = module.push(Inode::Table {
        fields: vec![("field".into(), leaf)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("annotated".into(), inner)],
    });
    module.set_root(Some(root));
    module.annotate(inner, AnnotationKind::Intent("note".into()));
    module.annotate(root, AnnotationKind::Intent("note".into()));

    let paths = value_paths(&module);
    assert_eq!(paths.get(&root).map(String::as_str), Some(""));
    assert_eq!(paths.get(&inner).map(String::as_str), Some("annotated"));
    assert_eq!(
        paths.get(&leaf).map(String::as_str),
        Some("annotated.field")
    );
}

/// A secret reachable only through a back edge still taints its ancestors. A
/// post-order walk marked the cycle member done before the taint arrived.
#[test]
fn a_secret_behind_a_cycle_back_edge_is_reported() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from("hidden")));
    // `a.next` is a `Ref` so the cycle closes without mutating a pushed node:
    // a -> ref -> b -> a. The arena is deterministic here: secret=0, ref=1,
    // a=2, b=3.
    let next = module.push(Inode::Ref(active_infinity::NodeId(3)));
    let a = module.push(Inode::Table {
        fields: vec![("s".into(), secret), ("next".into(), next)],
    });
    let b = module.push(Inode::Table {
        fields: vec![("back".into(), a)],
    });
    assert_eq!(b, active_infinity::NodeId(3));
    module.set_root(Some(a));
    let paths = secret_tainted_paths(&module);
    assert!(paths.contains(&"next".to_string()), "{paths:?}");
}

/// A spent budget ends the provenance entry list instead of inventing a marker
/// key (the line codec) or reporting the whole block absent (the JSON one).
#[cfg(feature = "json")]
#[test]
fn a_spent_budget_never_fabricates_a_provenance_key() {
    use active_infinity::interop::provenance_json_for;
    use active_infinity::{ProvEntry, ProvValue};

    let mut module = many_secrets(3_000);
    module.set_provenance(Some(Provenance {
        entries: (0..12)
            .map(|index| ProvEntry {
                key: format!("k{index:02}"),
                value: ProvValue::Text("z".repeat(4096)),
            })
            .collect(),
        ..Provenance::default()
    }));
    let lines = provenance_lines(&module);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].starts_with("k00="), "{lines:?}");
    let json = provenance_json_for(&module).expect("provenance must stay present");
    assert!(json["entries"].get("k00").is_some(), "{json}");
}

/// Many refs that share one long locator chain resolve it once: 200 000 refs
/// over a 4 000-hop chain measured 8.3 s before the memo.
#[test]
fn shared_locator_chains_resolve_once() {
    let mut module = InfinityModule::new();
    let mut current = module.push(Inode::Str("shared-chain-literal".into()));
    for _ in 0..4_000 {
        current = module.push(Inode::Ref(current));
    }
    let mut fields = Vec::new();
    for index in 0..200_000 {
        let secret = module.push(Inode::SecretRef { locator: current });
        fields.push((format!("s{index:06}"), secret));
    }
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));
    module.set_provenance(Some(Provenance {
        producer: Some("agent".into()),
        ..Provenance::default()
    }));
    let start = std::time::Instant::now();
    let lines = provenance_lines(&module);
    let elapsed = start.elapsed();
    assert_eq!(lines, vec!["producer=agent".to_string()]);
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "provenance_lines took {elapsed:?}"
    );
}

/// Fragments are hidden from the public heap and from exports, but they are not
/// stored-metadata redaction targets: rewriting a one-byte fragment would
/// destroy the prose. Metadata must therefore not contain one, and the refusal
/// keeps `encode(decode(image))` equal to `image`.
#[cfg(feature = "json")]
#[test]
fn an_interpolated_one_byte_part_must_not_appear_in_metadata() {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("svc".into()));
    let interp = module.push(Inode::Interpolate {
        parts: vec![InterpPart::Literal("S".into()), InterpPart::Expr(name)],
    });
    let secret = module.push(Inode::SecretRef { locator: interp });
    let root = module.push(Inode::Table {
        fields: vec![("password".into(), secret)],
    });
    module.set_root(Some(root));
    module.annotate(root, AnnotationKind::Intent("S note".into()));
    module.set_provenance(Some(Provenance {
        producer: Some("agent S run".into()),
        ..Provenance::default()
    }));

    let error = encode(&module).expect_err("a fragment in metadata must be refused");
    assert_eq!(error.code(), "infinity/encode", "{error}");
    assert!(error.to_string().contains("fragment"), "{error}");
}

/// The canonical image is a fixed point: promotion must not move secret material
/// in a way that a second pass redacts differently.
#[test]
fn canonicalization_is_a_fixed_point_for_locator_fragments() {
    for shape in 0..3 {
        let mut module = InfinityModule::new();
        let literal = "hunter2";
        // Shape 0 has no `name` node (INF-04): pushing it unconditionally
        // left it unreachable in that shape, and encode now refuses
        // unreachable nodes. Shapes 1 and 2 use it as the locator's operand.
        let locator = match shape {
            0 => module.push(Inode::Str(literal.into())),
            1 => {
                let name = module.push(Inode::Str("svc".into()));
                module.push(Inode::Interpolate {
                    parts: vec![
                        InterpPart::Literal("hunter-".into()),
                        InterpPart::Expr(name),
                    ],
                })
            }
            _ => {
                let name = module.push(Inode::Str("svc".into()));
                let left = module.push(Inode::Str(literal.into()));
                module.push(Inode::Binary {
                    op: active_infinity::BinOp::Add,
                    lhs: left,
                    rhs: name,
                })
            }
        };
        let secret = module.push(Inode::SecretRef { locator });
        let root = module.push(Inode::Table {
            fields: vec![("password".into(), secret)],
        });
        module.set_root(Some(root));
        module.annotate(root, AnnotationKind::Intent("a note".into()));
        module.set_provenance(Some(Provenance {
            producer: Some("agent run".into()),
            ..Provenance::default()
        }));

        let image = encode(&module).expect("encode");
        validate_canonical(&image, active_infinity::Limits::default())
            .unwrap_or_else(|error| panic!("shape {shape}: {error}"));
        let decoded = active_infinity::decode(&image).expect("decode");
        let again = encode(&decoded).expect("re-encode");
        assert_eq!(
            image, again,
            "shape {shape}: canonicalization is not a fixed point"
        );
    }
}
