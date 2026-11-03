//! Canonical identity must not depend on arena construction order.
//!
//! Cross-cutting pass 1, finding #1: two roots that render identically (two
//! equal integers, two secrets, two identical constraint expressions) were
//! ordered by arena id, so the same logical module built in the other order
//! produced other bytes and another hash. A module is identified by its content
//! (layout §6), and the annotations stored per node are part of that content.
//!
//! Each pair below is the *same* module — the same field-to-annotation mapping —
//! built with the arenas in opposite order.

use active_infinity::{encode, hash_image, AnnotationKind, InfinityModule, Inode};

/// Both build orders of one module must encode to the same bytes.
fn assert_order_independent(first: InfinityModule, second: InfinityModule) {
    let a = encode(&first).expect("encode first");
    let b = encode(&second).expect("encode second");
    assert_eq!(
        active_infinity::ir::hash_hex(&hash_image(&a).expect("hash")),
        active_infinity::ir::hash_hex(&hash_image(&b).expect("hash")),
        "the two build orders hash differently"
    );
    assert_eq!(a, b, "the two build orders encode differently");
}

#[test]
fn equal_integer_subjects_annotated_differently_are_order_independent() {
    let build = |reverse: bool| {
        let mut module = InfinityModule::new();
        let first = module.push(Inode::Int(2));
        let second = module.push(Inode::Int(2));
        let (a, b) = if reverse {
            (second, first)
        } else {
            (first, second)
        };
        let root = module.push(Inode::Table {
            fields: vec![("a".to_string(), a), ("b".to_string(), b)],
        });
        module.set_root(Some(root));
        module.annotate(a, AnnotationKind::Intent("first".to_string()));
        module.annotate(b, AnnotationKind::Intent("second".to_string()));
        module
    };
    assert_order_independent(build(false), build(true));
}

#[test]
fn distinct_secret_subjects_are_order_independent() {
    // The field-to-secret map is by text: `alpha` is annotated "alpha-rule"
    // whichever arena slot it lands in.
    let build = |reverse: bool| {
        let mut module = InfinityModule::new();
        let mut ids = std::collections::BTreeMap::new();
        let texts = ["alpha", "bravo"];
        let order: Vec<&str> = if reverse {
            texts.iter().rev().copied().collect()
        } else {
            texts.to_vec()
        };
        for text in order {
            let id = module.push(Inode::Secret(text.into()));
            ids.insert(text, id);
        }
        let root = module.push(Inode::Table {
            fields: vec![
                ("alpha".to_string(), ids["alpha"]),
                ("bravo".to_string(), ids["bravo"]),
            ],
        });
        module.set_root(Some(root));
        module.annotate(
            ids["alpha"],
            AnnotationKind::Intent("alpha-rule".to_string()),
        );
        module.annotate(
            ids["bravo"],
            AnnotationKind::Intent("bravo-rule".to_string()),
        );
        module
    };
    assert_order_independent(build(false), build(true));
}

#[test]
fn identical_constraint_expressions_are_order_independent() {
    use active_infinity::Constraint;
    let build = |reverse: bool| {
        let mut module = InfinityModule::new();
        let one = module.push(Inode::Int(1));
        let first = module.push(Inode::Constrained {
            target: one,
            constraint: Constraint::Odd,
        });
        let second = module.push(Inode::Constrained {
            target: one,
            constraint: Constraint::Odd,
        });
        let (a, b) = if reverse {
            (second, first)
        } else {
            (first, second)
        };
        let root = module.push(Inode::Table {
            fields: vec![("a".to_string(), a), ("b".to_string(), b)],
        });
        module.set_root(Some(root));
        module.annotate(
            a,
            AnnotationKind::Constraint {
                source: "left".to_string(),
                expr: one,
            },
        );
        module.annotate(
            b,
            AnnotationKind::Constraint {
                source: "right".to_string(),
                expr: one,
            },
        );
        module
    };
    assert_order_independent(build(false), build(true));
}

#[test]
fn a_field_mapping_survives_a_reversed_arena() {
    // Four strings pushed in opposite orders; every field still names the same
    // text, so the only difference is the arena.
    let build = |reverse: bool| {
        let mut module = InfinityModule::new();
        let mut ids = std::collections::BTreeMap::new();
        let texts = ["a", "b", "c", "d"];
        let order: Vec<&str> = if reverse {
            texts.iter().rev().copied().collect()
        } else {
            texts.to_vec()
        };
        for text in order {
            let id = module.push(Inode::Str(text.to_string()));
            ids.insert(text, id);
        }
        let root = module.push(Inode::Table {
            fields: texts
                .iter()
                .map(|text| (text.to_string(), ids[*text]))
                .collect(),
        });
        module.set_root(Some(root));
        module
    };
    assert_order_independent(build(false), build(true));
}
