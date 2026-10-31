//! Marathon I-11: the three-way merge's refusals, paths and bounds.
//!
//! These pin the properties the review found missing: paths are unambiguous,
//! a shape change is not mislabelled, metadata is base-aware and compared
//! redacted, annotations are order-insensitive, inputs are validated up front,
//! and the imported-node budget refuses a shared large cone.

use active_infinity::merge::{merge, ConflictKind, Merge, MAX_MERGE_NODES};
use active_infinity::{InfinityModule, Inode, NodeId, Provenance};

fn int_fields(fields: &[(&str, i64)]) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut entries = Vec::new();
    for (name, value) in fields {
        let id = module.push(Inode::Int(*value));
        entries.push((name.to_string(), id));
    }
    let root = module.push(Inode::Table { fields: entries });
    module.set_root(Some(root));
    module
}

fn conflicts(result: Merge) -> Vec<active_infinity::Conflict> {
    match result {
        Merge::Conflicts(conflicts) => conflicts,
        Merge::Clean(_) => panic!("expected conflicts"),
    }
}

#[test]
fn a_field_name_with_a_dot_is_escaped_in_the_path() {
    let base = int_fields(&[("a.b", 1)]);
    let left = int_fields(&[("a.b", 2)]);
    let right = int_fields(&[("a.b", 3)]);
    let found = conflicts(merge(&base, &left, &right).expect("merge"));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].field, "a\\.b");
    assert_eq!(found[0].kind, ConflictKind::ModifyModify);
}

#[test]
fn a_field_named_like_a_metadata_marker_is_escaped() {
    let base = int_fields(&[("<bindings>", 1)]);
    let left = int_fields(&[("<bindings>", 2)]);
    let right = int_fields(&[("<bindings>", 3)]);
    let found = conflicts(merge(&base, &left, &right).expect("merge"));
    assert_eq!(found[0].field, "\\<bindings>");
}

/// The base says `server` is an integer while both sides turned it into a
/// table: the shape changed, so the conflict belongs to `server` and is
/// `ModifyModify`. Descending would report `server.port` as an addition.
#[test]
fn a_non_table_base_is_not_descended_into() {
    let base = int_fields(&[("server", 1)]);
    let mut left = InfinityModule::new();
    let port = left.push(Inode::Int(8080));
    let server = left.push(Inode::Table {
        fields: vec![("port".into(), port)],
    });
    let root = left.push(Inode::Table {
        fields: vec![("server".into(), server)],
    });
    left.set_root(Some(root));

    let mut right = InfinityModule::new();
    let port = right.push(Inode::Int(9090));
    let server = right.push(Inode::Table {
        fields: vec![("port".into(), port)],
    });
    let root = right.push(Inode::Table {
        fields: vec![("server".into(), server)],
    });
    right.set_root(Some(root));

    let found = conflicts(merge(&base, &left, &right).expect("merge"));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].field, "server");
    assert_eq!(found[0].kind, ConflictKind::ModifyModify);
}

#[test]
fn annotations_in_a_different_order_do_not_conflict() {
    let mut base = int_fields(&[("a", 1)]);
    let mut left = int_fields(&[("a", 1)]);
    let mut right = int_fields(&[("a", 1)]);
    let base_root = base.root().expect("root");
    let left_root = left.root().expect("root");
    let right_root = right.root().expect("root");
    let intent = active_infinity::AnnotationKind::Intent("first".into());
    let flag = active_infinity::AnnotationKind::AiImmutable(true);
    base.annotate(base_root, intent.clone());
    base.annotate(base_root, flag.clone());
    // Same two annotations, added in the opposite order on each side.
    left.annotate(left_root, flag.clone());
    left.annotate(left_root, intent.clone());
    right.annotate(right_root, intent);
    right.annotate(right_root, flag);

    assert!(
        merge(&base, &left, &right)
            .expect("merge")
            .module()
            .is_some(),
        "annotation insertion order is not a semantic difference"
    );
}

#[test]
fn a_one_sided_extension_is_adopted() {
    let base = int_fields(&[("a", 1)]);
    let left = int_fields(&[("a", 1)]);
    let mut right = int_fields(&[("a", 1)]);
    right.set_extensions(vec![(7, b"extension".to_vec())]);

    let module = merge(&base, &left, &right)
        .expect("merge")
        .into_module()
        .expect("a one-sided extension is adopted");
    assert_eq!(module.extensions(), &[(7, b"extension".to_vec())]);
}

#[test]
fn different_extensions_on_both_sides_conflict() {
    let base = int_fields(&[("a", 1)]);
    let mut left = int_fields(&[("a", 1)]);
    left.set_extensions(vec![(7, b"left".to_vec())]);
    let mut right = int_fields(&[("a", 1)]);
    right.set_extensions(vec![(7, b"right".to_vec())]);

    let found = conflicts(merge(&base, &left, &right).expect("merge"));
    assert_eq!(found[0].field, "<extensions>");
}

/// A secret in one side's provenance must not be comparable as text: an
/// attacker who guesses it would otherwise see the merge turn clean.
#[test]
fn provenance_text_is_compared_redacted() {
    let base = int_fields(&[("a", 1)]);
    let mut left = int_fields(&[("a", 1)]);
    left.set_provenance(Some(Provenance {
        producer: Some("hunter2".into()),
        ..Provenance::default()
    }));
    let mut right = int_fields(&[("a", 1)]);
    let _secret = right.push(Inode::Secret(active_infinity::SecretBytes::from("hunter2")));
    right.set_provenance(Some(Provenance {
        producer: Some("hunter2".into()),
        ..Provenance::default()
    }));

    let found = conflicts(merge(&base, &left, &right).expect("merge"));
    assert_eq!(found[0].field, "<provenance>", "{found:?}");
}

#[test]
fn a_dangling_reference_is_refused_before_any_comparison() {
    let mut bad = InfinityModule::new();
    let dangling = bad.push(Inode::Ref(NodeId::NONE));
    bad.set_root(Some(dangling));
    let good = int_fields(&[("a", 1)]);

    let error = merge(&good, &good, &bad).expect_err("a dangling input is refused");
    assert_eq!(error.code(), "infinity/node-ref", "{error}");
}

/// Two fields that both take a large shared cone must not materialise more than
/// the node ceiling: the import budget is charged across every take.
#[test]
fn the_import_budget_refuses_two_takes_of_a_shared_cone() {
    let half = (MAX_MERGE_NODES / 2) + 1;
    let mut right = InfinityModule::new();
    let mut entries = Vec::with_capacity(half);
    for index in 0..half {
        let value = right.push(Inode::Int(index as i64));
        entries.push((format!("k{index}"), value));
    }
    let cone = right.push(Inode::Table { fields: entries });
    let root = right.push(Inode::Table {
        fields: vec![("a".into(), cone), ("b".into(), cone)],
    });
    right.set_root(Some(root));

    let base = int_fields(&[("a", 1), ("b", 2)]);
    let left = int_fields(&[("a", 1), ("b", 2)]);
    let error = merge(&base, &left, &right).expect_err("the import budget refuses");
    assert_eq!(error.code(), "infinity/limit", "{error}");
    assert!(error.to_string().contains("imported"), "{error}");
}
