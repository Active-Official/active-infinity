//! Three-way merge: clean merges produce a canonical module, and every
//! incompatible change reports its typed conflict.

use std::collections::BTreeMap;

use active_infinity::{
    content_hash, decode, encode, merge, ConflictKind, InfinityModule, Inode, Merge,
};

fn table(fields: &[(&str, Inode)]) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut nodes = Vec::with_capacity(fields.len());
    for (name, node) in fields {
        let id = module.push(node.clone());
        nodes.push(((*name).to_string(), id));
    }
    let root = module.push(Inode::Table { fields: nodes });
    module.set_root(Some(root));
    module
}

fn int_fields(fields: &[(&str, i64)]) -> InfinityModule {
    table(
        &fields
            .iter()
            .map(|(name, value)| (*name, Inode::Int(*value)))
            .collect::<Vec<_>>(),
    )
}

fn ints(module: &InfinityModule) -> BTreeMap<String, i64> {
    let root = module.root().expect("root");
    let Inode::Table { fields } = module.get(root).expect("root node") else {
        panic!("root is not a table");
    };
    fields
        .iter()
        .map(|(name, id)| {
            let Inode::Int(value) = module.get(*id).expect("value") else {
                panic!("field {name} is not an int");
            };
            (name.clone(), *value)
        })
        .collect()
}

fn clean(result: Merge) -> InfinityModule {
    match result.into_module() {
        Some(module) => module,
        None => panic!("unexpected conflicts"),
    }
}

fn conflicts(result: Merge) -> Vec<active_infinity::Conflict> {
    match result {
        Merge::Clean(_) => panic!("expected conflicts"),
        Merge::Conflicts(conflicts) => conflicts,
    }
}

#[test]
fn a_clean_merge_takes_each_sides_change() {
    let base = int_fields(&[("a", 1), ("b", 2), ("c", 3)]);
    let left = int_fields(&[("a", 10), ("b", 2), ("c", 3)]);
    let right = int_fields(&[("a", 1), ("b", 20), ("c", 3)]);
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    let fields = ints(&merged);
    assert_eq!(fields["a"], 10);
    assert_eq!(fields["b"], 20);
    assert_eq!(fields["c"], 3);
}

#[test]
fn identical_changes_merge_once() {
    let base = int_fields(&[("a", 1)]);
    let left = int_fields(&[("a", 5)]);
    let right = int_fields(&[("a", 5)]);
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(ints(&merged)["a"], 5);
}

#[test]
fn an_add_on_one_side_is_taken() {
    let base = int_fields(&[("a", 1)]);
    let left = int_fields(&[("a", 1), ("b", 2)]);
    let right = int_fields(&[("a", 1)]);
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(ints(&merged)["b"], 2);
}

#[test]
fn the_same_addition_on_both_sides_is_clean() {
    let base = int_fields(&[("a", 1)]);
    let left = int_fields(&[("a", 1), ("d", 4)]);
    let right = int_fields(&[("a", 1), ("d", 4)]);
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(ints(&merged)["d"], 4);
}

#[test]
fn different_additions_conflict() {
    let base = int_fields(&[("a", 1)]);
    let left = int_fields(&[("a", 1), ("d", 4)]);
    let right = int_fields(&[("a", 1), ("d", 5)]);
    let conflicts = conflicts(merge(&base, &left, &right).expect("merge"));
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].field, "d");
    assert_eq!(conflicts[0].kind, ConflictKind::AddAdd);
}

#[test]
fn different_modifications_conflict() {
    let base = int_fields(&[("a", 1)]);
    let left = int_fields(&[("a", 2)]);
    let right = int_fields(&[("a", 3)]);
    let conflicts = conflicts(merge(&base, &left, &right).expect("merge"));
    assert_eq!(conflicts[0].field, "a");
    assert_eq!(conflicts[0].kind, ConflictKind::ModifyModify);
}

#[test]
fn delete_versus_modify_conflicts() {
    let base = int_fields(&[("a", 1), ("b", 2)]);
    let left = int_fields(&[("b", 2)]);
    let right = int_fields(&[("a", 9), ("b", 2)]);
    let conflicts = conflicts(merge(&base, &left, &right).expect("merge"));
    assert_eq!(conflicts[0].field, "a");
    assert_eq!(conflicts[0].kind, ConflictKind::DeleteModify);
}

#[test]
fn a_delete_on_one_side_wins_over_an_unchanged_field() {
    let base = int_fields(&[("a", 1), ("b", 2)]);
    let left = int_fields(&[("b", 2)]);
    let right = int_fields(&[("a", 1), ("b", 2)]);
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    let fields = ints(&merged);
    assert!(!fields.contains_key("a"));
    assert_eq!(fields["b"], 2);
}

#[test]
fn a_non_table_root_is_a_kind_mismatch() {
    let mut base = InfinityModule::new();
    let root = base.push(Inode::Int(1));
    base.set_root(Some(root));
    let left = int_fields(&[("a", 1)]);
    let right = int_fields(&[("a", 1)]);
    let conflicts = conflicts(merge(&base, &left, &right).expect("merge"));
    assert_eq!(conflicts[0].kind, ConflictKind::KindMismatch);
}

#[test]
fn the_merged_module_is_canonical_and_stable() {
    let base = int_fields(&[("a", 1)]);
    let left = int_fields(&[("a", 2), ("left_only", 7)]);
    let right = int_fields(&[("a", 1), ("right_only", 8)]);
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    let image = encode(&merged).expect("encode");
    let decoded = decode(&image).expect("decode");
    assert_eq!(ints(&decoded)["left_only"], 7);
    assert_eq!(ints(&decoded)["right_only"], 8);
    assert_eq!(
        content_hash(&image).expect("hash"),
        content_hash(&encode(&decoded).expect("re-encode")).expect("hash again")
    );
}

#[test]
fn nested_tables_compare_by_content() {
    // Build base { cfg = { x = 1, y = 2 } }, left unchanged, right { x = 1, y = 3 }.
    let nested = |y: i64, z: i64| {
        let mut module = InfinityModule::new();
        let x = module.push(Inode::Int(1));
        let y_node = module.push(Inode::Int(y));
        let z_node = module.push(Inode::Int(z));
        let inner = module.push(Inode::Table {
            fields: vec![
                ("x".to_string(), x),
                ("y".to_string(), y_node),
                ("z".to_string(), z_node),
            ],
        });
        let root = module.push(Inode::Table {
            fields: vec![("cfg".to_string(), inner)],
        });
        module.set_root(Some(root));
        module
    };
    let base = nested(2, 0);
    let left = nested(2, 0);
    let right = nested(3, 0);
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    let root = merged.root().expect("root");
    let Inode::Table { fields } = merged.get(root).expect("root node") else {
        panic!("root");
    };
    let cfg = fields
        .iter()
        .find(|(name, _)| name == "cfg")
        .expect("cfg")
        .1;
    let Inode::Table { fields: inner } = merged.get(cfg).expect("cfg node") else {
        panic!("cfg");
    };
    let y = inner.iter().find(|(name, _)| name == "y").expect("y").1;
    assert_eq!(merged.get(y), Some(&Inode::Int(3)));
}

#[test]
fn a_conflict_returns_no_module() {
    let base = int_fields(&[("a", 1)]);
    let left = int_fields(&[("a", 2)]);
    let right = int_fields(&[("a", 3)]);
    let result = merge(&base, &left, &right).expect("merge");
    assert!(result.module().is_none());
    assert_eq!(result.conflicts().len(), 1);
}

/// Module metadata is not combined by the field merge. A difference between the
/// two sides is a conflict named after the component, so no side's change is
/// dropped silently.
#[test]
fn a_binding_difference_is_a_conflict_not_a_silent_choice() {
    let base = int_fields(&[("a", 1)]);
    let left = int_fields(&[("a", 1)]);
    let mut right = int_fields(&[("a", 1)]);
    let root = right.root().expect("root");
    right.bind("extra", root);

    match merge(&base, &left, &right).expect("merge") {
        Merge::Conflicts(conflicts) => {
            assert_eq!(conflicts.len(), 1, "{conflicts:?}");
            assert_eq!(conflicts[0].field, "<bindings>");
            assert_eq!(conflicts[0].kind, ConflictKind::KindMismatch);
        }
        Merge::Clean(_) => panic!("a binding difference must not merge cleanly"),
    }
}

#[test]
fn a_provenance_difference_is_a_conflict() {
    use active_infinity::Provenance;

    let base = int_fields(&[("a", 1)]);
    let left = int_fields(&[("a", 1)]);
    let mut right = int_fields(&[("a", 1)]);
    right.set_provenance(Some(Provenance {
        producer: Some("agent-b".into()),
        ..Provenance::default()
    }));

    match merge(&base, &left, &right).expect("merge") {
        Merge::Conflicts(conflicts) => assert_eq!(conflicts[0].field, "<provenance>"),
        Merge::Clean(_) => panic!("a provenance difference must not merge cleanly"),
    }
    // Both sides agreeing on the metadata is not a conflict.
    let mut twin = int_fields(&[("a", 1)]);
    twin.set_provenance(right.provenance().cloned());
    assert!(merge(&base, &twin, &right)
        .expect("merge")
        .module()
        .is_some());
}

/// Equality of secrets is an oracle (`SECURITY.md` I-2). A field whose subtree
/// reaches a secret conflicts even when both sides are byte-identical, so the
/// outcome never reveals whether two secrets match.
#[test]
fn a_secret_field_never_merges_cleanly_even_when_both_sides_agree() {
    use active_infinity::SecretBytes;

    let base = table(&[("s", Inode::Str("plain".into()))]);
    let left = table(&[("s", Inode::Secret(SecretBytes::new(b"hunter2".to_vec())))]);
    let right = table(&[("s", Inode::Secret(SecretBytes::new(b"hunter2".to_vec())))]);

    match merge(&base, &left, &right).expect("merge") {
        Merge::Conflicts(conflicts) => {
            assert_eq!(conflicts[0].field, "s");
            assert_eq!(conflicts[0].kind, ConflictKind::ModifyModify);
        }
        Merge::Clean(_) => panic!("a secret field must not merge cleanly"),
    }

    // A secret on only one side is also a conflict.
    let plain = table(&[("s", Inode::Str("plain".into()))]);
    match merge(&base, &left, &plain).expect("merge") {
        Merge::Conflicts(conflicts) => assert_eq!(conflicts[0].kind, ConflictKind::ModifyModify),
        Merge::Clean(_) => panic!("a one-sided secret must not merge cleanly"),
    }

    // An unrelated field still merges while another field holds a secret: the
    // walk is over the compared subtree, not the whole module.
    let base = table(&[("s", Inode::Str("plain".into())), ("n", Inode::Int(1))]);
    let left = table(&[
        ("s", Inode::Secret(SecretBytes::new(b"a".to_vec()))),
        ("n", Inode::Int(2)),
    ]);
    let right = table(&[
        ("s", Inode::Secret(SecretBytes::new(b"a".to_vec()))),
        ("n", Inode::Int(1)),
    ]);
    // The secret field conflicts; the merge still reports only that field.
    let conflicts = match merge(&base, &left, &right).expect("merge") {
        Merge::Conflicts(conflicts) => conflicts,
        Merge::Clean(_) => panic!("the secret field must conflict"),
    };
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].field, "s");
}

/// The merge bounds its own work: a module past the node ceiling is refused
/// before any canonical form is computed.
#[test]
fn a_module_over_the_merge_ceiling_is_refused() {
    use active_infinity::merge::MAX_MERGE_NODES;

    let mut big = InfinityModule::new();
    for _ in 0..=MAX_MERGE_NODES {
        big.push(Inode::Int(0));
    }
    let error = merge(&big, &big, &big).expect_err("the node ceiling must refuse");
    assert_eq!(error.code(), "infinity/limit");
    assert!(error.to_string().contains("merge node count"), "{error}");
}

fn bound_module(root_fields: &[(&str, i64)], bound: i64) -> InfinityModule {
    let mut module = int_fields(root_fields);
    let target = module.push(Inode::Int(bound));
    module.bind("b", target);
    module
}

/// A binding retarget between two nodes with the same shape but different
/// values used to compare equal by canonical position, so the merge kept the
/// left binding and dropped the right side's change.
#[test]
fn a_binding_retarget_with_a_different_value_is_a_conflict() {
    let base = int_fields(&[("a", 1)]);
    let left = bound_module(&[("a", 1)], 100);
    let right = bound_module(&[("a", 1)], 200);
    match merge(&base, &left, &right).expect("merge") {
        Merge::Conflicts(conflicts) => {
            assert_eq!(conflicts[0].field, "<bindings>", "{conflicts:?}");
        }
        Merge::Clean(_) => panic!("a retargeted binding must not merge cleanly"),
    }
}

/// Identical bindings must not conflict just because one side added a field:
/// the added node shifts canonical numbering, which the positional comparison
/// mistook for a metadata change.
#[test]
fn an_unrelated_field_change_does_not_conflict_on_identical_bindings() {
    let base = bound_module(&[("a", 1)], 7);
    let left = bound_module(&[("a", 2)], 7);
    let right = bound_module(&[("a", 1), ("c", 3)], 7);
    let merged = merge(&base, &left, &right).expect("merge");
    let module = merged.module().expect("a clean merge");
    let fields = ints(module);
    assert_eq!(fields.get("a"), Some(&2));
    assert_eq!(fields.get("c"), Some(&3));
}
