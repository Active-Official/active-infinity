//! Host tests for the fuzz helpers, compiled from the same source file the
//! fuzz targets include.
//!
//! A helper that silently returns an empty list disables every oracle built on
//! it: the graph-cycle lane passed thousands of runs because `table_children`
//! read the wrong section and `repoint_ref` never matched an edge.

#[path = "../fuzz/fuzz_targets/common.rs"]
mod common;

use active_infinity::{decode, encode, validate, InfinityModule, Inode};

/// A root table over a `Ref` chain, with the ids the encoder assigns.
fn ring() -> (Vec<u8>, u32, u32) {
    let mut module = InfinityModule::new();
    let leaf = module.push(Inode::Int(7));
    let head = module.push(Inode::Ref(leaf));
    let root = module.push(Inode::Table {
        fields: vec![("head".into(), head), ("leaf".into(), leaf)],
    });
    module.set_root(Some(root));
    let image = encode(&module).expect("ring encodes");
    let decoded = decode(&image).expect("ring decodes");
    let root_id = decoded.root().expect("root").0;
    // Canonical encoding renumbers the arena, so take the `head` field's id
    // from the decoded root rather than the pre-encode construction.
    let head_id = match decoded.get(decoded.root().expect("root")) {
        Some(Inode::Table { fields }) => fields
            .iter()
            .find(|(name, _)| name == "head")
            .map(|(_, id)| id.0)
            .expect("the head field"),
        _ => panic!("the root is a table"),
    };
    (image, root_id, head_id)
}

#[test]
fn table_children_reads_the_fields_section() {
    let (image, root_id, head_id) = ring();
    let children = common::table_children(&image, root_id);
    assert_eq!(children.len(), 2, "a two-field table has two children");

    let decoded = decode(&image).expect("decode");
    let mut expected: Vec<u32> = match decoded.get(decoded.root().expect("root")) {
        Some(Inode::Table { fields }) => fields.iter().map(|(_, id)| id.0).collect(),
        _ => panic!("the root is a table"),
    };
    expected.sort_unstable();
    let mut actual = children.clone();
    actual.sort_unstable();
    assert_eq!(actual, expected);
    assert!(children.contains(&head_id), "{children:?}");
}

#[test]
fn repoint_ref_rewrites_the_edge_and_forms_a_cycle() {
    let (image, _root, head) = ring();
    let mut mutated = image.clone();
    assert!(
        common::repoint_ref(&mut mutated, head, head),
        "the helper must find and replace the Ref edge"
    );
    let error = validate(&mutated).expect_err("a self-loop is refused");
    assert_eq!(error.code(), "infinity/cycle", "{error}");
}

/// A refused repoint must leave the image byte-identical: the helper is used
/// inside a fuzz campaign where a half-mutated buffer would poison the oracle.
#[test]
fn a_failed_repoint_leaves_the_buffer_unchanged() {
    let (image, root, _head) = ring();
    let mut copy = image.clone();
    assert!(
        !common::repoint_ref(&mut copy, root, root),
        "the root is a table"
    );
    assert_eq!(copy, image);
}
