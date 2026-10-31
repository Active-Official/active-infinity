//! Marathon section I-03: canonical form.
//!
//! `tests/marathon_layout_tests.rs` and `tests/marathon_validate_tests.rs` cover
//! the wire rules; this file covers identity: the same logical module must encode
//! to the same bytes whatever order its arena was built in.

use active_infinity::{encode, InfinityModule, Inode};

/// The same logical module: a table `{a: 1}` plus two values reachable only
/// through bindings (`y` → 8, `z` → 9), with those values pushed in opposite
/// orders. Only the binding roots can order them, so this is where the arena's
/// construction order used to leak into the canonical bytes.
fn module(values_reversed: bool) -> InfinityModule {
    let mut module = InfinityModule::new();
    let one = module.push(Inode::Int(1));
    let (y_value, z_value) = if values_reversed {
        let z = module.push(Inode::Int(9));
        let y = module.push(Inode::Int(8));
        (y, z)
    } else {
        let y = module.push(Inode::Int(8));
        let z = module.push(Inode::Int(9));
        (y, z)
    };
    let root = module.push(Inode::Table {
        fields: vec![("a".to_string(), one)],
    });
    module.set_root(Some(root));
    module.bind("y", y_value);
    module.bind("z", z_value);
    module
}

#[test]
fn arena_order_does_not_change_the_canonical_bytes() {
    // Canonical numbering used to order the binding roots by numeric node id, so
    // the arena's construction order leaked into the image: two modules with the
    // same content had two hashes.
    let forward = encode(&module(false)).expect("encode forward");
    let reversed = encode(&module(true)).expect("encode reversed");
    assert_eq!(
        forward, reversed,
        "the same module must have one canonical encoding"
    );
}

#[test]
fn arena_order_does_not_change_module_equality() {
    assert_eq!(
        module(false),
        module(true),
        "structural equality is over the canonical form"
    );
}

#[test]
fn the_canonical_encoding_is_stable_across_repetition() {
    let image = encode(&module(false)).expect("encode");
    let decoded = active_infinity::decode(&image).expect("decode");
    let again = encode(&decoded).expect("re-encode");
    assert_eq!(
        image, again,
        "decode then encode is the identity on an image"
    );
    active_infinity::validate_canonical(&image, active_infinity::Limits::default())
        .expect("the encoding is canonical");
}
