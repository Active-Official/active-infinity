//! C-3.3 delta canonicalization: an in-place fragment replacement changes the
//! canonical hash exactly as the whole-image delta hash predicts.

use active_infinity::stream::{apply_delta, apply_delta_in_place, delta_hash, DeltaOp};
use active_infinity::{content_hash, encode, validate, InfinityModule, Inode};

fn base() -> (InfinityModule, active_infinity::ir::NodeId) {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("gateway".into()));
    let port = module.push(Inode::Int(8080));
    let root = module.push(Inode::Table {
        fields: vec![("name".into(), name), ("port".into(), port)],
    });
    module.set_root(Some(root));
    (module, port)
}

fn fragment(value: i64) -> InfinityModule {
    let mut fragment = InfinityModule::new();
    let root = fragment.push(Inode::Int(value));
    fragment.set_root(Some(root));
    fragment
}

#[test]
fn delta_replacement_updates_the_hash_and_matches_the_projection() {
    let (base, target) = base();
    let ops = vec![DeltaOp::PutNode {
        target,
        fragment: Box::new(fragment(9090)),
    }];
    let mut updated = base.clone();
    apply_delta_in_place(&mut updated, &ops).expect("in-place delta");
    let image = encode(&updated).expect("encode");
    validate(&image).expect("validate");
    let new_hash = content_hash(&image).expect("hash");
    assert_ne!(
        new_hash,
        content_hash(&encode(&base).expect("base")).expect("base hash")
    );
    assert_eq!(delta_hash(&base, &ops).expect("delta hash"), new_hash);

    let cloned = apply_delta(&base, &ops).expect("clone delta");
    assert_eq!(cloned, updated);
}

#[test]
fn a_large_patch_keeps_the_rest_of_the_graph() {
    let mut module = InfinityModule::new();
    let mut fields = Vec::new();
    for index in 0..1_000 {
        let value = module.push(Inode::Int(index));
        fields.push((format!("field-{index}"), value));
    }
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));
    // The last field is node 999; the root table is node 1000.
    let target = active_infinity::ir::NodeId(999);
    let ops = vec![DeltaOp::PutNode {
        target,
        fragment: Box::new(fragment(-1)),
    }];
    let mut updated = module.clone();
    apply_delta_in_place(&mut updated, &ops).expect("large delta");
    let image = encode(&updated).expect("encode");
    validate(&image).expect("validate");
    assert_eq!(updated.node_count(), module.node_count() + 1);
}
