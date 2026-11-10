//! Regression tests for INF-INTEROP-01: `from_active_core` duplicated nodes
//! when the core arena was parent-first.
//!
//! The top-level loop in `from_active_core` lowered *every* arena node via
//! `lower_node` without consulting `map` first, so a node already lowered as
//! another node's child was lowered a second time and `map.insert` then
//! pointed at the duplicate while the parent kept referencing the first
//! copy. A caller-built `CoreModule` may legally list a parent before its
//! children (`active-core`'s own parser emits children-first arenas, so the
//! `parse -> bridge` path never hit this); only caller-built modules did.
//!
//! The arenas below are built by hand with `CoreModule::add_node`, which
//! accepts a forward reference: the parent is added first, naming a child id
//! that does not exist yet, and the child is added second.

#![cfg(feature = "active-core")]

use active_core::ir::{
    Module as CoreModule, Node as CoreNode, NodeId as CoreNodeId, Value as CoreValue,
};
use active_infinity::interop::from_active_core;
use active_infinity::{decode, encode, InfinityModule, Inode, NodeId};

/// The single child of the root array node.
fn array_child(module: &InfinityModule, array: NodeId) -> NodeId {
    match module.get(array) {
        Some(Inode::Array { elements }) => {
            assert_eq!(
                elements.len(),
                1,
                "test fixture arrays hold exactly one child"
            );
            elements[0]
        }
        other => panic!("expected an array node at {array}, got {other:?}"),
    }
}

/// The target of a binding by name.
fn binding(module: &InfinityModule, name: &str) -> NodeId {
    module
        .bindings()
        .iter()
        .find(|(bound, _)| bound == name)
        .map(|(_, id)| *id)
        .unwrap_or_else(|| panic!("expected binding {name:?}"))
}

/// The parent-first arena W4 used to confirm INF-INTEROP-01: node 0 is the
/// parent array, node 1 its literal child; the binding `x` names the child
/// and the root is the parent. Before the fix the bridged module held 3
/// nodes (the child twice) and the binding pointed at the duplicate.
fn parent_first_core() -> CoreModule {
    let mut core = CoreModule::new("parent-first.active");
    // Forward reference: node 1 does not exist yet when node 0 is added.
    let parent = core.add_node(CoreNode::Array {
        elements: vec![CoreNodeId(1)],
    });
    assert_eq!(parent, CoreNodeId(0));
    let child = core.add_node(CoreNode::Literal(CoreValue::Int(7)));
    assert_eq!(child, CoreNodeId(1));
    core.bindings.insert("x".to_string(), CoreNodeId(1));
    core.root = Some(CoreNodeId(0));
    core
}

#[test]
fn probe_from_active_core_parent_first() {
    let core = parent_first_core();
    let out = from_active_core(&core).expect("parent-first bridge");
    assert_eq!(
        out.node_count(),
        2,
        "parent-first arena with 2 core nodes must lower to exactly 2 nodes, got {}",
        out.node_count()
    );
    let root = out.root().expect("root is the parent array");
    let parent_child = array_child(&out, root);
    let bound = binding(&out, "x");
    assert_eq!(
        bound, parent_child,
        "binding x must resolve to the node the parent array references, not a duplicate copy"
    );
    assert_eq!(out.get(bound), Some(&Inode::Int(7)));
    // The bytes were already right before the fix (`encode()` silently drops
    // the duplicate per INF-ENCODE-DROP-01 / INF-04); the round-trip pins
    // that the fixed in-memory module and the wire form now agree.
    let bytes = encode(&out).expect("encode bridged module");
    let back = decode(&bytes).expect("decode bridged module");
    assert_eq!(back.node_count(), 2);
    let back_root = back.root().expect("decoded root is the parent array");
    assert_eq!(binding(&back, "x"), array_child(&back, back_root));
    assert_eq!(back.get(binding(&back, "x")), Some(&Inode::Int(7)));
}

/// Control: the same shape with a children-first arena, the order
/// `active-core`'s own parser emits. This passed before the fix and must
/// keep passing — the fix must not change the parser-emitted path.
#[test]
fn children_first_arena_is_unchanged() {
    let mut core = CoreModule::new("children-first.active");
    let child = core.add_node(CoreNode::Literal(CoreValue::Int(7)));
    assert_eq!(child, CoreNodeId(0));
    let parent = core.add_node(CoreNode::Array {
        elements: vec![CoreNodeId(0)],
    });
    assert_eq!(parent, CoreNodeId(1));
    core.bindings.insert("x".to_string(), CoreNodeId(0));
    core.root = Some(CoreNodeId(1));
    let out = from_active_core(&core).expect("children-first bridge");
    assert_eq!(out.node_count(), 2);
    let root = out.root().expect("root is the parent array");
    assert_eq!(binding(&out, "x"), array_child(&out, root));
    assert_eq!(out.get(binding(&out, "x")), Some(&Inode::Int(7)));
}

/// Diamond, parent-first: two parents share one child, which sits last in
/// the arena. Before the fix the top-level loop re-lowered the shared child
/// a second time (4 nodes, binding at the duplicate); after the fix both
/// parents and the binding resolve to the one lowered child.
#[test]
fn shared_child_lowered_once_parent_first() {
    let mut core = CoreModule::new("diamond.active");
    let first = core.add_node(CoreNode::Array {
        elements: vec![CoreNodeId(2)],
    });
    let second = core.add_node(CoreNode::Array {
        elements: vec![CoreNodeId(2)],
    });
    let child = core.add_node(CoreNode::Literal(CoreValue::Int(7)));
    assert_eq!(
        (first, second, child),
        (CoreNodeId(0), CoreNodeId(1), CoreNodeId(2))
    );
    core.bindings.insert("x".to_string(), CoreNodeId(2));
    core.root = Some(CoreNodeId(0));
    let out = from_active_core(&core).expect("diamond bridge");
    assert_eq!(
        out.node_count(),
        3,
        "diamond arena with 3 core nodes must lower to exactly 3 nodes, got {}",
        out.node_count()
    );
    let children: Vec<NodeId> = out
        .nodes()
        .iter()
        .filter_map(|node| match node {
            Inode::Array { elements } => {
                assert_eq!(
                    elements.len(),
                    1,
                    "test fixture arrays hold exactly one child"
                );
                Some(elements[0])
            }
            _ => None,
        })
        .collect();
    assert_eq!(children.len(), 2, "both parents must survive as arrays");
    assert_eq!(
        children[0], children[1],
        "both parents must reference the same lowered child, not two copies"
    );
    assert_eq!(
        binding(&out, "x"),
        children[0],
        "binding x must resolve to the shared child"
    );
    assert_eq!(out.get(children[0]), Some(&Inode::Int(7)));
}
