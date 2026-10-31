//! Node remapping and hash formatting.
//!
//! `canonical::remap_node` is the codec's single implementation for rewriting
//! references into another arena: canonicalization uses it, and a projection
//! (a subgraph carried on the wire) uses it instead of reimplementing the match.
//! `ir::hash_hex` formats every content hash, receipt hash and log head.

#![cfg(feature = "active-core")]

use active_infinity::canonical::remap_node;
use active_infinity::interop::from_active_source;
use active_infinity::ir::{hash_hex, parse_hash_hex};
use active_infinity::{Error, InfinityModule, Inode, NodeId};

const SOURCE: &str = r#"
# @intent: "remap fixture"
[app]
name        = "remap"
environment = env.APP_ENV ?: "test"
routes      = ["/a", "/b"]

let base = "https://api.example.com"
let timeout = 1500ms
let retries = 3

[services]
auth_url    = "${base}/auth"
read_timeout = timeout * 2
scaled      = timeout * retries
token       = secret("remap-canary")

[database]
pool     = 16
password = secret("remap-secret-2")
"#;

fn module() -> InfinityModule {
    from_active_source(SOURCE, "remap.active").expect("parse + lower")
}

#[test]
fn identity_remap_returns_the_same_node() {
    let module = module();
    let remap: Vec<NodeId> = (0..module.node_count() as u32).map(NodeId).collect();
    for (index, node) in module.nodes().iter().enumerate() {
        let mapped = remap_node(node, &remap).expect("identity remap");
        assert_eq!(
            &mapped, node,
            "node {index} changed under an identity remap"
        );
    }
}

#[test]
fn remap_rewrites_every_child_reference() {
    let module = module();
    let count = module.node_count() as u32;
    // Reverse the arena: old id i becomes count - 1 - i.
    let remap: Vec<NodeId> = (0..count).map(|id| NodeId(count - 1 - id)).collect();
    let mut rewritten = 0usize;
    for node in module.nodes() {
        let mapped = remap_node(node, &remap).expect("reverse remap");
        let expected: Vec<NodeId> = node
            .children()
            .iter()
            .map(|child| remap[child.index()])
            .collect();
        assert_eq!(
            mapped.children(),
            expected,
            "a child reference was not rewritten in {node:?}"
        );
        if !expected.is_empty() {
            rewritten += 1;
        }
    }
    assert!(
        rewritten >= 8,
        "the fixture must exercise several child-bearing kinds, saw {rewritten}"
    );
}

#[test]
fn remap_keeps_leaf_children_empty() {
    for node in [
        Inode::Null,
        Inode::Bool(true),
        Inode::Int(-7),
        Inode::Float(0.5),
        Inode::Str("text".to_string()),
        Inode::DurationMs(1500),
        Inode::Ident("name".to_string()),
    ] {
        let remap = vec![NodeId::NONE; 4];
        let mapped = remap_node(&node, &remap).expect("leaves remap trivially");
        assert_eq!(mapped, node);
        assert!(mapped.children().is_empty());
    }
}

#[test]
fn a_reference_outside_the_arena_is_refused() {
    let remap = vec![NodeId::NONE; 4];
    let node = Inode::Ref(NodeId(2));
    let error = remap_node(&node, &remap).expect_err("a dropped node is dangling");
    assert!(matches!(error, Error::EncodeDangling(_)), "{error:?}");

    // A partial arena keeps the nodes it includes and refuses the rest.
    let mut remap = vec![NodeId::NONE; 4];
    remap[2] = NodeId(0);
    let mapped = remap_node(&node, &remap).expect("a kept node remaps");
    assert_eq!(mapped, Inode::Ref(NodeId(0)));
}

#[test]
fn a_projection_of_a_real_module_encodes() {
    // The shape Active RPC sends for `subgraph`: copy the cone, remap the
    // references, then encode. This is the path that used to leave an
    // interpolation pointing outside the new arena.
    let module = module();
    let root = active_infinity::interop::resolve_path(&module, "services").expect("path");
    let cone = active_infinity::interop::subgraph(&module, &[root]);
    let mut remap = vec![NodeId::NONE; module.node_count()];
    let mut projected = InfinityModule::new();
    for old in &cone {
        remap[old.index()] = projected.push(Inode::Null);
    }
    for (index, old) in cone.iter().enumerate() {
        let node = module.get(*old).expect("cone node");
        let mapped = remap_node(node, &remap).expect("cone is closed");
        *projected.node_mut(NodeId(index as u32)).expect("slot") = mapped;
    }
    projected.set_root(Some(remap[root.index()]));
    let bytes = active_infinity::encode(&projected).expect("projection encodes");
    active_infinity::validate(&bytes).expect("projection validates");
    let decoded = active_infinity::decode(&bytes).expect("decode");
    assert!(decoded
        .nodes()
        .iter()
        .any(|node| matches!(node, Inode::Interpolate { .. })));
}

#[test]
fn hash_hex_is_lowercase_and_round_trips() {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(8).wrapping_add(1);
    }
    let text = hash_hex(&bytes);
    assert_eq!(text.len(), 64);
    assert!(
        text.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "lowercase hex only: {text}"
    );
    assert_eq!(parse_hash_hex(&text), Some(bytes));
}

#[test]
fn hash_hex_matches_known_vectors() {
    assert_eq!(hash_hex(&[0u8; 32]), "0".repeat(64));
    assert_eq!(hash_hex(&[0xffu8; 32]), "ff".repeat(32));
    let counting: [u8; 32] = core::array::from_fn(|index| index as u8);
    assert_eq!(
        hash_hex(&counting),
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
}
