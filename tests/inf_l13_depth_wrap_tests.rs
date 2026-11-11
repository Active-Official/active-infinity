//! Regression tests for INF-L13: `check_depth`/`ir` depth
//! `depth[node]+1` can wrap in release if `depth == u32::MAX`, and
//! `check_reachability` takes a dead `limits` parameter
//! (`let _ = limits;`).
//!
//! The wrap is unreachable under the default ceilings — depth is bounded
//! by the node count (a longest path in an acyclic graph has at most one
//! node per step), and `Limits::default().max_nodes` is 4M — so no
//! behavioural test can fail before the fix and pass after it. The audit
//! says so itself ("unreachable under max_nodes ... defence-in-depth
//! only"). What these tests pin, through the public API, is the behaviour
//! of the two functions the fix touches, at the exact boundaries the
//! changed lines enforce:
//!
//! * `Validated::check_depth` (wire side, `src/validate.rs`): the
//!   `depth[node] + 1` there becomes `saturating_add(1)`, matching the
//!   `ir.rs` half, which INF-09 already made saturating. A 4096-deep
//!   wire chain still validates, a 4097-deep one is still refused with
//!   `infinity/depth` at the default ceiling, and a 5001-deep one still
//!   validates when the caller raises the ceiling — so the refusal is the
//!   ceiling, not the bytes, and the saturating add changed nothing
//!   observable.
//! * `InfinityModule::check_depth` (in-memory side, `src/ir.rs`): already
//!   saturating since INF-09 (`63ffe90`); the boundary tests pin it so
//!   the two halves can never drift apart again.
//! * `Validated::check_reachability` (wire side): the dead `limits`
//!   parameter is removed — the only call site is `validate()` — and a
//!   hand-assembled wire image carrying an unreachable node is still
//!   refused with `infinity/node` ("unreachable node"), which is the
//!   refusal branch of the function whose signature changes. Removing a
//!   parameter and a `let _ = ...` line cannot change behaviour; the
//!   test proves the branch still fires after the edit.
//!
//! The wrap mechanism itself is demonstrated, not asserted here, by a
//! standalone release-mode probe (see the INF-L13 record §3): with
//! overflow checks off, `u32::MAX + 1` evaluates to `0` — the exact
//! expression the old line used — while `u32::MAX.saturating_add(1)`
//! stays `u32::MAX`, which the `next > limits.max_depth` check then
//! refuses. A wrap would have turned a too-deep chain into a shallow
//! one; saturation fails closed instead.

use active_infinity::layout::{DIALECT_HASH_GOLDEN, HEADER_SIZE};
use active_infinity::{
    decode_with, encode, hash_image, validate, validate_with, DecodeOpts, Error, InfinityModule,
    Inode, Limits, UnOp,
};

#[path = "deep_chain_image.rs"]
mod deep_chain_image;

/// A unary chain of `depth` nodes: the leaf `Int` is depth `depth`, the
/// root `Unary` depth 1. (The INF-09 `chain` helper, same shape.)
fn chain(depth: u32) -> InfinityModule {
    assert!(depth >= 1, "a chain needs at least the leaf node");
    let mut module = InfinityModule::new();
    let mut cur = module.push(Inode::Int(1));
    for _ in 1..depth {
        cur = module.push(Inode::Unary {
            op: UnOp::Neg,
            expr: cur,
        });
    }
    module.set_root(Some(cur));
    module
}

/// Assert `error` is the depth refusal at the default ceiling.
fn assert_depth_refusal(error: &Error) {
    assert_eq!(error.code(), "infinity/depth", "{error}");
    match error {
        Error::Depth { limit } => assert_eq!(
            *limit,
            Limits::default().max_depth,
            "the refusal names the default ceiling"
        ),
        other => panic!("expected Error::Depth, got {other:?}"),
    }
}

#[test]
fn wire_chain_at_the_default_ceiling_validates() {
    // Boundary: depth 4096 is the last depth the ceiling allows, through
    // the wire validator — the exact `check_depth` the fix touches.
    // Lenient options: the hand-built chain image carries no canonical
    // flag, so default `validate()` (which proves canonicality, INF-02)
    // would refuse it with `infinity/not-canonical` after the depth
    // check passes — the depth verdict is what this test pins.
    let lenient = DecodeOpts {
        limits: Limits::default(),
        verify_hash: true,
        verify_canonical: false,
    };
    let bytes = deep_chain_image::build_ref_chain_image(4096);
    validate_with(&bytes, lenient).expect("a depth-4096 wire image validates");
    let decoded = decode_with(&bytes, lenient).expect("a depth-4096 wire image decodes");
    assert_eq!(decoded.node_count(), 4096);
}

#[test]
fn wire_chain_one_past_the_ceiling_is_refused() {
    // Boundary: depth 4097 is the first depth past the ceiling, through
    // the wire validator. The refusal is produced by the `next >
    // limits.max_depth` check immediately after the changed line, so this
    // pins the line's neighbourhood: the saturating add must not move,
    // weaken, or invert that refusal.
    let bytes = deep_chain_image::build_ref_chain_image(4097);
    let error = validate(&bytes).expect_err("default limits refuse depth 4097");
    assert_depth_refusal(&error);
}

#[test]
fn wire_chain_past_the_ceiling_validates_when_the_ceiling_is_raised() {
    // The refusal is the ceiling, not the bytes: the same 5001-deep wire
    // image validates when the caller raises `max_depth`.
    let bytes = deep_chain_image::build_ref_chain_image(5001);
    let raised = DecodeOpts {
        limits: Limits {
            max_depth: 100_000,
            ..Limits::default()
        },
        verify_hash: true,
        verify_canonical: false,
    };
    validate_with(&bytes, raised).expect("a 5001-deep image validates at a 100k ceiling");
}

#[test]
fn second_root_deep_chain_is_still_caught() {
    // `check_depth` starts its sweep at every node with no incoming edge
    // — a module root, a binding target, an annotation subject — so a
    // deep chain reachable only through a binding cannot slip past the
    // ceiling behind a shallow root. The chain head has no incoming edge
    // (bindings are not graph edges), so it is a sweep root and its
    // depth grows to 5000.
    let mut module = InfinityModule::new();
    let mut cur = module.push(Inode::Int(1));
    for _ in 1..5000 {
        cur = module.push(Inode::Unary {
            op: UnOp::Neg,
            expr: cur,
        });
    }
    let shallow = module.push(Inode::Str("shallow".into()));
    module.set_root(Some(shallow));
    module.bind("deep", cur);
    let error = encode(&module).expect_err("a binding-fed 5000-deep chain must be refused");
    assert_depth_refusal(&error);
}

#[test]
fn ir_check_depth_boundary_is_unchanged() {
    // The `ir.rs` half is already saturating (INF-09); these pin it so
    // the two halves agree at the boundary and can never drift apart.
    chain(4096)
        .check_depth(4096)
        .expect("depth 4096 under a 4096 ceiling");
    let error = chain(4097)
        .check_depth(4096)
        .expect_err("depth 4097 past a 4096 ceiling");
    assert_depth_refusal(&error);
    chain(4097)
        .check_depth(5000)
        .expect("depth 4097 under a 5000 ceiling");
}

fn align8(value: usize) -> usize {
    value.saturating_add(7) & !7
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// A wire image of two `Int` nodes where only node 0 is reachable: the
/// root word names node 0, there are no edges, and node 1 (`Int(1)`) is
/// an orphan. Layout mirrors `deep_chain_image::assemble` (itself
/// verbatim the `working_budget_tests.rs` INF-06 assembler): `HEADER_SIZE`
/// 224, section order `Section::ALL`, node records 32 bytes, Blake3
/// content hash over the image with the hash field zeroed.
fn build_unreachable_node_image() -> Vec<u8> {
    // Nodes: 32 bytes each — kind, 3 flag bytes (0), aux u32, a/b/c u64.
    let mut nodes = Vec::with_capacity(2 * 32);
    for value in [0u64, 1u64] {
        nodes.push(2u8);
        nodes.extend_from_slice(&[0u8; 3]);
        push_u32(&mut nodes, 0);
        push_u64(&mut nodes, value);
        push_u64(&mut nodes, 0);
        push_u64(&mut nodes, 0);
    }
    // Bindings: one root word (node 0), then zero name/node pairs.
    let mut bindings = Vec::with_capacity(8);
    push_u32(&mut bindings, 0);
    push_u32(&mut bindings, 0);

    let empty: Vec<u8> = Vec::new();
    let bodies: [&[u8]; 17] = [
        &nodes, &empty, // children
        &empty, // fields
        &empty, // parts
        &empty, // edges
        &empty, // strings
        &empty, // blobs
        &empty, // annotations
        &empty, // provenance
        &empty, // extensions
        &empty, // units
        &empty, // types
        &empty, // aux
        &empty, // numbers
        &empty, // secrets
        &empty, // hashes
        &bindings,
    ];
    let counts: [u32; 17] = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut image = vec![0u8; HEADER_SIZE];
    image[0..4].copy_from_slice(b"AINF");
    image[4..6].copy_from_slice(&1u16.to_le_bytes());
    image[6..8].copy_from_slice(&1u16.to_le_bytes());
    image[8..10].copy_from_slice(&0u16.to_le_bytes());
    image[10..12].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
    image[48..56].copy_from_slice(&DIALECT_HASH_GOLDEN.to_le_bytes());
    let mut cursor = HEADER_SIZE;
    let mut offsets = [0u32; 17];
    for (index, body) in bodies.iter().enumerate() {
        cursor = align8(cursor);
        offsets[index] = cursor as u32;
        image.extend_from_slice(body);
        while image.len() % 8 != 0 {
            image.push(0);
        }
        cursor = image.len();
    }
    let total_size = image.len() as u64;
    image[56..64].copy_from_slice(&total_size.to_le_bytes());
    for (index, span) in offsets.iter().enumerate() {
        let base = 64 + index * 8;
        image[base..base + 4].copy_from_slice(&span.to_le_bytes());
        image[base + 4..base + 8].copy_from_slice(&counts[index].to_le_bytes());
    }
    let hash = hash_image(&image).expect("hash a well-formed image");
    image[16..48].copy_from_slice(&hash);
    image
}

#[test]
fn wire_image_with_an_unreachable_node_is_refused() {
    // The refusal branch of `Validated::check_reachability` — the
    // function whose dead `limits` parameter the fix removes — driven
    // through the public `validate()` API. Node 1 is reachable from
    // nothing: not the root, not a binding, not an annotation.
    let bytes = build_unreachable_node_image();
    let error = validate(&bytes).expect_err("an unreachable node must be refused");
    assert_eq!(error.code(), "infinity/node", "{error}");
    let message = error.to_string();
    match error {
        Error::Node { id, reason } => {
            assert_eq!(id, 1, "the refused node is the orphan");
            assert_eq!(reason, "unreachable node", "{message}");
        }
        other => panic!("expected Error::Node, got {other:?}"),
    }
}

#[test]
fn wire_chain_of_two_validates() {
    // The accept side of the same check: a two-node chain where every
    // node is reachable from the root still validates, so the fix does
    // not over-refuse. Lenient options, as in
    // `wire_chain_at_the_default_ceiling_validates`: the hand-built
    // image carries no canonical flag.
    let lenient = DecodeOpts {
        limits: Limits::default(),
        verify_hash: true,
        verify_canonical: false,
    };
    let bytes = deep_chain_image::build_ref_chain_image(2);
    validate_with(&bytes, lenient).expect("a reachable two-node chain validates");
}
