//! Hand-built wire image of a `Ref` chain, shared by the depth tests.
//!
//! The encoder refuses modules deeper than `Limits::default().max_depth`
//! (INF-09), so a test that needs a *wire image* deeper than the ceiling
//! cannot build it with `encode()` — it must hand-roll the bytes. The
//! layout mirrors `tests/working_budget_tests.rs` (INF-06: `HEADER_SIZE`
//! 224, section order `Section::ALL`, node records 32 bytes, Blake3
//! content hash over the image with the hash field zeroed).
//!
//! Shape: node 0 is `Int(0)` (kind 2, `a` = value); node `i >= 1` is
//! `Ref(i - 1)` (kind 11, `a` = target); the edge table is exactly the
//! derived set `(child, referencer)` — `Ref(i)` contributes `(i - 1, i)`;
//! the root is the last node. Depth equals the node count: the root is
//! depth 1, the leaf `Int` depth `node_count`. All other sections are
//! empty. Test files include this one with
//! `#[path = "deep_chain_image.rs"] mod deep_chain_image;`.

use active_infinity::hash_image;
use active_infinity::layout::{DIALECT_HASH_GOLDEN, HEADER_SIZE};

fn align8(value: usize) -> usize {
    value.saturating_add(7) & !7
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Build a wire image whose module is a `Ref` chain of `depth` nodes
/// (depth == node count), root the last node, no other sections.
///
/// `depth` must be at least 1 (a lone `Int` leaf). The image is
/// structurally valid for any depth the caller's limits allow: the
/// content hash is stamped, the edge table is exactly the derived set,
/// and every node is reachable from the root.
pub fn build_ref_chain_image(depth: u32) -> Vec<u8> {
    assert!(depth >= 1, "a chain needs at least the leaf node");
    let count = depth as usize;

    // Nodes: 32 bytes each — kind, 3 flag bytes (0), aux u32, a/b/c u64.
    // `Int(0)`: kind 2, a = 0. `Ref(target)`: kind 11, a = target.
    let mut nodes = Vec::with_capacity(count * 32);
    nodes.push(2u8);
    nodes.extend_from_slice(&[0u8; 3]);
    push_u32(&mut nodes, 0);
    push_u64(&mut nodes, 0);
    push_u64(&mut nodes, 0);
    push_u64(&mut nodes, 0);
    for target in 0..count - 1 {
        nodes.push(11u8);
        nodes.extend_from_slice(&[0u8; 3]);
        push_u32(&mut nodes, 0);
        push_u64(&mut nodes, target as u64);
        push_u64(&mut nodes, 0);
        push_u64(&mut nodes, 0);
    }

    // Edges: exactly the derived set, strictly increasing. A stored row is
    // (child, referencer) — `check_edges` derives `(child, index)` per
    // node — so `Ref(i)` over child `i - 1` contributes `(i - 1, i)`.
    let mut edges = Vec::with_capacity((count - 1) * 8);
    for referencer in 1..count {
        push_u32(&mut edges, (referencer - 1) as u32);
        push_u32(&mut edges, referencer as u32);
    }

    // Bindings: one root word, then zero name/node pairs.
    let mut bindings = Vec::with_capacity(8);
    push_u32(&mut bindings, (count - 1) as u32);
    push_u32(&mut bindings, 0);

    // Section bodies in `Section::ALL` order; everything else is empty.
    let empty: Vec<u8> = Vec::new();
    let bodies: [&[u8]; 17] = [
        &nodes, &empty, // children
        &empty, // fields
        &empty, // parts
        &edges, &empty, // strings
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
    let counts: [u32; 17] = [
        depth,
        0,
        0,
        0,
        (count - 1) as u32,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
    ];
    assemble(&bodies, &counts)
}

/// Lay section bodies out after the header and stamp the content hash.
/// Verbatim the `working_budget_tests.rs` (INF-06) assembler.
fn assemble(bodies: &[&[u8]; 17], counts: &[u32; 17]) -> Vec<u8> {
    let mut image = vec![0u8; HEADER_SIZE];
    image[0..4].copy_from_slice(b"AINF");
    image[4..6].copy_from_slice(&1u16.to_le_bytes());
    image[6..8].copy_from_slice(&1u16.to_le_bytes());
    image[8..10].copy_from_slice(&0u16.to_le_bytes());
    image[10..12].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
    // [12..16] reserved zero; [16..48] content hash, patched below.
    image[48..56].copy_from_slice(&DIALECT_HASH_GOLDEN.to_le_bytes());
    let mut cursor = HEADER_SIZE;
    let mut offsets = [0u32; 17];
    for (index, body) in bodies.iter().enumerate() {
        cursor = align8(cursor);
        offsets[index] = cursor as u32;
        image.extend_from_slice(body);
        // Zero padding to the next 8-byte boundary.
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
    // The hash covers the whole image with the hash field zeroed.
    let hash = hash_image(&image).expect("hash a well-formed image");
    image[16..48].copy_from_slice(&hash);
    image
}
