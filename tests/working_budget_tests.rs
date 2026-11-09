//! Regression tests + RSS probe for INF-06 (worst-case allocation at default
//! ceilings: validate + decode is multi-GiB transient).
//!
//! The audit (round 1, W4-R1-INF-CORE) showed `validate()` on a 1 GiB
//! max-size image costs ~600–700 MiB transient on top of the caller's buffer,
//! and `validate_canonical` can exceed 3–4 GiB, because `check_edges`
//! materialises *two* full edge Vecs (`edges` + `derived`, the latter up to
//! ~56M entries / ~448 MiB when node references outnumber the stored edge
//! table) and there is no single memory budget. The fix streams the edge
//! comparison (one `derived` Vec, capped at the stored edge count, compared
//! element-wise against the stored table) and adds `Limits::max_working_bytes`
//! (default 512 MiB), enforced from the header counts before any allocation.
//!
//! The images here are hand-built byte by byte (header + sections + Blake3
//! content hash), not encoder-built: only hand-building can produce the
//! hostile shape (node references far outnumbering the stored edge table),
//! which no encoder output can express, and it gives exact control over
//! section counts. The builder mirrors the wire layout in `src/layout.rs`
//! (`HEADER_SIZE` 224, section order `Section::ALL`, node records 32 bytes,
//! `hash_image` over `[..16] + 32 zero bytes + [48..]`).
//!
//! The RSS legs run the validation in a subprocess (`examples/inf06_probe`)
//! so the reported peak covers only the validate call: the test process holds
//! the image bytes and other tests allocate concurrently, so an in-process
//! peak would be meaningless. Both legs use the structural check
//! (`verify_canonical: false`): the canonical proof is a separate decode +
//! re-encode allocation story (decode side bounded by INF-01's
//! `max_decoded_bytes`, encode side builds a second full image) and is
//! measured separately, not asserted here.
//!
//! Shapes (both at the default ceilings: 4,194,304 nodes, ~16.7M edges):
//! * **hostile**: 37,748,727 node references (16.7M children + 16.7M fields +
//!   4.2M interpolation expressions) against a 16,777,216-row edge table.
//!   Pre-fix `check_edges` pushes all 37.7M pairs into `derived` (growth
//!   realloc 33.5M -> 67.1M entries = 268 + 537 MiB alive at once) on top of
//!   the 128 MiB `edges` Vec and the 608 MiB input buffer: peak RSS ~1.5 GiB,
//!   over `input + 512 MiB`. Post-fix the per-node dedup collapses the
//!   duplicate references, `derived` is capped at the stored count, and the
//!   image is refused with `infinity/edge-set` at ~660 MiB peak.
//! * **valid**: a 2048-layer DAG, 4,194,304 array nodes, 16,769,024 distinct
//!   derived pairs exactly equal to the stored edge table, depth 2048 (under
//!   the 4096 ceiling), every node reachable from the root and the 2048
//!   layer-0 bindings. It must validate before and after the fix; the peak
//!   drops from ~760 MiB to ~570 MiB.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use active_infinity::layout::{DIALECT_HASH_GOLDEN, HEADER_SIZE};
use active_infinity::{
    encode, hash_image, validate_with, DecodeOpts, Error, InfinityModule, Inode, Limits, ProvEntry,
    ProvValue, Provenance,
};

/// Structural-only options: hash verified, canonical proof off. The proof is
/// a separate allocation story (see the module docs); these tests pin the
/// structural validator the INF-06 fix changes.
fn structural_opts() -> DecodeOpts {
    DecodeOpts {
        verify_canonical: false,
        ..DecodeOpts::default()
    }
}

/// The INF-06 working budget: validate's own transient must fit in it, so a
/// max-shape image validates with peak RSS at most `input + 512 MiB`.
const WORKING_BUDGET_MIB: u64 = 512;

// ---------------------------------------------------------------------------
// Hand-rolled image builder
// ---------------------------------------------------------------------------

/// One node record: kind byte, flags byte (always 0 here), aux u32, a/b/c u64.
#[derive(Clone, Copy)]
struct NodeSpec {
    kind: u8,
    aux: u32,
    a: u64,
    b: u64,
    c: u64,
}

fn node(kind: u8, aux: u32, a: u64, b: u64, c: u64) -> NodeSpec {
    NodeSpec { kind, aux, a, b, c }
}

/// A whole image described section by section. Only the sections the builder
/// is asked to fill are non-empty; the rest are empty (offset = cursor,
/// count = 0), which `validate_layout` accepts.
struct Spec {
    nodes: Vec<NodeSpec>,
    children: Vec<u32>,
    fields: Vec<(u32, u32)>,
    parts: Vec<(u32, u32)>,
    edges: Vec<(u32, u32)>,
    strings: Vec<String>,
    root: u32,
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

/// Serialise one section body, in wire order. Sections are laid out
/// consecutively from the header, each 8-aligned with zero padding, and
/// `total_size` is the aligned end — exactly what `validate_layout` demands.
fn build_image(spec: &Spec) -> Vec<u8> {
    // Section bodies in `Section::ALL` order. Empty sections are empty vecs.
    let mut nodes = Vec::with_capacity(spec.nodes.len() * 32);
    for rec in &spec.nodes {
        nodes.push(rec.kind);
        nodes.push(0);
        nodes.push(0);
        nodes.push(0);
        push_u32(&mut nodes, rec.aux);
        push_u64(&mut nodes, rec.a);
        push_u64(&mut nodes, rec.b);
        push_u64(&mut nodes, rec.c);
    }
    let mut children = Vec::with_capacity(spec.children.len() * 4);
    for child in &spec.children {
        push_u32(&mut children, *child);
    }
    let mut fields = Vec::with_capacity(spec.fields.len() * 16);
    for (name, node) in &spec.fields {
        push_u32(&mut fields, *name);
        push_u32(&mut fields, 0);
        push_u32(&mut fields, *node);
        push_u32(&mut fields, 0);
    }
    let mut parts = Vec::with_capacity(spec.parts.len() * 8);
    for (tag, value) in &spec.parts {
        push_u32(&mut parts, *tag);
        push_u32(&mut parts, *value);
    }
    let mut edges = Vec::with_capacity(spec.edges.len() * 8);
    for (from, to) in &spec.edges {
        push_u32(&mut edges, *from);
        push_u32(&mut edges, *to);
    }
    // Strings: offset table of count+1 u32s (cumulative ends), then the heap.
    // A zero-count strings section is EMPTY on the wire: `section_end`
    // returns the offset itself for count 0, so no table word is written.
    let mut strings = Vec::new();
    if !spec.strings.is_empty() {
        let mut heap = Vec::new();
        let mut ends = Vec::with_capacity(spec.strings.len() + 1);
        ends.push(0u32);
        for text in &spec.strings {
            heap.extend_from_slice(text.as_bytes());
            ends.push(heap.len() as u32);
        }
        for end in &ends {
            push_u32(&mut strings, *end);
        }
        strings.extend_from_slice(&heap);
    }
    let blobs: Vec<u8> = Vec::new();
    let annotations: Vec<u8> = Vec::new();
    let provenance: Vec<u8> = Vec::new();
    let extensions: Vec<u8> = Vec::new();
    let units: Vec<u8> = Vec::new();
    let types: Vec<u8> = Vec::new();
    let aux: Vec<u8> = Vec::new();
    let numbers: Vec<u8> = Vec::new();
    let secrets: Vec<u8> = Vec::new();
    let hashes: Vec<u8> = Vec::new();
    let mut bindings = Vec::with_capacity(8);
    push_u32(&mut bindings, spec.root);
    push_u32(&mut bindings, 0);

    let bodies: [&[u8]; 17] = [
        &nodes,
        &children,
        &fields,
        &parts,
        &edges,
        &strings,
        &blobs,
        &annotations,
        &provenance,
        &extensions,
        &units,
        &types,
        &aux,
        &numbers,
        &secrets,
        &hashes,
        &bindings,
    ];
    let counts: [u32; 17] = [
        spec.nodes.len() as u32,
        spec.children.len() as u32,
        spec.fields.len() as u32,
        spec.parts.len() as u32,
        spec.edges.len() as u32,
        spec.strings.len() as u32,
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

// ---------------------------------------------------------------------------
// Small edge-set semantics tests (must pass identically before and after the
// streaming rewrite: same errors, same accepted images)
// ---------------------------------------------------------------------------

/// Three nodes: root array `[1, 2]` over two `Int` leaves.
fn tiny_spec(edges: Vec<(u32, u32)>, children: Vec<u32>) -> Spec {
    Spec {
        nodes: vec![
            node(7, 0, 0, children.len() as u64, 0),
            node(2, 0, 1, 0, 0),
            node(2, 0, 2, 0, 0),
        ],
        children,
        fields: vec![],
        parts: vec![],
        edges,
        strings: vec![],
        root: 0,
    }
}

#[test]
fn inf06_tiny_valid_image_passes() {
    let image = build_image(&tiny_spec(vec![(1, 0), (2, 0)], vec![1, 2]));
    let meta = validate_with(&image, structural_opts()).expect("tiny valid image");
    assert_eq!(meta.nodes, 3);
    assert_eq!(meta.edges, 2);
}

#[test]
fn inf06_extra_stored_edge_is_edge_set() {
    // (2, 1) is sorted and in range, but no node derives it.
    let image = build_image(&tiny_spec(vec![(1, 0), (2, 0), (2, 1)], vec![1, 2]));
    assert!(matches!(
        validate_with(&image, structural_opts()).expect_err("extra edge"),
        Error::EdgeSet
    ));
}

#[test]
fn inf06_missing_stored_edge_is_edge_set() {
    let image = build_image(&tiny_spec(vec![(1, 0)], vec![1, 2]));
    assert!(matches!(
        validate_with(&image, structural_opts()).expect_err("missing edge"),
        Error::EdgeSet
    ));
}

#[test]
fn inf06_duplicate_references_collapse_to_the_edge_set() {
    // Two references to node 1 from the same parent are ONE derived pair:
    // the image is valid, and the stored table holds the deduped pair.
    // This is the case the per-node dedup in the streaming comparison must
    // preserve — without it, a valid image with duplicate refs would be
    // refused once `derived` is capped at the stored count.
    let image = build_image(&tiny_spec(vec![(1, 0), (2, 0)], vec![1, 1, 2]));
    validate_with(&image, structural_opts()).expect("duplicate refs are one pair");
}

#[test]
fn inf06_duplicate_references_do_not_hide_a_missing_edge() {
    let image = build_image(&tiny_spec(vec![(1, 0)], vec![1, 1, 2]));
    assert!(matches!(
        validate_with(&image, structural_opts()).expect_err("missing (2, 0)"),
        Error::EdgeSet
    ));
}

#[test]
fn inf06_derived_exceeding_the_table_is_edge_set() {
    // 50 distinct children, one stored edge: the derived set exceeds the
    // table, so the streaming comparison must fail fast with EdgeSet
    // instead of growing `derived` toward the reference count.
    let mut nodes = vec![node(7, 0, 0, 50, 0)];
    let mut children = Vec::with_capacity(50);
    for id in 1..=50u32 {
        nodes.push(node(2, 0, id as u64, 0, 0));
        children.push(id);
    }
    let image = build_image(&Spec {
        nodes,
        children,
        fields: vec![],
        parts: vec![],
        edges: vec![(1, 0)],
        strings: vec![],
        root: 0,
    });
    assert!(matches!(
        validate_with(&image, structural_opts()).expect_err("derived exceeds table"),
        Error::EdgeSet
    ));
}

#[test]
fn inf06_self_loop_edge_is_cycle() {
    let image = build_image(&tiny_spec(vec![(0, 0), (1, 0), (2, 0)], vec![1, 2]));
    assert!(matches!(
        validate_with(&image, structural_opts()).expect_err("self-loop"),
        Error::Cycle { .. }
    ));
}

#[test]
fn inf06_out_of_order_edge_table_is_edge_error() {
    let image = build_image(&tiny_spec(vec![(2, 0), (1, 0)], vec![1, 2]));
    assert!(matches!(
        validate_with(&image, structural_opts()).expect_err("out of order"),
        Error::Edge { .. }
    ));
}

#[test]
fn inf06_out_of_range_edge_is_edge_error() {
    let image = build_image(&tiny_spec(vec![(1, 0), (9, 0)], vec![1, 2]));
    assert!(matches!(
        validate_with(&image, structural_opts()).expect_err("out of range"),
        Error::Edge { .. }
    ));
}

// ---------------------------------------------------------------------------
// Max-shape builders (direct-to-buffer; the Spec path would hold a second
// 4M-entry copy of the node table in the test process)
// ---------------------------------------------------------------------------

const MAX_NODES: u32 = 1 << 22; // 4,194,304
const MAX_EDGES: u32 = 1 << 24; // 16,777,216

/// Valid max-shape image: 2048 layers x 2048 array nodes, each node in layers
/// 0..=2046 references 4 nodes in the next layer; the last layer are sinks.
/// Derived pairs == stored edge table exactly (16,769,024 pairs), depth 2048,
/// every node reachable from root 0.
fn build_valid_max_shape() -> Vec<u8> {
    const LAYERS: u32 = 2048;
    const WIDTH: u32 = 2048;
    const LAST_LAYER_START: u32 = (LAYERS - 1) * WIDTH; // 4,192,256
    const CHILD_TOTAL: u32 = (LAYERS - 1) * WIDTH * 4; // 16,769,024
    assert_eq!(LAYERS * WIDTH, MAX_NODES);

    // Nodes: 32 bytes each; layer k < 2047 is an Array of 4 children starting
    // at child offset 4 * id; the last layer are Arrays of 0 children.
    let mut nodes = vec![0u8; MAX_NODES as usize * 32];
    for id in 0..MAX_NODES {
        let off = id as usize * 32;
        nodes[off] = 7;
        if id < LAST_LAYER_START {
            let a = (id as u64) * 4;
            nodes[off + 8..off + 16].copy_from_slice(&a.to_le_bytes());
            nodes[off + 16..off + 24].copy_from_slice(&4u64.to_le_bytes());
        } else {
            let a = CHILD_TOTAL as u64;
            nodes[off + 8..off + 16].copy_from_slice(&a.to_le_bytes());
        }
    }
    // Children: node (k, j) references layer k+1 nodes (2j+t) mod 2048.
    let mut children = vec![0u8; CHILD_TOTAL as usize * 4];
    for id in 0..LAST_LAYER_START {
        let k = id / WIDTH;
        let j = id % WIDTH;
        let base = ((k + 1) * WIDTH) as usize;
        for t in 0..4u32 {
            let child = base + ((2 * j + t) % WIDTH) as usize;
            let at = (id as usize * 4 + t as usize) * 4;
            children[at..at + 4].copy_from_slice(&(child as u32).to_le_bytes());
        }
    }
    // Edges: for each child (layer k+1, position p), its parents in layer k,
    // ascending — the emitted order is sorted by (from, to) by construction.
    // Parent (k, j) references child p iff (2j + t) mod 2048 == p for some
    // t in 0..3, i.e. 2j == p - t (mod 2048) with p - t even.
    let mut edges = Vec::with_capacity(CHILD_TOTAL as usize * 8);
    for child in WIDTH..MAX_NODES {
        let k = child / WIDTH - 1;
        let p = child % WIDTH;
        let mut parents = [0u32; 4];
        let mut n = 0usize;
        for t in 0..4u32 {
            let r = (p + WIDTH - t) % WIDTH;
            if r % 2 == 0 {
                let j = r / 2;
                parents[n] = k * WIDTH + j;
                n += 1;
                parents[n] = k * WIDTH + j + WIDTH / 2;
                n += 1;
            }
        }
        parents[..n].sort_unstable();
        for parent in &parents[..n] {
            edges.extend_from_slice(&child.to_le_bytes());
            edges.extend_from_slice(&parent.to_le_bytes());
        }
    }
    assert_eq!(edges.len(), CHILD_TOTAL as usize * 8, "edge count");
    // Bindings: every layer-0 node is a named root. Layer 0 has 2048 source
    // nodes and the module root is only node 0, so without these the other
    // 2047 layer-0 nodes would be unreachable (`check_reachability` fails
    // the image before the RSS leg ever runs). The names are zero-padded so
    // string-id order is text order, which `check_bindings` requires.
    let mut strings = Vec::new();
    let mut heap = Vec::new();
    let mut ends = vec![0u32];
    for j in 0..WIDTH {
        let name = format!("b{j:04}");
        heap.extend_from_slice(name.as_bytes());
        ends.push(heap.len() as u32);
    }
    for end in &ends {
        strings.extend_from_slice(&end.to_le_bytes());
    }
    strings.extend_from_slice(&heap);
    let mut bindings = Vec::with_capacity((WIDTH as usize + 1) * 8);
    bindings.extend_from_slice(&0u32.to_le_bytes());
    bindings.extend_from_slice(&0u32.to_le_bytes());
    for j in 0..WIDTH {
        bindings.extend_from_slice(&j.to_le_bytes());
        bindings.extend_from_slice(&j.to_le_bytes());
    }
    let bodies: [&[u8]; 17] = [
        &nodes,
        &children,
        &[],
        &[],
        &edges,
        &strings,
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &bindings,
    ];
    let counts: [u32; 17] = [
        MAX_NODES,
        CHILD_TOTAL,
        0,
        0,
        CHILD_TOTAL,
        WIDTH,
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
        WIDTH + 1,
    ];
    assemble(&bodies, &counts)
}

/// Hostile max-shape image: 37,748,727 node references against a 16,777,216
/// row edge table. Node kinds split the 4,194,304 nodes into 1,398,101
/// arrays (12 children each = 16,777,212 refs), 1,398,101 tables (12 fields
/// each = 16,777,212 refs), 1,398,101 interpolations (3 PART_EXPR parts each
/// = 4,194,303 refs) and one Null node. Every reference names node 0, so the
/// *distinct* derived set is only 4,194,303 pairs — but the pre-fix code
/// pushes every reference before deduping, which is the blowup.
fn build_hostile_max_shape() -> Vec<u8> {
    const GROUP: u32 = 1_398_101;
    const CHILDREN: u32 = GROUP * 12; // 16,777,212
    const FIELDS: u32 = GROUP * 12; // 16,777,212
    const PARTS: u32 = GROUP * 3; // 4,194,303
    assert_eq!(GROUP * 3 + 1, MAX_NODES);

    // Nodes.
    let mut nodes = vec![0u8; MAX_NODES as usize * 32];
    for id in 0..MAX_NODES {
        let off = id as usize * 32;
        if id < GROUP {
            // Array: children [12*id, 12*id+12).
            nodes[off] = 7;
            nodes[off + 8..off + 16].copy_from_slice(&((id as u64) * 12).to_le_bytes());
            nodes[off + 16..off + 24].copy_from_slice(&12u64.to_le_bytes());
        } else if id < GROUP * 2 {
            // Table: fields [12*(id-GROUP), 12*(id-GROUP)+12).
            nodes[off] = 8;
            nodes[off + 8..off + 16].copy_from_slice(&(((id - GROUP) as u64) * 12).to_le_bytes());
            nodes[off + 16..off + 24].copy_from_slice(&12u64.to_le_bytes());
        } else if id < GROUP * 3 {
            // Interpolate: parts [3*(id-2*GROUP), 3*(id-2*GROUP)+3).
            nodes[off] = 14;
            nodes[off + 8..off + 16]
                .copy_from_slice(&(((id - GROUP * 2) as u64) * 3).to_le_bytes());
            nodes[off + 16..off + 24].copy_from_slice(&3u64.to_le_bytes());
        } else {
            // Null.
            nodes[off] = 0;
        }
    }
    // Children: all node 0 (16,777,212 x u32 zero — one memset).
    let children = vec![0u8; CHILDREN as usize * 4];
    // Fields: 12-field pattern (name ids 0..11, node 0), repeated.
    let mut pattern = [0u8; 12 * 16];
    for f in 0..12usize {
        pattern[f * 16..f * 16 + 4].copy_from_slice(&(f as u32).to_le_bytes());
    }
    let mut fields = vec![0u8; FIELDS as usize * 16];
    for chunk in fields.chunks_mut(pattern.len()) {
        chunk.copy_from_slice(&pattern[..chunk.len()]);
    }
    // Parts: (PART_EXPR, 0) repeated.
    let mut parts = vec![0u8; PARTS as usize * 8];
    for chunk in parts.chunks_mut(8) {
        chunk[0..4].copy_from_slice(&1u32.to_le_bytes());
    }
    // Edges: the first MAX_EDGES pairs (i, j) with i < j, in lex order:
    // i=0..3 contribute 4,194,303 + 4,194,302 + 4,194,301 + 4,194,300 pairs
    // (16,777,206), and i=4 contributes the last 10 (j=5..14).
    let mut edges = Vec::with_capacity(MAX_EDGES as usize * 8);
    let mut emitted = 0u32;
    let mut i = 0u32;
    while emitted < MAX_EDGES {
        let mut j = i + 1;
        while j < MAX_NODES && emitted < MAX_EDGES {
            edges.extend_from_slice(&i.to_le_bytes());
            edges.extend_from_slice(&j.to_le_bytes());
            emitted += 1;
            j += 1;
        }
        i += 1;
    }
    assert_eq!(edges.len(), MAX_EDGES as usize * 8, "edge count");
    // Strings: 12 field names, strictly ascending.
    let names: Vec<String> = (0..12).map(|i| format!("f{i:02}")).collect();
    let mut strings = Vec::new();
    let mut heap = Vec::new();
    let mut ends = vec![0u32];
    for name in &names {
        heap.extend_from_slice(name.as_bytes());
        ends.push(heap.len() as u32);
    }
    for end in &ends {
        strings.extend_from_slice(&end.to_le_bytes());
    }
    strings.extend_from_slice(&heap);
    let bodies: [&[u8]; 17] = [
        &nodes,
        &children,
        &fields,
        &parts,
        &edges,
        &strings,
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[0, 0, 0, 0, 0, 0, 0, 0],
    ];
    let counts: [u32; 17] = [
        MAX_NODES, CHILDREN, FIELDS, PARTS, MAX_EDGES, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];
    assemble(&bodies, &counts)
}

// ---------------------------------------------------------------------------
// RSS probe runner (subprocess: examples/inf06_probe)
// ---------------------------------------------------------------------------

struct ProbeOutput {
    result: Result<(), String>,
    input_bytes: u64,
    baseline_kib: u64,
    peak_kib: u64,
    validate_ms: u128,
}

/// Locate the probe binary under target/debug/examples/ (or
/// target/release/examples/ when built that way). `cargo test` builds example
/// targets, so it is there after the build; if it is not, fail with the exact
/// command that produces it instead of guessing.
fn example_binary() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("target"));
    let stem = if cfg!(target_os = "windows") {
        "inf06_probe.exe"
    } else {
        "inf06_probe"
    };
    for profile in ["debug", "release"] {
        let candidate = target.join(profile).join("examples").join(stem);
        if candidate.exists() {
            return candidate;
        }
    }
    panic!(
        "INF-06 probe binary not found under {}; run `cargo build --example inf06_probe` first (cargo test normally builds it)",
        target.join("debug").join("examples").display()
    );
}

fn run_probe(image_path: &Path, canonical: bool) -> ProbeOutput {
    let mut command = Command::new(example_binary());
    command.arg(image_path);
    if canonical {
        command.arg("--canonical");
    } else {
        command.arg("--structural");
    }
    let output = command.output().expect("run the inf06_probe subprocess");
    assert!(
        output.status.success(),
        "probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    let mut result = None;
    let mut input_bytes = None;
    let mut baseline_kib = None;
    let mut peak_kib = None;
    let mut validate_ms = None;
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("bad probe line: {line}"));
        match key {
            "result" => {
                result = Some(if value == "ok" {
                    Ok(())
                } else {
                    Err(value.to_string())
                })
            }
            "input_bytes" => input_bytes = Some(value.parse().expect("input_bytes")),
            "baseline_kib" => baseline_kib = Some(value.parse().expect("baseline_kib")),
            "peak_kib" => peak_kib = Some(value.parse().expect("peak_kib")),
            "validate_ms" => validate_ms = Some(value.parse().expect("validate_ms")),
            other => panic!("unknown probe key: {other}"),
        }
    }
    ProbeOutput {
        result: result.expect("probe result"),
        input_bytes: input_bytes.expect("probe input_bytes"),
        baseline_kib: baseline_kib.expect("probe baseline_kib"),
        peak_kib: peak_kib.expect("probe peak_kib"),
        validate_ms: validate_ms.expect("probe validate_ms"),
    }
}

fn assert_within_working_budget(out: &ProbeOutput, what: &str) {
    let budget_bytes = out.input_bytes + WORKING_BUDGET_MIB * 1024 * 1024;
    let peak_bytes = out.peak_kib * 1024;
    // Always report the measurement (visible with --nocapture): the record
    // quotes exact peaks, never estimates.
    println!(
        "{what}: peak RSS {} MiB (input {} MiB, baseline {} KiB, validate {} ms, bound {} MiB)",
        peak_bytes / (1024 * 1024),
        out.input_bytes / (1024 * 1024),
        out.baseline_kib,
        out.validate_ms,
        budget_bytes / (1024 * 1024)
    );
    assert!(
        peak_bytes <= budget_bytes,
        "{what}: peak RSS {} MiB exceeds input {} MiB + {} MiB budget (baseline {} KiB, validate {} ms)",
        peak_bytes / (1024 * 1024),
        out.input_bytes / (1024 * 1024),
        WORKING_BUDGET_MIB,
        out.baseline_kib,
        out.validate_ms
    );
}

fn write_temp_image(dir: &tempfile::TempDir, name: &str, image: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    let mut file = std::fs::File::create(&path).expect("create temp image");
    file.write_all(image).expect("write temp image");
    file.sync_all().expect("sync temp image");
    path
}

#[test]
fn inf06_hostile_max_refs_within_working_budget() {
    // Pre-fix this FAILS: the 37.7M-reference derived Vec peaks at 1253 MiB
    // RSS (measured twice pre-fix, 1253 MiB both times) against an input +
    // 512 MiB bound of 1120 MiB. Post-fix the image is refused with
    // infinity/edge-set, and the peak must sit inside the same bound.
    let image = build_hostile_max_shape();
    let dir = tempfile::TempDir::new().expect("temp dir");
    let path = write_temp_image(&dir, "hostile.ainf", &image);
    drop(image);
    let out = run_probe(&path, false);
    assert!(
        out.result.is_err(),
        "hostile image must be refused, got ok (peak {} KiB)",
        out.peak_kib
    );
    assert_within_working_budget(&out, "hostile max-refs image");
}

#[test]
fn inf06_valid_max_shape_within_working_budget() {
    // Must validate before and after the fix; the peak is reported by the
    // probe (see the println in `assert_within_working_budget`) and recorded
    // in records/F2-INF/INF-06.md. Bound: input ~320 MiB + 512 MiB.
    let image = build_valid_max_shape();
    // Sanity: the shape is what the header claims before the subprocess runs.
    let meta = validate_with(&image, structural_opts()).expect("valid max-shape image");
    assert_eq!(meta.nodes, MAX_NODES);
    assert_eq!(meta.edges, 16_769_024);
    let dir = tempfile::TempDir::new().expect("temp dir");
    let path = write_temp_image(&dir, "valid.ainf", &image);
    drop(image);
    let out = run_probe(&path, false);
    assert!(
        out.result.is_ok(),
        "valid max-shape image must validate, got {:?} (peak {} KiB)",
        out.result,
        out.peak_kib
    );
    assert_within_working_budget(&out, "valid max-shape image");
}

#[test]
fn inf06_default_limits_admit_max_shape_counts() {
    // The working budget must not refuse the legitimate max-shape image at
    // default limits: its counts are all at (not over) their ceilings.
    // (Pre-fix this passes vacuously — there is no budget yet — and post-fix
    // it pins that the budget's bound for this shape sits under 512 MiB.)
    let limits = Limits::default();
    assert_eq!(limits.max_nodes, MAX_NODES);
    assert_eq!(limits.max_edges, MAX_EDGES);
}

// ---------------------------------------------------------------------------
// Working-budget unit tests (need the fix to compile: they name the new field)
// ---------------------------------------------------------------------------

/// Structural options identical to the default except for the working budget.
fn with_working_budget(max_working_bytes: u64) -> DecodeOpts {
    DecodeOpts {
        limits: Limits {
            max_working_bytes,
            ..Limits::default()
        },
        verify_canonical: false,
        ..DecodeOpts::default()
    }
}

#[test]
fn inf06_working_budget_defaults() {
    assert_eq!(Limits::default().max_working_bytes, 512 << 20);
    // The strict profile's working budget equals its total-bytes ceiling:
    // a strict image's working set never exceeds its own size by this rule.
    assert_eq!(Limits::strict().max_working_bytes, 8 << 20);
}

#[test]
fn inf06_working_budget_zero_is_invalid_argument() {
    let limits = Limits {
        max_working_bytes: 0,
        ..Limits::default()
    };
    let error = limits
        .check()
        .expect_err("a zero working budget must be refused");
    assert_eq!(error.code(), "infinity/invalid-argument");
    assert!(
        format!("{error}").contains("max_working_bytes"),
        "the message names the field, got {error}"
    );
}

#[test]
fn inf06_tiny_image_refused_below_working_budget() {
    // The tiny image's bound is 65,675 bytes (fixed 64 KiB allowance plus
    // ~100 bytes of section-driven terms): a 64 KiB budget refuses it, a
    // 128 KiB budget admits it. The refusal names the budget.
    let image = build_image(&tiny_spec(vec![(1, 0), (2, 0)], vec![1, 2]));
    let error = validate_with(&image, with_working_budget(64 << 10))
        .expect_err("a 64 KiB working budget must refuse even a tiny image");
    assert_eq!(error.code(), "infinity/limit", "{error}");
    assert!(
        format!("{error}").contains("working bytes"),
        "the refusal names the budget, got {error}"
    );
}

#[test]
fn inf06_tiny_image_accepted_above_working_budget() {
    let image = build_image(&tiny_spec(vec![(1, 0), (2, 0)], vec![1, 2]));
    validate_with(&image, with_working_budget(128 << 10))
        .expect("a 128 KiB working budget admits the tiny image");
}

#[test]
fn inf06_provenance_projection_bounded_by_working_budget() {
    // 600 provenance entries sharing one 1 MiB text value: the image stays
    // ~1.1 MiB (the string is interned once) while the projection — key plus
    // value bytes cloned per entry — is 600 x (4 + 1 MiB) = 629,148,000
    // bytes. That sits between the 512 MiB working budget and the 1 GiB
    // total-bytes ceiling the guard used to use, so pre-fix the image
    // validates structurally (materialising ~600 MiB inside `check_provenance`)
    // while post-fix it is refused with `infinity/limit` before any cloning
    // happens. Structural options are used on purpose: the default
    // `validate()` would refuse the same image pre-fix too, but at the
    // decoded-bytes budget inside the canonical proof — a different limit
    // for a different reason — while this test pins the validation path.
    let shared = "p".repeat(1024 * 1024);
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Null);
    module.set_root(Some(root));
    module.set_provenance(Some(Provenance {
        entries: (0..600)
            .map(|i| ProvEntry {
                key: format!("k{i:03}"),
                value: ProvValue::Text(shared.clone()),
            })
            .collect(),
        ..Provenance::default()
    }));
    let image = encode(&module).expect("encode shared-provenance module");
    assert!(
        image.len() < 2 * 1024 * 1024,
        "the image must stay small: {}",
        image.len()
    );
    let error = validate_with(&image, structural_opts())
        .expect_err("a 600 MiB provenance projection must be refused");
    assert_eq!(error.code(), "infinity/limit", "{error}");
    assert!(
        format!("{error}").contains("provenance projection"),
        "the refusal names the projection, got {error}"
    );
}
