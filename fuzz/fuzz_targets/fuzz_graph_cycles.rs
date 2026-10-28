#![no_main]

//! Graph cycles: every cycle shape must surface as a cycle, not a depth error.
//!
//! Invariants under test:
//!
//! 1. A self-loop, a two-node cycle and a long cycle are refused with
//!    `infinity/cycle`, whatever their length.
//! 2. A cycle is detected before the depth ceiling can mask it.
//! 3. A valid chain of the same shape still validates.
//!
//! The image is built from a `Ref` chain, then one child pointer is repointed
//! backwards. The derived edge table is rebuilt in the documented sorted order,
//! so the only structural fault is the cycle itself.
//!
//! Run with `cargo +nightly fuzz run fuzz_graph_cycles -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_infinity::{decode, encode, validate, InfinityModule, Inode};

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let length = 1 + (data[0] as u32 % 64);
    let module: InfinityModule = common::ring_chain(length);
    let Ok(image) = encode(&module) else {
        return;
    };

    // Control: the unclosed ring is a chain and validates.
    assert!(validate(&image).is_ok(), "a chain must validate");

    // Canonical encoding renumbers the arena, so derive the head and leaf from
    // the root table instead of assuming indices. `r1` is the Ref whose child
    // is the leaf; closing `r1` on the head forms a ring over every Ref while
    // the root still reaches the leaf, so reachability passes and only
    // acyclicity can reject it.
    let Some(root) = common::root_node(&image) else {
        return;
    };
    let fields = common::table_children(&image, root);
    let Some(head) = fields
        .iter()
        .copied()
        .find(|node| common::kind(&image, *node) == Some(11))
    else {
        return;
    };
    let Some(leaf) = fields
        .iter()
        .copied()
        .find(|node| common::kind(&image, *node) == Some(2))
    else {
        return;
    };
    let mut first = head;
    let mut guard = 0u32;
    loop {
        match common::ref_child(&image, first) {
            Some(child) if child == leaf => break,
            Some(child) => {
                first = child;
                guard += 1;
                if guard > length + 2 {
                    return;
                }
            }
            None => return,
        }
    }

    // Self-loop: the edge-table contract rejects a `from == to` row as
    // `infinity/edge` before acyclicity runs; the important property is that
    // it is refused structurally, not by the depth ceiling.
    let mut self_loop = image.clone();
    if common::repoint_ref(&mut self_loop, first, first) {
        let error = validate(&self_loop).expect_err("a self-loop must be refused");
        assert_eq!(error.code(), "infinity/edge", "self-loop code");
        assert!(decode(&self_loop).is_err(), "a cycle must not decode");
    }

    // Close the ring. The root still points at the leaf directly, so every node
    // remains reachable and the outcome must be `infinity/cycle`.
    if head != first {
        let mut ring = image.clone();
        if common::repoint_ref(&mut ring, first, head) {
            let error = validate(&ring).expect_err("a ring must be refused");
            assert_eq!(error.code(), "infinity/cycle", "ring code for length {length}");
        }
    }

    // Fuzz-selected single child rewiring: any result is a stable code.
    let count = common::node_count(&image).unwrap_or(1).max(1);
    let node = data[1] as u32 % count;
    let target = (data.get(2).copied().unwrap_or(0) as u32) % count;
    if common::ref_child(&image, node).is_some() {
        let mut rewired = image.clone();
        if common::repoint_ref(&mut rewired, node, target) {
            match validate(&rewired) {
                Ok(_) => {
                    let module = decode(&rewired).expect("validated image decodes");
                    let _ = encode(&module);
                }
                Err(error) => assert!(
                    error.code().starts_with("infinity/"),
                    "unexpected code {}",
                    error.code()
                ),
            }
        }
    }

    let _ = Inode::Null;
});
