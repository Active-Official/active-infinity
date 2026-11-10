//! Regression tests for INF-15: `content_key_with` render is recursive;
//! debug/small-stack abort (INF-CANON-STACK-01), `AUDIT-REPORT.md:769`,
//! verified CONFIRMED by W4.
//!
//! The audit probe (`audit_bisect.rs`, W4) encoded annotated `Unary` chains
//! of increasing depth. At the audit HEAD (`6aad041`) release was fine up
//! to 256 and returned `infinity/limit` at 257 and above, but debug
//! (`cargo test`, 2 MiB test-thread stack) aborted the process with
//! `thread 'bisect_annotated_chain' has overflowed its stack`, exit code
//! `0xc00000fd` (`STATUS_STACK_OVERFLOW`), at depth ~200 — before the
//! `KEY_DEPTH` guard could return the error. Any debug test or downstream
//! debug consumer encoding an annotated chain deeper than ~150 aborted
//! instead of receiving an `Err`, and the same applied to any consumer
//! thread with a small stack.
//!
//! The fix landed as INF-10 (commit `6f18110`): `content_key_with` no
//! longer renders recursively. The key is now the exact render while it
//! fits in 1 MiB, produced by `render_key_exact` — an explicit action
//! stack (`src/canonical.rs`) — and a Blake3 tree-hash digest past it
//! (`subtree_digest`, likewise iterative). There is no depth cap on the
//! key itself any more: depth is bounded upstream by `prepare()` at
//! `Limits::default().max_depth` (4096, INF-09). The recursive render
//! that aborted is gone — no `render()` remains in `canonical.rs` — so
//! INF-15 needed no source change of its own. This file pins that, so
//! the abort can never come back silently.
//!
//! One expectation changed with INF-10 and is pinned as the new correct
//! behaviour, not as a regression: a 200-deep annotated chain is now a
//! *legal* module and encodes `Ok`. The 256-deep refusal was INF-10's
//! target, not INF-15's. The finding's "returns `Err` instead of
//! aborting" property therefore lives where an `Err` is actually correct
//! today — at the real ceiling: a chain past 4096 nodes is refused
//! cleanly with `infinity/depth`, in debug, instead of aborting.
//!
//! Depth counting: these tests keep the audit probe's `chain(depth)`
//! (a leaf `Int` plus `depth` `Unary` nodes, so `depth + 1` nodes in
//! total) so the sweep below is the probe verbatim. INF-09's
//! `chain(depth)` counts nodes instead (leaf plus `depth - 1` unaries),
//! so audit-depth 4095 here is INF-09's depth-4096 chain — the last
//! depth the ceiling allows — and audit-depth 4096 is the first refusal.

use active_infinity::{
    decode, encode, validate, AnnotationKind, Error, InfinityModule, Inode, Limits, UnOp,
};

/// A unary chain of `depth` `Unary` nodes over one leaf `Int`: the audit
/// probe's shape, `depth + 1` nodes in total.
fn chain(depth: usize) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut cur = module.push(Inode::Int(1));
    for _ in 0..depth {
        cur = module.push(Inode::Unary {
            op: UnOp::Neg,
            expr: cur,
        });
    }
    module.set_root(Some(cur));
    module
}

/// The audit probe's module: a unary chain annotated at its head, so
/// `encode` must render the chain as an ordering key.
fn annotated_chain(depth: usize) -> InfinityModule {
    let mut module = chain(depth);
    let head = module.root().unwrap();
    module.annotate(head, AnnotationKind::Intent("deep".into()));
    module
}

/// Assert `error` is the depth refusal at the default ceiling (INF-09).
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
fn original_bisect_sweep_encodes_without_aborting() {
    // The audit probe's sweep, verbatim. At 6aad041 debug aborted the
    // process at depth 200 (exit 0xc00000fd) and never reached 250; now
    // every depth encodes. Depths 257 and above return `Ok` here, not
    // the audit-time `infinity/limit`: INF-10 removed the key's 256
    // depth cap, so a 300-deep annotated chain is a legal module.
    for depth in [10usize, 50, 100, 200, 250, 255, 256, 257, 260, 300] {
        let module = annotated_chain(depth);
        let bytes = encode(&module)
            .unwrap_or_else(|error| panic!("annotated depth {depth} must encode, got {error}"));
        validate(&bytes)
            .unwrap_or_else(|error| panic!("annotated depth {depth} must validate, got {error}"));
    }
}

#[test]
fn annotated_chain_at_the_depth_ceiling_encodes() {
    // Audit-depth 4095 is 4096 nodes: the last depth the ceiling
    // allows (INF-09). The old recursive render would have needed
    // ~4096 frames; the iterative render encodes it in bounded stack.
    let at_ceiling = annotated_chain(4095);
    let bytes = encode(&at_ceiling).expect("encode must accept depth 4096");
    validate(&bytes).expect("a depth-4096 image validates");
    let decoded = decode(&bytes).expect("a depth-4096 image decodes");
    assert_eq!(decoded.node_count(), 4096);
}

#[test]
fn annotated_chain_past_the_ceiling_is_refused_cleanly() {
    // Audit-depth 4096 is 4097 nodes: the first depth past the ceiling.
    // This is the finding's "returns `Err` instead of aborting" pin at
    // the boundary where an `Err` is correct: the refusal must arrive
    // as a value, in debug, with the process alive to report it.
    let past = annotated_chain(4096);
    let error = encode(&past).expect_err("encode must refuse depth 4097");
    assert_depth_refusal(&error);
}

#[test]
fn small_stack_thread_encodes_a_200_deep_annotated_chain() {
    // The finding's second half: a consumer thread with a small stack.
    // A 256 KiB stack is 8x smaller than the 2 MiB test-thread stack
    // that overflowed at depth ~200. The whole encode — key render
    // included — runs in bounded stack, so the thread completes.
    let handle = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| encode(&annotated_chain(200)).is_ok())
        .expect("spawn a 256 KiB thread");
    let ok = handle
        .join()
        .expect("the 256 KiB thread must complete, not abort the process");
    assert!(ok, "a 200-deep annotated chain encodes on a 256 KiB stack");
}

#[test]
fn small_stack_thread_encodes_a_ceiling_deep_annotated_chain() {
    // The strongest pin: the maximum legal depth (audit-depth 4095 is
    // 4096 nodes) on the 256 KiB stack. If any step of `encode` still
    // recursed per level of depth, this thread would abort the process
    // with `STATUS_STACK_OVERFLOW` instead of returning.
    let handle = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| encode(&annotated_chain(4095)).is_ok())
        .expect("spawn a 256 KiB thread");
    let ok = handle
        .join()
        .expect("the 256 KiB thread must complete, not abort the process");
    assert!(
        ok,
        "a ceiling-deep annotated chain encodes on a 256 KiB stack"
    );
}
