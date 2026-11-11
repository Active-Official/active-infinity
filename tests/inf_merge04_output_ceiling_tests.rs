//! Regression tests for INF-MERGE-04: the merge output node ceiling is
//! checked only after a full encode+decode of an over-ceiling module.
//!
//! Round-1 report §B.8: `src/merge.rs:247–250, 296–305`. The imported-nodes
//! budget counts only imported right-hand nodes, and the output ceiling
//! (`module.node_count() > MAX_MERGE_NODES`) is checked only after a full
//! `encode(&merged)` + `decode(&image)`. A merge of a 262k-node left with
//! 262k imported right nodes pays the whole canonical encode + decode
//! before being refused. The audit's suggested fix is to check
//! `merged.node_count()` before `encode()` — "the count is exact at that
//! point" — and return the same `Limit{"merge output nodes"}` there.
//!
//! That suggestion is half right, and the half that is wrong matters. The
//! finding itself (the ceiling is enforced too late) is correct. But
//! `merged.node_count()` is the ARENA length, and the arena still holds
//! every node a decision orphaned: the left cone a `TakeRight` replaced,
//! a deleted field's cone. The encoder drops those with
//! `drop_unreachable`, so the arena count can exceed the ceiling while the
//! output fits. A literal arena-count check would refuse a legitimate
//! merge — test 4 pins exactly that shape, with the arithmetic asserted
//! in-test: the arena at the check is one node OVER the ceiling while the
//! output is 62,141 nodes UNDER it.
//!
//! The fix therefore counts what the encoder will keep — the closure of
//! `merged.roots()` (root table, binding targets, annotation subjects and
//! constraint expressions, the same root set `canonical_order` walks) —
//! before `encode_with`, returning the same `Limit{"merge output nodes"}`.
//! The post-decode check stays as the exact backstop, so a miscount can
//! only ever refuse late, never wrongly and never silently.
//!
//! Fail-before / pass-after at HEAD `b27b345` (INF-MERGE-03):
//!
//! * Tests 1 and 3 expect `Err` with kind `"merge output nodes"`. They
//!   PASS at HEAD as well as after the fix — the refusal itself is not
//!   the bug, the work paid before it is. What changes is the work: at
//!   HEAD the merge pays a full canonical encode + decode of a 524,285
//!   node module (test 1) before refusing; after the fix it refuses from
//!   the pre-encode count. The fail-before evidence for tests 1 and 3 is
//!   therefore the measured wall time, recorded in the INF-MERGE-04
//!   record (pre-fix vs post-fix runs of this file), not a red test.
//!   No timing assertion is made here: the PC is shared with the F1
//!   worker and Docker, so a wall-clock bound would be flaky by
//!   construction.
//! * Test 2 pins the exact boundary: output at exactly `MAX_MERGE_NODES`
//!   merges cleanly. It passes at HEAD and after the fix, and it pins
//!   the pre-check against OVER-counting: a pre-check that counted the
//!   arena (test 4's shape) or any superset of the kept nodes would
//!   refuse here.
//! * Test 4 pins the fix against the literal audit suggestion: a merge
//!   whose arena is over the ceiling but whose output fits merges
//!   cleanly. It passes at HEAD (the post-decode check is the only
//!   ceiling) and after the fix; it would FAIL under a literal
//!   `merged.node_count()` pre-check.
//! * Test 5 pins the roots-closure semantics for the backstop: the only
//!   excess over the ceiling is a binding target that no field reaches.
//!   It passes at HEAD (the post-decode check catches it) and after the
//!   fix (the pre-check's roots closure counts the binding). It pins
//!   that the binding-rooted node counts, so the post-decode check stays
//!   load-bearing for the closure semantics even though the pre-check
//!   normally fires first.
//!
//! Budget note: every big shape below keeps the merge work budget in
//! view. `decide()` charges roughly 3× the subtree size per `equal()`
//! call, so a 262k-node subtree present on two sides with different
//! content would trip `Limit("merge work")` (INF-MERGE-06) long before
//! the output check. The big subtrees here therefore live in fields
//! present on ONE side only (a one-sided field costs one `has_secret`
//! walk, ~2 charges per node), except test 4's replaced field, which is
//! kept to 62,140 leaves so its full `decide()` stays near 0.9M of the
//! 4,194,304 budget. The totals were verified by running the file, not
//! by arithmetic alone: no test here trips the work budget.

use std::time::Instant;

use active_infinity::{
    merge::{self, MAX_MERGE_NODES},
    InfinityModule, Inode, Merge, NodeId,
};

/// Push a table of `count` `Int(0)` leaves and return its id.
///
/// Field names are zero-padded so the table is already in canonical
/// field order; the values are identical on purpose (no secrets, no
/// distinguishing content — the merge must decide these fields by
/// presence alone).
fn push_int_table(module: &mut InfinityModule, count: usize) -> NodeId {
    let mut fields = Vec::with_capacity(count);
    for i in 0..count {
        let id = module.push(Inode::Int(0));
        fields.push((format!("f{i:06}"), id));
    }
    module.push(Inode::Table { fields })
}

/// A module whose root is a table of the given `(name, id)` fields.
fn root_module(fields: Vec<(String, NodeId)>) -> InfinityModule {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));
    module
}

/// The empty root table all three sides share when a test adds fields on
/// one side only.
fn empty_root() -> InfinityModule {
    root_module(Vec::new())
}

fn err_kind_message(result: Result<Merge, active_infinity::Error>) -> (String, String) {
    let error = result.expect_err("the merge must refuse");
    (error.code().to_string(), error.to_string())
}

/// Test 1 — the audit's shape at full size: a 262,143-node left plus
/// 262,142 imported right nodes, output 524,285 nodes.
///
/// The refusal is `Limit{"merge output nodes"}`. At HEAD this error is
/// raised only after the full canonical encode + decode of the 524,285
/// node merged module; after the fix it is raised from the pre-encode
/// count. The elapsed time is printed for the record — it is the
/// fail-before / pass-after evidence, not an assertion.
#[test]
fn over_ceiling_output_is_refused_with_merge_output_nodes() {
    let base = empty_root();
    let mut left = InfinityModule::new();
    let a = push_int_table(&mut left, 262_141);
    let left = {
        let root = left.push(Inode::Table {
            fields: vec![("a".to_string(), a)],
        });
        left.set_root(Some(root));
        left
    };
    let mut right = InfinityModule::new();
    let b = push_int_table(&mut right, 262_141);
    let right = {
        let root = right.push(Inode::Table {
            fields: vec![("b".to_string(), b)],
        });
        right.set_root(Some(root));
        right
    };
    assert_eq!(left.node_count(), 262_143);
    assert_eq!(right.node_count(), 262_143);
    // Output = left (262,143) + imported `b` cone (262,142).
    let started = Instant::now();
    let (code, message) = err_kind_message(merge::merge(&base, &left, &right));
    eprintln!(
        "INF-MERGE-04 test 1: over-ceiling merge refused in {:?}",
        started.elapsed()
    );
    assert_eq!(code, "infinity/limit", "{message}");
    assert!(
        message.contains("merge output nodes"),
        "expected the output-nodes limit, got: {message}"
    );
}

/// Test 2 — the exact boundary: output at exactly `MAX_MERGE_NODES`
/// merges cleanly.
///
/// Output = left (131,073) + imported `b` cone (131,071) = 262,144.
#[test]
fn output_exactly_at_the_ceiling_merges_cleanly() {
    let base = empty_root();
    let mut left = InfinityModule::new();
    let a = push_int_table(&mut left, 131_071);
    let left = {
        let root = left.push(Inode::Table {
            fields: vec![("a".to_string(), a)],
        });
        left.set_root(Some(root));
        left
    };
    let mut right = InfinityModule::new();
    let b = push_int_table(&mut right, 131_070);
    let right = {
        let root = right.push(Inode::Table {
            fields: vec![("b".to_string(), b)],
        });
        right.set_root(Some(root));
        right
    };
    assert_eq!(left.node_count(), 131_073);
    assert_eq!(right.node_count(), 131_072);
    let merged = match merge::merge(&base, &left, &right).expect("merge") {
        Merge::Clean(module) => module,
        Merge::Conflicts(conflicts) => panic!("expected a clean merge, got {conflicts:?}"),
    };
    assert_eq!(merged.node_count(), MAX_MERGE_NODES);
}

/// Test 3 — one node over the ceiling is refused with the same limit.
///
/// Output = left (131,073) + imported `b` cone (131,072) = 262,145.
#[test]
fn output_one_over_the_ceiling_is_refused() {
    let base = empty_root();
    let mut left = InfinityModule::new();
    let a = push_int_table(&mut left, 131_071);
    let left = {
        let root = left.push(Inode::Table {
            fields: vec![("a".to_string(), a)],
        });
        left.set_root(Some(root));
        left
    };
    let mut right = InfinityModule::new();
    let b = push_int_table(&mut right, 131_071);
    let right = {
        let root = right.push(Inode::Table {
            fields: vec![("b".to_string(), b)],
        });
        right.set_root(Some(root));
        right
    };
    assert_eq!(left.node_count(), 131_073);
    assert_eq!(right.node_count(), 131_073);
    let (code, message) = err_kind_message(merge::merge(&base, &left, &right));
    assert_eq!(code, "infinity/limit", "{message}");
    assert!(
        message.contains("merge output nodes"),
        "expected the output-nodes limit, got: {message}"
    );
}

/// Test 4 — an orphaned left cone does NOT count toward the output
/// ceiling.
///
/// `left` is exactly at the ceiling (262,144 nodes): a left-only `bulk`
/// table of 200,001 ints plus a `cfg` table of 62,140 ints shared with
/// base. Right replaces `cfg` with `Int(1)`: one node is imported, the
/// whole 62,141-node left `cfg` cone is orphaned, and the output is
/// 200,004 nodes — 62,140 under the ceiling. But the ARENA at the
/// pre-encode check is `left` + imported = 262,145, one OVER the
/// ceiling. A literal `merged.node_count()` pre-check would refuse this
/// legitimate merge; the roots-closure check must not.
#[test]
fn orphaned_left_cone_does_not_count_toward_the_output_ceiling() {
    let mut base = InfinityModule::new();
    let cfg_base = push_int_table(&mut base, 62_140);
    let base = {
        let root = base.push(Inode::Table {
            fields: vec![("cfg".to_string(), cfg_base)],
        });
        base.set_root(Some(root));
        base
    };
    let mut left = InfinityModule::new();
    let bulk = push_int_table(&mut left, 200_001);
    let cfg_left = push_int_table(&mut left, 62_140);
    let left = {
        let root = left.push(Inode::Table {
            fields: vec![("bulk".to_string(), bulk), ("cfg".to_string(), cfg_left)],
        });
        left.set_root(Some(root));
        left
    };
    let mut right = InfinityModule::new();
    let one = right.push(Inode::Int(1));
    let right = {
        let root = right.push(Inode::Table {
            fields: vec![("cfg".to_string(), one)],
        });
        right.set_root(Some(root));
        right
    };
    assert_eq!(base.node_count(), 62_142);
    assert_eq!(left.node_count(), MAX_MERGE_NODES);
    assert_eq!(right.node_count(), 2);
    // The arena at the pre-encode check: left (262,144) + 1 imported
    // node = 262,145 — over the ceiling. The output is not.
    assert!(
        left.node_count() + 1 > MAX_MERGE_NODES,
        "test shape is wrong: the arena must exceed the ceiling"
    );
    let merged = match merge::merge(&base, &left, &right).expect("merge") {
        Merge::Clean(module) => module,
        Merge::Conflicts(conflicts) => panic!("expected a clean merge, got {conflicts:?}"),
    };
    // root + bulk table + 200,001 bulk ints + cfg Int(1).
    assert_eq!(merged.node_count(), 200_004);
    let root = merged.root().expect("root");
    let Inode::Table { fields } = merged.get(root).expect("root node") else {
        panic!("root is not a table");
    };
    let cfg = fields
        .iter()
        .find(|(name, _)| name == "cfg")
        .map(|(_, id)| *id)
        .expect("cfg field");
    assert_eq!(merged.get(cfg), Some(&Inode::Int(1)));
}

/// Test 5 — a binding target no field reaches still counts toward the
/// output ceiling.
///
/// Root-cone output is exactly at the ceiling (262,144): left `a`
/// (131,073 nodes) + imported `b` cone (131,071). Left also carries an
/// extra `Int` node bound as `bb` that no field references; the encoder
/// keeps it because a binding target is a root, so the true output is
/// 262,145 and the merge must refuse. A root-only count would see
/// 262,144 and pass the pre-check; the post-decode backstop would still
/// refuse, so this test passes at HEAD too — it pins that the
/// binding-rooted node counts, not the timing of the refusal.
#[test]
fn binding_only_node_counts_toward_the_output_ceiling() {
    let base = empty_root();
    let mut left = InfinityModule::new();
    let a = push_int_table(&mut left, 131_071);
    let extra = left.push(Inode::Int(7));
    left.bind("bb", extra);
    let left = {
        let root = left.push(Inode::Table {
            fields: vec![("a".to_string(), a)],
        });
        left.set_root(Some(root));
        left
    };
    let mut right = InfinityModule::new();
    let b = push_int_table(&mut right, 131_070);
    let right = {
        let root = right.push(Inode::Table {
            fields: vec![("b".to_string(), b)],
        });
        right.set_root(Some(root));
        right
    };
    assert_eq!(left.node_count(), 131_074);
    assert_eq!(right.node_count(), 131_072);
    let (code, message) = err_kind_message(merge::merge(&base, &left, &right));
    assert_eq!(code, "infinity/limit", "{message}");
    assert!(
        message.contains("merge output nodes"),
        "expected the output-nodes limit, got: {message}"
    );
}
