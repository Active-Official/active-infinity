//! Regression tests for INF-MERGE-06: the merge work budget turns a
//! large legitimate conflicting merge into `Limit` instead of a conflict
//! report.
//!
//! Round-1 report `AUDIT-REPORT.md:924`: `src/merge.rs:381-500` (at the
//! audit's line numbers). `decide()` walks each subtree for secrets, then
//! `equal()` walks both subtrees again and re-encodes each — three
//! `equal()` calls per field; for one root field holding a 262k-node
//! subtree the arithmetic is ~2.9M of the 4.19M `MAX_MERGE_WORK` budget
//! before any nested walk. **Fix (audit):** memoize `has_secret` per
//! (module, node) within one merge (inputs are immutable), and
//! short-circuit `nested_conflicts` when the budget is nearly spent by
//! returning the parent conflict instead of erroring.
//!
//! Verification evidence, two independent probes of the same failure:
//!
//! * W4 (`results/W4-R1-INF-CORE/RESULTS-W4-R1-INF-CORE.md`,
//!   INF-MERGE-06, CONFIRMED): one root field holding a 200,000-node
//!   flat array, left and right changing different elements —
//!   `merge` returns `Err(Limit { kind: "merge work", limit: 4194304 })`
//!   in 1.64 s instead of a conflict report. Test 2 below is that shape
//!   verbatim.
//! * Round 2 (`AUDIT-REPORT-ROUND2.md`, INF-MERGE-06, upgraded): one
//!   root field `cfg` holding 64 child tables x 4,000 int leaves
//!   (256,066 nodes, just under `MAX_MERGE_NODES`); both sides change
//!   every leaf differently — `merge returned Err: merge work limit
//!   4194304 exceeded`, no conflict report at all. Test 1 below is
//!   that shape verbatim.
//!
//! The charge arithmetic, verified from the code (not just the reports)
//! — a `has_secret` walk of an N-node cone charges `2N - 1` (one per
//! traversed edge plus one per visited node) and an `image()` charges
//! `N` (one per fragment node). `decide()` on a field with no secrets
//! pays 2 `has_secret` walks of its own plus 3 `equal()` calls of 2
//! walks + 2 images each: `4N + 3 x 6N = 22N` unfixed, exactly
//! `22N - 8` (each walk charges `2N - 1`). For the round-2 shape
//! (`N = 256,065`) that is 5,633,422 > `MAX_MERGE_WORK`
//! 4,194,304 — the merge errors before it ever learns the field
//! conflicts. (The audit's "~2.9M" counts only part of the walks; the
//! `22N - 8` total is the exact unfixed cost, asserted in-test by the node
//! counts and by the fail-before runs below.)
//!
//! The fix has three parts, all in `src/merge.rs`:
//!
//! 1. `has_secret` is memoized per (module, node) within one merge
//!    (the audit's part 1, implemented literally — only the queried
//!    node's answer is cached). The three `equal()` calls then re-use
//!    the prologue's walks, so `decide()` costs `12N - 3`: 3 fresh walks
//!    (`6N - 3`) + 6 images (`6N`). For the round-2 shape that is
//!    3,072,777 < 4,194,304, so the verdict itself is established.
//! 2. Both refinement paths — `try_nested_merge` (the decide-side
//!    refinement) and `nested_conflicts` (the report-side refinement)
//!    — pre-check the remaining work budget before descending: one
//!    more level of refinement costs up to `12 x cone` (one child
//!    decision per node of the cone), so when the remainder cannot pay
//!    for even one level the parent conflict stands instead of a
//!    descent that can only die mid-way. The cone sizes come from the
//!    secret memo (measured when the node was first walked); an
//!    unmeasured cone means "unknown" and the refinement proceeds —
//!    the `Limit` catch below is the backstop.
//! 3. Any `Error::Limit` raised while refining an already-established
//!    conflict is caught and degrades to the parent conflict:
//!    `try_nested_merge` returns `None`, `nested_conflicts` returns
//!    "truncated", and the caller pushes the parent path with the
//!    already-established kind. Only `Limit` is caught — any other
//!    error still propagates. The verdict-establishing calls (the
//!    three `equal()` calls in `decide()`) still propagate `Limit` as
//!    an error: when the budget cannot even establish the verdict,
//!    there is no conflict to report.
//!
//! Two consequences are deliberate and pinned here, not hidden:
//!
//! * A large merge whose nested refinement cannot be afforded reports
//!   the parent conflict instead of the leaf paths (test 1), and a
//!   merge whose refinement dies mid-descent reports the conflicts
//!   established so far plus the parent (test 3). The report stays
//!   truthful — every listed conflict is real — it is only coarser.
//! * A large merge that would have merged cleanly through nested
//!   refinement (disjoint edits, INF-MERGE-01) but cannot afford the
//!   refinement now reports a conflict instead of erroring. That is
//!   fail-closed and strictly better than the old behaviour (an error
//!   either way before this fix); it is not a regression, and small
//!   disjoint merges still merge cleanly (test 5).
//!
//! Deliberately NOT done: memoizing `image()` as well. It would make
//! refinement nearly free, but then a 256k-leaf conflict would expand
//! into ~55,000 leaf conflicts before the 1 MiB conflict-path cap
//! stops it — trading a work-budget failure for a path-budget
//! truncation. The work-budget pre-check keeps the report small
//! instead. See the INF-MERGE-06 record §3 for the full arithmetic.
//!
//! Fail-before / pass-after at HEAD `40e6676` (TEST-13):
//!
//! * Tests 1, 2 and 3 FAIL at HEAD (`Err(Limit { kind: "merge work"
//!   })`) and PASS after the fix (a conflict report).
//! * Tests 4, 5 and 6 pass at HEAD and after the fix: they pin the
//!   fix against over-refusal (small shapes still refine), against
//!   breaking clean nested merges, and against memo corruption under
//!   node sharing.
//!
//! No test here asserts a wall-clock bound: the budgets are pure
//! integer arithmetic on node counts, so the outcomes are
//! deterministic in every profile.

use active_infinity::{
    merge::{self, MAX_MERGE_WORK},
    Conflict, ConflictKind, InfinityModule, Inode, Merge, SecretBytes,
};

/// Build the round-2 probe shape: a root table with one field `cfg`
/// holding `tables` child tables of `leaves` int leaves each. `value`
/// picks the leaf value by (table, leaf), so base/left/right share the
/// shape and differ only in content. `pad` appends that many `x`/`y`
/// characters to every table/leaf name, lengthening the conflict paths
/// (test 3 uses it so the 1 MiB conflict-path cap binds after a few
/// thousand leaves instead of ~55,000 — the descent itself is what is
/// pinned, not the push count).
///
/// Node count: 1 root + 1 `cfg` + `tables` + `tables x leaves`.
fn build_nested(
    tables: usize,
    leaves: usize,
    value: impl Fn(usize, usize) -> i64,
    pad: usize,
) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut child_tables = Vec::with_capacity(tables);
    for t in 0..tables {
        let mut fields = Vec::with_capacity(leaves);
        for f in 0..leaves {
            let id = module.push(Inode::Int(value(t, f)));
            fields.push((format!("f{f:06}{}", "y".repeat(pad)), id));
        }
        let table = module.push(Inode::Table { fields });
        child_tables.push((format!("t{t:06}{}", "x".repeat(pad)), table));
    }
    let cfg = module.push(Inode::Table {
        fields: child_tables,
    });
    let root = module.push(Inode::Table {
        fields: vec![("cfg".to_string(), cfg)],
    });
    module.set_root(Some(root));
    module
}

/// Build the W4 probe shape: a root table with one field `data`
/// holding a flat array of `len` int leaves, all `value` except the
/// one `change` (index, value), when given.
///
/// Node count: 1 root + 1 array + `len`.
fn build_array(len: usize, value: i64, change: Option<(usize, i64)>) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut elements = Vec::with_capacity(len);
    for i in 0..len {
        let v = match change {
            Some((index, changed)) if index == i => changed,
            _ => value,
        };
        elements.push(module.push(Inode::Int(v)));
    }
    let array = module.push(Inode::Array { elements });
    let root = module.push(Inode::Table {
        fields: vec![("data".to_string(), array)],
    });
    module.set_root(Some(root));
    module
}

/// The conflicts of a merge result, or a panic naming what was got
/// instead (an `Err` here is the INF-MERGE-06 failure mode itself).
fn expect_conflicts(result: Result<Merge, active_infinity::Error>) -> Vec<Conflict> {
    match result.expect("the merge must not error") {
        Merge::Conflicts(conflicts) => conflicts,
        Merge::Clean(_) => panic!("expected a conflict report, got a clean merge"),
    }
}

/// The merged module of a clean merge, or a panic naming what was got.
fn expect_clean(result: Result<Merge, active_infinity::Error>) -> InfinityModule {
    match result.expect("the merge must not error") {
        Merge::Clean(module) => *module,
        Merge::Conflicts(conflicts) => panic!("expected a clean merge, got {conflicts:?}"),
    }
}

/// The value of one leaf of a merged nested module, by (table, leaf).
fn leaf_value(module: &InfinityModule, table: usize, leaf: usize) -> i64 {
    let root = module.root().expect("root");
    let Inode::Table { fields } = module.get(root).expect("root table") else {
        panic!("root is not a table")
    };
    let cfg = fields
        .iter()
        .find(|(name, _)| name == "cfg")
        .expect("cfg field")
        .1;
    let Inode::Table { fields } = module.get(cfg).expect("cfg table") else {
        panic!("cfg is not a table")
    };
    let child = fields[table].1;
    let Inode::Table { fields } = module.get(child).expect("child table") else {
        panic!("child is not a table")
    };
    let id = fields[leaf].1;
    match module.get(id).expect("leaf") {
        Inode::Int(v) => *v,
        other => panic!("leaf is not an int: {other:?}"),
    }
}

/// Test 1 — the round-2 probe shape verbatim: 64 child tables x 4,000
/// int leaves (256,066 nodes), both sides changing every leaf
/// differently.
///
/// Unfixed `decide()` costs `22N - 8` = 5,633,422 > `MAX_MERGE_WORK`, so
/// the merge errors with `Limit("merge work")`. After the fix the
/// verdict costs `12N - 3` = 3,072,777, the refinement pre-check fires
/// (one more level would cost `12 x 256,065` = 3,072,780 against
/// 1,121,527 remaining), and the merge reports exactly the parent conflict.
#[test]
fn large_conflicting_merge_reports_a_conflict_not_a_limit() {
    let base = build_nested(64, 4_000, |_, _| 0, 0);
    let left = build_nested(64, 4_000, |_, _| 1, 0);
    let right = build_nested(64, 4_000, |_, _| 2, 0);
    assert_eq!(base.node_count(), 256_066);
    assert_eq!(left.node_count(), 256_066);
    assert_eq!(right.node_count(), 256_066);
    // The verdict alone must fit: 12 x 256,065 = 3,072,780 of the
    // 4,194,304 budget.
    assert!(12 * (base.node_count() - 1) < MAX_MERGE_WORK);
    let conflicts = expect_conflicts(merge::merge(&base, &left, &right));
    assert_eq!(
        conflicts,
        vec![Conflict {
            field: "cfg".to_string(),
            kind: ConflictKind::ModifyModify,
        }],
        "a large conflicting merge must report its parent conflict, got: {conflicts:?}"
    );
}

/// Test 2 — the W4 probe shape verbatim: one root field holding a
/// 200,000-node flat array, left and right changing different
/// elements.
///
/// Unfixed `decide()` costs `22N - 8` = 4,400,014 > `MAX_MERGE_WORK`, so
/// the merge errors with `Limit("merge work")`. After the fix the
/// verdict costs `12N - 3` = 2,400,009; an array is never descended into
/// (`table_fields` returns `None`), so the merge reports exactly the
/// parent conflict with no refinement at all.
#[test]
fn w4_flat_array_conflict_reports_a_conflict_not_a_limit() {
    let base = build_array(200_000, 0, None);
    let left = build_array(200_000, 0, Some((0, 1)));
    let right = build_array(200_000, 0, Some((1, 1)));
    assert_eq!(base.node_count(), 200_002);
    assert_eq!(left.node_count(), 200_002);
    assert_eq!(right.node_count(), 200_002);
    assert!(12 * (base.node_count() - 1) < MAX_MERGE_WORK);
    let conflicts = expect_conflicts(merge::merge(&base, &left, &right));
    assert_eq!(
        conflicts,
        vec![Conflict {
            field: "data".to_string(),
            kind: ConflictKind::ModifyModify,
        }],
        "a large conflicting array merge must report its parent conflict, got: {conflicts:?}"
    );
}

/// Test 3 — the refinement dies mid-descent, so the report degrades
/// to the conflicts established so far plus the parent: 30 child
/// tables x 4,000 leaves (120,032 nodes), both sides changing every
/// leaf differently. The names are padded to 157 characters, so a leaf
/// path is 319 bytes and the 1 MiB conflict-path cap binds after
/// ~3,287 leaf conflicts instead of ~55,188 — the descent is what is
/// pinned, and the test stays fast (an unpadded run takes ~6 minutes:
/// every leaf `image()` allocates a fragment map sized by the whole
/// 120k-node module; see the record §6).
///
/// The verdict costs `12N - 3` = 1,440,369 and the refinement pre-check
/// passes (`12 x 120,031` = 1,440,372 < 2,753,935 remaining), so the descent
/// starts — but a full descent would cost `12 x` the sum of every
/// cone below the root, far more than remains, and the 1 MiB
/// conflict-path cap stops the leaf expansion first (319-byte paths:
/// at most 3,287 leaf conflicts fit). The merge must still return a
/// conflict report — the partial leaf list plus the parent `cfg` —
/// never an error.
#[test]
fn refinement_degrades_to_the_parent_when_the_budget_dies_mid_descent() {
    let base = build_nested(30, 4_000, |_, _| 0, 150);
    let left = build_nested(30, 4_000, |_, _| 1, 150);
    let right = build_nested(30, 4_000, |_, _| 2, 150);
    assert_eq!(base.node_count(), 120_032);
    assert_eq!(left.node_count(), 120_032);
    assert_eq!(right.node_count(), 120_032);
    let conflicts = expect_conflicts(merge::merge(&base, &left, &right));
    // The parent stands for the unrefined remainder: without it the
    // report would silently omit most of the conflicting subtree.
    assert!(
        conflicts
            .iter()
            .any(|c| c.field == "cfg" && c.kind == ConflictKind::ModifyModify),
        "the degraded report must name the parent cfg, got {} conflicts",
        conflicts.len()
    );
    // The leaf expansion ran until the conflict-path cap stopped it:
    // 319-byte paths, 1 MiB cap, so ~3,287 leaf conflicts precede the
    // parent. A small count here would mean the descent never started
    // (over-refusal); zero would mean the error path was taken instead.
    assert!(
        conflicts.len() > 3_000,
        "the degraded report must hold the established leaf conflicts, got {}",
        conflicts.len()
    );
    assert!(
        conflicts
            .iter()
            .all(|c| c.kind == ConflictKind::ModifyModify),
        "every reported conflict is a genuine leaf/parent disagreement: {conflicts:?}"
    );
}

/// Test 4 — guard against over-refusal: a small conflicting merge
/// still refines to the leaf path. Only one leaf differs on each
/// side, everything else identical.
#[test]
fn small_conflicting_merge_still_reports_leaf_paths() {
    let base = build_nested(2, 3, |_, _| 0, 0);
    let left = build_nested(2, 3, |t, f| if t == 0 && f == 0 { 1 } else { 0 }, 0);
    let right = build_nested(2, 3, |t, f| if t == 0 && f == 0 { 2 } else { 0 }, 0);
    let conflicts = expect_conflicts(merge::merge(&base, &left, &right));
    assert_eq!(
        conflicts,
        vec![Conflict {
            field: "cfg.t000000.f000000".to_string(),
            kind: ConflictKind::ModifyModify,
        }],
        "a small conflict must still refine to its leaf path, got: {conflicts:?}"
    );
}

/// Test 5 — guard for INF-MERGE-01: small disjoint nested edits
/// still merge cleanly through the nested refinement. Left changes
/// one leaf of the first table, right changes one leaf of the second.
#[test]
fn small_disjoint_nested_edits_still_merge_cleanly() {
    let base = build_nested(2, 3, |_, _| 0, 0);
    let left = build_nested(2, 3, |t, f| if t == 0 && f == 0 { 1 } else { 0 }, 0);
    let right = build_nested(2, 3, |t, f| if t == 1 && f == 0 { 2 } else { 0 }, 0);
    let merged = expect_clean(merge::merge(&base, &left, &right));
    assert_eq!(leaf_value(&merged, 0, 0), 1);
    assert_eq!(leaf_value(&merged, 1, 0), 2);
    assert_eq!(leaf_value(&merged, 0, 1), 0);
    assert_eq!(leaf_value(&merged, 1, 1), 0);
}

/// Test 6 — guard for the memo itself: one secret node shared by two
/// fields must conflict on both. The second field's `has_secret` is a
/// cache hit on the same (module, node); a memo that confused nodes
/// or modules would clear one of the two fields.
///
/// The secret is never compared (`SECURITY.md` I-2): both sides hold
/// the identical secret and the base holds plain strings, yet both
/// fields conflict.
#[test]
fn memoized_secret_check_still_conflicts_on_a_shared_secret_node() {
    fn shared_secret() -> InfinityModule {
        let mut module = InfinityModule::new();
        let secret = module.push(Inode::Secret(SecretBytes::new(b"hunter2".to_vec())));
        let root = module.push(Inode::Table {
            fields: vec![("s1".to_string(), secret), ("s2".to_string(), secret)],
        });
        module.set_root(Some(root));
        module
    }
    fn plain() -> InfinityModule {
        let mut module = InfinityModule::new();
        let a = module.push(Inode::Str("plain".into()));
        let b = module.push(Inode::Str("plain".into()));
        let root = module.push(Inode::Table {
            fields: vec![("s1".to_string(), a), ("s2".to_string(), b)],
        });
        module.set_root(Some(root));
        module
    }
    let base = plain();
    let left = shared_secret();
    let right = shared_secret();
    let conflicts = expect_conflicts(merge::merge(&base, &left, &right));
    assert_eq!(
        conflicts,
        vec![
            Conflict {
                field: "s1".to_string(),
                kind: ConflictKind::ModifyModify,
            },
            Conflict {
                field: "s2".to_string(),
                kind: ConflictKind::ModifyModify,
            },
        ],
        "a secret shared by two fields must conflict on both, got: {conflicts:?}"
    );
}
