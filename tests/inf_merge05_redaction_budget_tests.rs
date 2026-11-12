//! Regression tests for INF-MERGE-05: the provenance and extensions
//! redaction budgets are not cumulative (local copies never written back).
//!
//! Round-1 report `AUDIT-REPORT.md:923`: `src/merge.rs:607, 622` (at the
//! audit's line numbers). `provenance_budget` / `extensions_budget` copy
//! the shared redaction budget into locals never written back (contrast
//! `annotation_keys`, which does write back). Each section gets a fresh
//! full `MAX_MERGE_WORK` budget — up to ~3x the intended redaction work.
//! **Fix (audit):** write the locals back with `self.redaction.set(...)`
//! after each section.
//!
//! Round 2 (`AUDIT-REPORT-ROUND2.md`, INF-MERGE-05) probe-verified it:
//! three identical modules, each with a 150,000-char provenance producer
//! and a 150,000-byte extension payload, plus one unreachable secret node
//! (so no field conflicts). Redaction cost (`canonical::redaction_cost`)
//! is `secrets.len() x text.len() x 8` = 1 x 150,000 x 8 = 1,200,000 per
//! `redact_within` call. Per section: left + right = 2,400,000. Combined
//! across both sections: 4,800,000 > `MAX_MERGE_WORK` 4,194,304 — so
//! cumulative budgets would refuse at the extensions right key (1,794,304
//! remaining < 1,200,000). Observed on HEAD: `result_is_clean=true`. The
//! merge succeeds only because each section gets a fresh budget.
//!
//! Correction to the round-2 probe's own arithmetic, recorded here so the
//! numbers below are exact: the probe comment says "3 modules x 1.2M =
//! 3.6M per section, 7.2M combined", counting the base key. The base key
//! is only computed when left and right differ (`metadata_plan` keys the
//! base only inside `if left_key != right_key`), and these modules are
//! identical, so the base is never keyed. The true spend is 2 x 1.2M =
//! 2.4M per section and 4.8M combined. The conclusion is unchanged —
//! the combined spend still exceeds the 4,194,304 ceiling — and every
//! total below is asserted in-test against `MAX_MERGE_WORK` so the claim
//! is checkable, not argued.
//!
//! The fix writes both locals back (`self.redaction.set(...)` after the
//! provenance block and after the extensions block), so the three
//! metadata sections — provenance, extensions, annotations — share one
//! cumulative `MAX_MERGE_WORK` redaction budget, exactly as the `Ctx`
//! field already documents ("Cumulative budget for redacting labels")
//! and exactly as `field_label` and `annotation_keys` already do. The
//! post-fix behaviour for the round-2 shape is a fail-closed
//! `<extensions>` conflict (the extensions arm returns `None` on
//! exhaustion and the caller conflicts), not an error: the merge
//! refuses the comparison it can no longer afford instead of merging
//! on a budget it never had.
//!
//! Fail-before / pass-after at HEAD `6e483af` (INF-MERGE-04):
//!
//! * Test 1 is the round-2 probe shape verbatim. It FAILS at HEAD (the
//!   merge is Clean) and PASSES after the fix (exactly one conflict,
//!   `<extensions>` / `KindMismatch`).
//! * Tests 2 and 3 pin the single-section fits: provenance alone and
//!   extensions alone at 2.4M each stay Clean. They pass at HEAD and
//!   after the fix, and they pin the fix against over-refusal.
//! * Test 4 pins the exact cumulative boundary, inclusive: provenance
//!   150,000 + extensions 112,144 spends exactly `MAX_MERGE_WORK`
//!   (4,194,304) and merges Clean. It passes at HEAD and after the fix.
//!   The boundary is inclusive because `redact_within` refuses only
//!   when `cost > budget`, not when `cost == budget`.
//! * Test 5 is one step past that boundary (extensions 112,145, total
//!   `MAX_MERGE_WORK` + 16). It FAILS at HEAD (Clean) and PASSES after
//!   the fix (exactly one `<extensions>` conflict).
//! * Test 6 pins that the cumulative budget reaches the third section:
//!   provenance + extensions spend 3.2M, leaving 994,304, and an
//!   annotation Intent text costing 1.2M then fails the redaction with
//!   `Limit{"projection redaction scan bytes"}`. It FAILS at HEAD
//!   (Clean — the annotation comparison starts from a fresh full
//!   budget there) and PASSES after the fix (`Err`, code
//!   `infinity/limit`). The error propagates past `metadata_plan`
//!   even though no conflict was pushed yet, so the merge returns the
//!   error, not a conflict report.
//!
//! No test here asserts a wall-clock bound: the budgets are pure
//! integer arithmetic on text lengths, so the outcomes are
//! deterministic in every profile.

use active_infinity::{
    merge::{self, MAX_MERGE_WORK},
    AnnotationKind, ConflictKind, InfinityModule, Inode, Merge, Provenance, SecretBytes,
};

/// One redaction of a text of `len` bytes against one secret costs
/// `1 x len x 8` (`canonical::redaction_cost`: one scan per secret,
/// eight passes). Asserted here so a change to the cost function fails
/// these tests loudly instead of silently moving the boundaries below.
const COST_PER_BYTE: usize = 8;

/// Build the round-2 probe shape: a root table with one field `a =
/// Int(1)`, one unreachable secret node (unreachable nodes still count
/// for `secret_texts`, which scans `module.nodes()`, so the secret
/// makes every redaction charge without causing a field conflict), an
/// optional provenance producer of `producer_len` bytes, and an
/// optional extension payload (tag 7) of `extension_len` bytes.
///
/// A length of 0 means the component is absent.
fn build(producer_len: usize, extension_len: usize) -> InfinityModule {
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Int(1));
    let root = module.push(Inode::Table {
        fields: vec![("a".to_string(), value)],
    });
    module.set_root(Some(root));
    let _unreachable_secret = module.push(Inode::Secret(SecretBytes::new(b"hunter2".to_vec())));
    if producer_len > 0 {
        module.set_provenance(Some(Provenance {
            producer: Some("p".repeat(producer_len)),
            ..Provenance::default()
        }));
    }
    if extension_len > 0 {
        module.add_extension(7, "p".repeat(extension_len).into_bytes());
    }
    module
}

/// The `Merge::Clean` module, or a panic naming what was got instead.
fn expect_clean(result: Merge) -> InfinityModule {
    match result {
        Merge::Clean(module) => *module,
        Merge::Conflicts(conflicts) => panic!("expected a clean merge, got {conflicts:?}"),
    }
}

/// Exactly one conflict, on the given field with the given kind.
fn expect_single_conflict(result: Merge, field: &str, kind: ConflictKind) {
    match result {
        Merge::Clean(_) => panic!("expected a conflict on {field}, got a clean merge"),
        Merge::Conflicts(conflicts) => {
            assert_eq!(
                conflicts.len(),
                1,
                "expected exactly one conflict, got {conflicts:?}"
            );
            assert_eq!(conflicts[0].field, field, "{conflicts:?}");
            assert_eq!(conflicts[0].kind, kind, "{conflicts:?}");
        }
    }
}

/// The redaction cost of keying one section (left + right) whose text
/// is `len` bytes: two `redact_within` calls, one per side. The base
/// key is never computed for identical modules.
fn section_cost(len: usize) -> usize {
    2 * len * COST_PER_BYTE
}

/// Test 1 — the round-2 probe shape verbatim: identical modules with a
/// 150,000-char provenance producer and a 150,000-byte extension
/// payload, plus one unreachable secret.
///
/// Per section: left + right = 2,400,000. Combined: 4,800,000, which
/// exceeds `MAX_MERGE_WORK` (4,194,304) by 605,696. After the fix the
/// extensions right key cannot be afforded (1,794,304 remaining <
/// 1,200,000) and the merge fails closed with one `<extensions>`
/// conflict. At HEAD the merge is Clean.
#[test]
fn provenance_and_extensions_together_exceed_one_budget() {
    assert_eq!(MAX_MERGE_WORK, 4_194_304);
    let combined = section_cost(150_000) + section_cost(150_000);
    assert_eq!(combined, 4_800_000);
    assert!(
        combined > MAX_MERGE_WORK,
        "test shape is wrong: the combined spend must exceed the budget"
    );
    // The provenance section alone fits; only the two sections together
    // exceed the budget. That is the finding: either section in
    // isolation passes, and only cumulative accounting refuses.
    assert!(section_cost(150_000) < MAX_MERGE_WORK);

    let base = build(150_000, 150_000);
    let left = build(150_000, 150_000);
    let right = build(150_000, 150_000);
    let result = merge::merge(&base, &left, &right).expect("merge");
    eprintln!("INF-MERGE-05 test 1: result={result:?}");
    expect_single_conflict(result, "<extensions>", ConflictKind::KindMismatch);
}

/// Test 2 — provenance alone, at the round-2 size, merges cleanly.
///
/// 2,400,000 < 4,194,304, so the provenance section fits in one budget
/// with or without cumulative accounting. Pins the fix against
/// over-refusal: a cumulative budget must not refuse a spend that fits.
#[test]
fn provenance_alone_under_the_budget_merges_cleanly() {
    assert!(section_cost(150_000) < MAX_MERGE_WORK);
    let base = build(150_000, 0);
    let left = build(150_000, 0);
    let right = build(150_000, 0);
    let merged = expect_clean(merge::merge(&base, &left, &right).expect("merge"));
    let expected = "p".repeat(150_000);
    assert_eq!(
        merged.provenance().unwrap().producer.as_deref(),
        Some(expected.as_str())
    );
}

/// Test 3 — extensions alone, at the round-2 size, merge cleanly.
///
/// Same arithmetic as test 2, for the other section.
#[test]
fn extensions_alone_under_the_budget_merge_cleanly() {
    assert!(section_cost(150_000) < MAX_MERGE_WORK);
    let base = build(0, 150_000);
    let left = build(0, 150_000);
    let right = build(0, 150_000);
    let merged = expect_clean(merge::merge(&base, &left, &right).expect("merge"));
    assert_eq!(merged.extensions().len(), 1);
    assert_eq!(merged.extensions()[0].0, 7);
    assert_eq!(merged.extensions()[0].1.len(), 150_000);
}

/// Test 4 — the exact cumulative boundary, inclusive: provenance
/// 150,000 + extensions 112,144 spends exactly `MAX_MERGE_WORK`.
///
/// Provenance: 2 x 150,000 x 8 = 2,400,000, leaving 1,794,304.
/// Extensions left: 112,144 x 8 = 897,152, leaving 897,152.
/// Extensions right: 897,152, leaving exactly 0. `redact_within`
/// refuses only when `cost > budget`, so the equal-cost call succeeds
/// and the merge is Clean. Pins the boundary against an off-by-one in
/// either direction: a `>=` refusal would conflict here, and a
/// miscounted cost would too.
#[test]
fn cumulative_spend_exactly_at_the_budget_merges_cleanly() {
    let total = section_cost(150_000) + section_cost(112_144);
    assert_eq!(total, MAX_MERGE_WORK);
    let base = build(150_000, 112_144);
    let left = build(150_000, 112_144);
    let right = build(150_000, 112_144);
    let merged = expect_clean(merge::merge(&base, &left, &right).expect("merge"));
    assert_eq!(merged.extensions()[0].1.len(), 112_144);
}

/// Test 5 — one step past the boundary: extensions 112,145, total
/// `MAX_MERGE_WORK` + 16.
///
/// Extensions right needs 897,160 with 897,144 remaining, so
/// `extensions_key` returns `None` and the merge fails closed with
/// one `<extensions>` conflict. At HEAD the merge is Clean: the
/// extensions section restarts from a fresh full budget and never
/// sees the 2,400,000 the provenance section spent.
#[test]
fn cumulative_spend_one_step_over_the_budget_conflicts_on_extensions() {
    let total = section_cost(150_000) + section_cost(112_145);
    assert_eq!(total, MAX_MERGE_WORK + 16);
    let base = build(150_000, 112_145);
    let left = build(150_000, 112_145);
    let right = build(150_000, 112_145);
    let result = merge::merge(&base, &left, &right).expect("merge");
    eprintln!("INF-MERGE-05 test 5: result={result:?}");
    expect_single_conflict(result, "<extensions>", ConflictKind::KindMismatch);
}

/// Test 6 — the cumulative budget reaches the annotations section.
///
/// Provenance 100,000 (1,600,000) + extensions 100,000 (1,600,000)
/// spend 3,200,000, leaving 994,304. An annotation Intent text of
/// 150,000 chars costs 1,200,000 on the left `annotation_keys` call —
/// more than the remainder — so `redact_within` fails and the merge
/// returns `Err(Limit{"projection redaction scan bytes"})`. At HEAD the
/// annotation comparison starts from a fresh full budget (the two
/// earlier sections never wrote back), so the same text fits and the
/// merge is Clean.
///
/// The annotation is identical on all three sides and its subject is
/// the plain `Int(1)` field value, so no `<annotations>` conflict and
/// no secret-field conflict can fire: the error is purely the spent
/// cumulative budget. The error propagates out of `metadata_plan`
/// before any field is decided, so the merge returns the error rather
/// than a conflict report.
#[test]
fn annotations_share_the_cumulative_budget() {
    let spent = section_cost(100_000) + section_cost(100_000);
    assert_eq!(spent, 3_200_000);
    let remaining = MAX_MERGE_WORK - spent;
    assert_eq!(remaining, 994_304);
    let annotation_cost = 150_000 * COST_PER_BYTE;
    assert_eq!(annotation_cost, 1_200_000);
    assert!(
        annotation_cost > remaining,
        "test shape is wrong: the annotation text must exceed the remainder"
    );
    assert!(
        annotation_cost < MAX_MERGE_WORK,
        "test shape is wrong: the annotation text must fit in a fresh budget"
    );

    let build_with_annotation = || {
        let mut module = build(100_000, 100_000);
        let root = module.root().expect("root");
        let Inode::Table { fields } = module.get(root).expect("root node") else {
            panic!("root is not a table");
        };
        let value = fields
            .iter()
            .find(|(name, _)| name == "a")
            .map(|(_, id)| *id)
            .expect("a field");
        module.annotate(value, AnnotationKind::Intent("i".repeat(150_000)));
        module
    };
    let base = build_with_annotation();
    let left = build_with_annotation();
    let right = build_with_annotation();
    let error = merge::merge(&base, &left, &right).expect_err("the merge must refuse");
    assert_eq!(error.code(), "infinity/limit", "{error}");
    assert!(
        error
            .to_string()
            .contains("projection redaction scan bytes"),
        "expected the redaction limit, got: {error}"
    );
    // The limit VALUE is deliberately not asserted: `redact_within`
    // reports `PROJECTION_REDACTION_BUDGET` (256 MiB) even though the
    // budget it charged is the merge's `MAX_MERGE_WORK` — a pre-existing
    // oddity in the error text, out of scope for this fix (see the
    // INF-MERGE-05 record §6.4). Only the code and the kind are pinned.
}
