//! Regression tests for INF-09: `validate_structure(max_depth=0)` meant
//! "no ceiling" while `Limits::check` rejected 0, and `prepare()` passed
//! 0 — encode ran unbounded while decode refused anything deeper than
//! `Limits::default().max_depth` (4096). W4 proved it with a 5000-deep
//! chain that encoded fine (200,264 bytes) but failed default decode
//! with `infinity/depth`.
//!
//! The fix removes the magic 0: `check_depth(0)` — and therefore
//! `validate_structure(..., 0)` — is `Error::InvalidArgument` (the same
//! message `Limits::check` uses, so one value can never mean two things),
//! and `prepare()` — hence `encode()` — passes
//! `Limits::default().max_depth`, so encode refuses what decode refuses.
//! The `from_active_core` lowering path takes the same ceiling, and
//! `project_root` spells its 4096 as the same named default instead of a
//! literal. The depth ceiling and the INF-06 working-bytes budget agree
//! because both are read off `Limits::default()`: a module at the depth
//! ceiling still fits the working budget, and a module past it is refused
//! before any Kahn pass allocates.

use active_infinity::{
    decode, encode, validate, validate_with, DecodeOpts, Error, InfinityModule, Inode, Limits, UnOp,
};

#[path = "deep_chain_image.rs"]
mod deep_chain_image;

/// A unary chain of `depth` nodes: the leaf `Int` is depth `depth`, the
/// root `Unary` depth 1. (W4's INF-09 reproduction used this shape.)
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
fn default_max_depth_is_4096() {
    // The named ceiling every leg below assumes. If the default ever
    // moves, the boundary tests move with it through
    // `Limits::default().max_depth`; this pins the value itself.
    assert_eq!(Limits::default().max_depth, 4096);
    assert_eq!(Limits::strict().max_depth, 128);
}

#[test]
fn check_depth_zero_is_an_argument_error() {
    // The old reading: `0` meant "no ceiling" — an empty module passed
    // and a shallow module passed, silently. The new reading: `0` is
    // rejected for every module, exactly as `Limits::check` rejects a
    // zero `max_depth` — the ceiling is a property of the argument, not
    // of the module, so the two can never disagree about what 0 means.
    let empty = InfinityModule::new();
    let error = empty
        .check_depth(0)
        .expect_err("check_depth(0) must be an argument error, even empty");
    assert_eq!(error.code(), "infinity/invalid-argument", "{error}");
    assert!(
        error.to_string().contains("max_depth must be non-zero"),
        "{error}"
    );
    let shallow = chain(3);
    let error = shallow
        .validate_structure(u64::MAX, 0)
        .expect_err("validate_structure(..., 0) must be an argument error");
    assert_eq!(error.code(), "infinity/invalid-argument", "{error}");
    assert!(
        error.to_string().contains("max_depth must be non-zero"),
        "{error}"
    );
    // The positive side is unchanged: no nodes, no depth fault.
    empty.check_depth(4096).expect("no nodes, no depth fault");
    shallow
        .check_depth(4096)
        .expect("depth 3 under the ceiling");
}

#[test]
fn limits_check_rejects_zero_max_depth() {
    // The other half of the contradiction, pinned so the agreement holds:
    // `Limits::check` already refused 0 before this fix, and still does.
    let limits = Limits {
        max_depth: 0,
        ..Limits::default()
    };
    let error = limits
        .check()
        .expect_err("Limits::check must reject max_depth 0");
    assert_eq!(error.code(), "infinity/invalid-argument", "{error}");
    assert!(
        error.to_string().contains("max_depth must be non-zero"),
        "{error}"
    );
    Limits::default().check().expect("default limits pass");
}

#[test]
fn encode_refuses_a_chain_deeper_than_the_default_ceiling() {
    // W4's reproduction, turned around: the 5000-deep chain (depth 5001)
    // encoded fine before the fix and failed default decode with
    // `infinity/depth`. After the fix encode refuses it first, with the
    // same code and the default ceiling as the limit — so no image
    // `encode()` produces can be one the default decoder refuses.
    let deep = chain(5001);
    let error = encode(&deep).expect_err("encode must refuse depth 5001");
    assert_depth_refusal(&error);
}

#[test]
fn encode_refuses_the_first_chain_past_the_ceiling() {
    // Boundary: depth 4097 is the first depth past the ceiling.
    let past = chain(4097);
    let error = encode(&past).expect_err("encode must refuse depth 4097");
    assert_depth_refusal(&error);
}

#[test]
fn encode_accepts_a_chain_at_the_default_ceiling_and_it_round_trips() {
    // Boundary: depth 4096 is the last depth the ceiling allows, and it
    // must still encode, validate and decode — the fix refuses only what
    // is past the ceiling, it does not shrink the accepted set.
    let at_ceiling = chain(4096);
    let bytes = encode(&at_ceiling).expect("encode must accept depth 4096");
    validate(&bytes).expect("a depth-4096 image validates");
    let decoded = decode(&bytes).expect("a depth-4096 image decodes");
    assert_eq!(decoded.node_count(), 4096);
    assert!(
        decoded.root().is_some(),
        "the round-tripped module keeps a root"
    );
    // Canonical renumbering moves the root id (pre-order from the roots),
    // so the round-trip is compared canonically, not by arena id.
    assert_eq!(decoded, at_ceiling, "encode/decode round-trips canonically");
}

#[test]
fn decode_refuses_a_hand_built_chain_deeper_than_the_ceiling() {
    // The decode half of W4's asymmetry, proved at the wire level without
    // going through `encode()` (which now refuses first): a hand-built
    // 5001-deep `Ref`-chain image is refused by default limits, and the
    // same bytes validate when the caller raises the ceiling — so the
    // refusal is the ceiling, not the bytes.
    let bytes = deep_chain_image::build_ref_chain_image(5001);
    let error = validate(&bytes).expect_err("default limits refuse depth 5001");
    assert_depth_refusal(&error);
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
fn try_structurally_eq_reports_the_depth_refusal() {
    // `prepare()` is the ceiling's enforcement point, and
    // `try_structurally_eq` is its second caller (besides `encode()`):
    // a module past the ceiling is unpreparable, so the comparison
    // reports the refusal instead of silently comparing. (The `==`
    // form falls back to the raw-arena comparison on prepare failure,
    // INF-07, so it still answers `true` for a module against its own
    // clone — only the tri-state form surfaces the error.)
    let deep = chain(5001);
    let error = deep
        .try_structurally_eq(&deep.clone())
        .expect_err("a depth-5001 module is unpreparable");
    assert_depth_refusal(&error);
    let shallow = chain(3);
    assert!(
        shallow
            .try_structurally_eq(&shallow.clone())
            .expect("a shallow module prepares"),
        "a shallow module still compares canonically"
    );
}
