//! INF-07 regression probe (fail-before / pass-after).
//!
//! Round-1 finding INF-07 (AUDIT-REPORT.md §B.3): `SecretBytes::eq` always
//! returns false — including for self — while `InfinityModule::eq` treats
//! `(Secret, Secret)` as equal. The two equality notions disagree, so any
//! generic code (`assert_eq!` on a node, `vec.contains`, dedup) that uses
//! `Inode::eq` directly gets the opposite answer to `InfinityModule::eq`.
//! `structurally_eq` also returns false when `prepare()` errors on either
//! side, so a module with a dangling reference is not equal to itself.
//!
//! The fix (audit recommendation (b), unified `node_eq` as the single
//! implementation): `Inode::Secret == Inode::Secret` is true — presence-only,
//! still no oracle, since it reveals only "both are secrets", which the kind
//! already reveals — and `structurally_eq` falls back to a raw-arena
//! comparison when `prepare()` fails, with `try_structurally_eq()` exposing
//! the tri-state (equal / different / unpreparable).
//!
//! This file is the fail-before probe: it was written against the pre-fix
//! API only and run before the fix, where it FAILED on the node-level,
//! dangling-module and NaN assertions (5 failed / 4 passed), proving the
//! divergence. After the fix every test passes; the
//! `try_structurally_eq_distinguishes_different_from_unpreparable` test was
//! added with the fix itself, since `try_structurally_eq` did not exist
//! pre-fix.

use active_infinity::{InfinityModule, Inode, NodeId, SecretBytes};

fn secret_module(secret: &str) -> InfinityModule {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from(secret)));
    let root = module.push(Inode::Table {
        fields: vec![("password".to_string(), secret)],
    });
    module.set_root(Some(root));
    module
}

#[test]
fn secret_bytes_value_never_equals_anything() {
    // The anti-oracle property lives at the SecretBytes (value) level and
    // must survive the fix unchanged: a secret value never equals anything,
    // including itself, so no comparison can confirm a guess.
    let first = SecretBytes::from("hunter2");
    let second = SecretBytes::from("hunter2");
    assert_ne!(
        first, second,
        "identical secret values must not compare equal"
    );
    assert_ne!(first, first.clone(), "a secret must not equal itself");
    assert_ne!(
        SecretBytes::from("hunter2"),
        SecretBytes::from("correct-horse"),
        "different secret values must not compare equal"
    );
    assert_ne!(
        SecretBytes::from("short"),
        SecretBytes::from("a-much-longer-secret"),
        "different-length secret values must not compare equal"
    );
}

#[test]
fn secret_node_equals_itself() {
    // FAIL-BEFORE: Inode::Secret == itself is false pre-fix (derived
    // PartialEq calls SecretBytes::eq, always false).
    let node = Inode::Secret(SecretBytes::from("hunter2"));
    assert_eq!(node, node.clone(), "a secret node must equal itself");
    assert_eq!(node, node, "a secret node must be reflexive");
}

#[test]
fn secret_nodes_compare_by_presence_only() {
    // FAIL-BEFORE: false pre-fix. Presence-only: the result is independent
    // of the secret contents, so equality can never become a guessing
    // oracle — two different secrets compare equal, exactly as two modules
    // holding different secrets already compare equal at module level.
    let first = Inode::Secret(SecretBytes::from("hunter2"));
    let second = Inode::Secret(SecretBytes::from("correct-horse-battery"));
    assert_eq!(
        first, second,
        "two secret nodes compare equal by presence only, regardless of content"
    );
    assert_eq!(
        Inode::Secret(SecretBytes::from("a")),
        Inode::Secret(SecretBytes::from("b")),
        "presence-only equality must not depend on the bytes at all"
    );
}

#[test]
fn secret_node_is_not_equal_to_other_kinds() {
    // Presence-only must not leak into a blanket true: a secret is equal
    // only to another secret.
    let secret = Inode::Secret(SecretBytes::from("hunter2"));
    assert_ne!(secret, Inode::Str("hunter2".to_string()));
    assert_ne!(secret, Inode::SecretRef { locator: NodeId(0) });
    assert_ne!(secret, Inode::Null);
    assert_ne!(secret, Inode::Int(0));
    assert_ne!(Inode::Str("x".to_string()), secret);
}

#[test]
fn node_level_and_module_level_agree() {
    // FAIL-BEFORE: module == clone is true pre-fix while the node-level
    // comparison of the very same secret node is false. After the fix the
    // two levels must agree everywhere generic code can observe them.
    let module = secret_module("hunter2");
    let clone = module.clone();
    assert_eq!(module, clone, "module equality is reflexive for secrets");
    for (index, node) in module.nodes().iter().enumerate() {
        let twin = &clone.nodes()[index];
        assert_eq!(
            node, twin,
            "node {index} ({node:?}) must agree with module-level equality"
        );
        assert_eq!(node, node, "node {index} must equal itself");
    }
    // Generic code paths that previously gave the opposite answer to the
    // module level: contains / position / dedup over nodes.
    let secret = Inode::Secret(SecretBytes::from("hunter2"));
    assert!(
        module.nodes().contains(&secret),
        "vec.contains over nodes must find the secret the module holds"
    );
    assert_eq!(
        module.nodes().iter().position(|n| *n == secret),
        Some(0),
        "position over nodes must find the secret node"
    );
}

#[test]
fn module_equality_still_blinds_secret_content() {
    // Already true pre-fix (W4 d3/d5); pinned so the fix cannot regress it
    // into a content comparison.
    let first = secret_module("hunter2");
    let second = secret_module("correct-horse-battery-staple");
    assert_eq!(
        first, second,
        "modules holding different secrets compare equal (presence-only)"
    );
    let third = secret_module("hunter2");
    assert_eq!(first, third);
    // But a structural difference is still a difference.
    let mut different = secret_module("hunter2");
    different.push(Inode::Int(1));
    assert_ne!(
        first, different,
        "an extra node is still a difference (INF-04 guard)"
    );
}

#[test]
fn dangling_module_equals_its_clone() {
    // FAIL-BEFORE: structurally_eq returns false when prepare() errors, so
    // a module with a dangling reference is not equal to itself. After the
    // fix the raw-arena fallback makes == reflexive even for unpreparable
    // modules, while try_structurally_eq() still reports the error.
    let mut bad = InfinityModule::new();
    let dangling = bad.push(Inode::Ref(NodeId(999)));
    bad.set_root(Some(dangling));
    let clone = bad.clone();
    assert_eq!(
        bad, clone,
        "an unpreparable module must still equal its clone"
    );
    assert_eq!(bad, bad, "an unpreparable module must be reflexive");
    assert!(
        !bad.structurally_eq(&secret_module("hunter2")),
        "an unpreparable module must not equal a different valid module"
    );
    let mut other_bad = InfinityModule::new();
    let other_dangling = other_bad.push(Inode::Ref(NodeId(555)));
    other_bad.set_root(Some(other_dangling));
    assert_ne!(
        bad, other_bad,
        "two unpreparable modules with different dangling refs must differ"
    );
}

#[test]
fn float_nan_node_equals_itself_by_bits() {
    // node_eq compares floats by bits so a NaN is equal to itself at module
    // level; the derived Inode PartialEq used f64 eq, where NaN != NaN.
    // FAIL-BEFORE at node level.
    let nan = Inode::Float(f64::NAN);
    assert_eq!(
        nan,
        nan.clone(),
        "a NaN float node must equal itself (bitwise)"
    );
    assert_eq!(
        Inode::Float(1.5),
        Inode::Float(1.5),
        "ordinary floats still compare by value"
    );
    assert_ne!(Inode::Float(1.5), Inode::Float(2.5));
    assert_ne!(
        Inode::Float(f64::NAN),
        Inode::Float(f64::from_bits(0x7ff8_0000_0000_0001)),
        "NaNs with different payload bits are different nodes"
    );
}

#[test]
fn try_structurally_eq_distinguishes_different_from_unpreparable() {
    // The tri-state form (added with the fix): Ok(true/false) when both
    // modules prepare, Err when either side cannot be prepared — so a
    // caller can tell "different" apart from "invalid", which `==` (by
    // design, via the raw-arena fallback) does not.
    let valid = secret_module("hunter2");
    let other_secret = secret_module("correct-horse-battery");
    assert_eq!(
        valid.try_structurally_eq(&other_secret),
        Ok(true),
        "different secrets are presence-only equal, canonically"
    );
    let mut different = secret_module("hunter2");
    different.push(Inode::Int(1));
    assert_eq!(
        valid.try_structurally_eq(&different),
        Ok(false),
        "a structural difference is Ok(false), not an error"
    );

    let mut bad = InfinityModule::new();
    let dangling = bad.push(Inode::Ref(NodeId(999)));
    bad.set_root(Some(dangling));
    assert!(
        bad.try_structurally_eq(&bad.clone()).is_err(),
        "an unpreparable module reports Err, not Ok(false)"
    );
    assert!(
        bad.try_structurally_eq(&valid).is_err(),
        "comparing an unpreparable module against a valid one is Err"
    );
    assert!(
        valid.try_structurally_eq(&bad).is_err(),
        "the error surfaces regardless of argument order"
    );
    // And `==` still agrees with the Ok cases, while staying reflexive on
    // the Err cases via the raw-arena fallback.
    assert!(valid == other_secret);
    assert!(valid != different);
    assert!(bad == bad.clone());
}

#[test]
fn non_secret_node_equality_is_unchanged() {
    // The manual PartialEq must reproduce the derived one exactly for every
    // non-secret, non-float variant.
    assert_eq!(Inode::Null, Inode::Null);
    assert_eq!(Inode::Bool(true), Inode::Bool(true));
    assert_ne!(Inode::Bool(true), Inode::Bool(false));
    assert_eq!(Inode::Int(-7), Inode::Int(-7));
    assert_ne!(Inode::Int(1), Inode::Int(2));
    assert_eq!(Inode::Str("a".to_string()), Inode::Str("a".to_string()));
    assert_ne!(Inode::Str("a".to_string()), Inode::Str("b".to_string()));
    assert_eq!(Inode::Ref(NodeId(3)), Inode::Ref(NodeId(3)));
    assert_ne!(Inode::Ref(NodeId(3)), Inode::Ref(NodeId(4)));
    assert_eq!(
        Inode::Array {
            elements: vec![NodeId(0), NodeId(1)]
        },
        Inode::Array {
            elements: vec![NodeId(0), NodeId(1)]
        }
    );
    assert_ne!(
        Inode::Array {
            elements: vec![NodeId(0)]
        },
        Inode::Array {
            elements: vec![NodeId(1)]
        }
    );
    assert_ne!(Inode::Null, Inode::Bool(false), "different variants differ");
    assert_ne!(
        Inode::Int(0),
        Inode::Float(0.0),
        "different variants differ"
    );
    assert_ne!(
        Inode::SecretRef { locator: NodeId(1) },
        Inode::SecretRef { locator: NodeId(2) },
        "SecretRef still compares its locator"
    );
}
