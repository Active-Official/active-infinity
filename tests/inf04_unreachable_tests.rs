//! INF-04 regression tests: `encode()` must fail closed on unreachable nodes.
//!
//! Before the fix, `encode()` silently dropped every node unreachable from
//! the module roots (including unreachable `Secret` nodes) and returned `Ok`,
//! while `structurally_eq` (hence `PartialEq`) compared only the prepared
//! (reachable) form and reported the dropped module as equal to the original.
//! The wire validator, by contrast, refuses unreachable nodes — so the
//! in-memory and wire invariants disagreed.
//!
//! After the fix: `encode()` refuses an unreachable node
//! (`Error::Node { reason: "unreachable node" }`, code `infinity/node`)
//! unless the caller explicitly opts in with
//! `EncodeOpts { drop_unreachable: true, ..Default::default() }` (the
//! stream-delta and merge paths, which replace a subtree without compacting
//! the arena). `structurally_eq` also sees an extra unreachable node: two
//! modules with different raw node counts are never equal.

use active_infinity::layout::EncodeOpts;
use active_infinity::{decode, encode, encode_with, InfinityModule, Inode, SecretBytes};

/// A module whose root is a string, plus one unreachable secret node.
/// This is the audit's probe P-C, word for word.
fn module_with_unreachable_secret() -> InfinityModule {
    let mut m = InfinityModule::new();
    let s = m.push(Inode::Str("hello".into()));
    let secret = m.push(Inode::Secret(SecretBytes::new(
        b"top-secret-value".to_vec(),
    )));
    let _ = secret;
    m.set_root(Some(s));
    assert!(m.has_secret());
    m
}

/// The same module without the unreachable secret.
fn module_without_secret() -> InfinityModule {
    let mut m = InfinityModule::new();
    let s = m.push(Inode::Str("hello".into()));
    m.set_root(Some(s));
    m
}

#[test]
fn encode_refuses_unreachable_secret() {
    let m = module_with_unreachable_secret();
    // The fail-closed rule: the secret the author thought was stored must
    // not vanish silently from the image.
    let error = encode(&m).expect_err("encode must refuse an unreachable node");
    assert_eq!(error.code(), "infinity/node", "{error}");
    assert!(error.to_string().contains("unreachable node"), "{error}");
    // The opt-in check agrees: the wire rule, applied to the in-memory module.
    assert!(m.check_reachable().is_err());
}

#[test]
fn encode_with_drop_unreachable_opt_in_drops_and_reports_nothing() {
    let m = module_with_unreachable_secret();
    let opts = EncodeOpts {
        drop_unreachable: true,
        ..EncodeOpts::default()
    };
    let image = encode_with(&m, opts).expect("opt-in encode succeeds");
    let decoded = decode(&image).expect("opt-in image decodes");
    assert!(
        !decoded.has_secret(),
        "the opt-in drops the unreachable secret, explicitly"
    );
    // Default opts still refuse the same module: the opt-in is per call, not
    // a global mode.
    assert!(encode(&m).is_err());
}

#[test]
fn structurally_eq_sees_unreachable_secret() {
    let with = module_with_unreachable_secret();
    let without = module_without_secret();
    // Before the fix this was `true`: prepare() dropped the secret on both
    // sides and the comparison never saw it.
    assert_ne!(with, without, "an extra unreachable secret is a difference");
    assert!(
        !with.structurally_eq(&without),
        "structurally_eq must see the unreachable secret too"
    );
    // No false negatives: identical modules (same unreachable nodes) are
    // still equal, and a module equals its own clone.
    assert_eq!(with, with.clone());
    assert!(with.structurally_eq(&with.clone()));
    assert_eq!(without, without.clone());
}

#[test]
fn encode_refuses_unreachable_blob_subtree() {
    let mut m = InfinityModule::new();
    let root = m.push(Inode::Str("root".into()));
    m.set_root(Some(root));
    // An unreachable Blob node with a payload, plus a child the blob reaches
    // only through the orphaned subtree.
    let payload = m.push(Inode::Blob {
        hash: [0u8; 32],
        size: 3,
        tainted: false,
        media_type: String::new(),
        payload: Some(b"abc".to_vec()),
    });
    let _ = payload;
    let error = encode(&m).expect_err("encode must refuse an unreachable blob");
    assert_eq!(error.code(), "infinity/node", "{error}");
}

#[test]
fn encode_accepts_fully_reachable_module() {
    // Guard against over-refusal: a module where every node is reachable
    // (root, bindings, annotation subjects) still encodes fine.
    let mut m = InfinityModule::new();
    let child = m.push(Inode::Str("child".into()));
    let root = m.push(Inode::Table {
        fields: vec![("k".to_string(), child)],
    });
    m.set_root(Some(root));
    let secret = m.push(Inode::Secret(SecretBytes::new(b"pw".to_vec())));
    m.bind("secret", secret);
    let image = encode(&m).expect("fully reachable module encodes");
    let decoded = decode(&image).expect("image decodes");
    assert!(decoded.has_secret());
    assert_eq!(m, decoded, "round-trip preserves the module");
}
