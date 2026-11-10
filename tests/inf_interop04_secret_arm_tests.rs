//! Regression tests for INF-INTEROP-04: `to_active_core` had a dead
//! `Secret -> CoreValue::Secret(plaintext)` arm behind the `has_secret`
//! gate (`src/interop.rs:593-595` at HEAD `d5c4533`).
//!
//! The arm was dead today -- the gate in `to_active_core` refuses any
//! secret-bearing module first, and the existing
//! `lowering_is_idempotent_through_active_core` test proves the gate works
//! -- but it was a loaded footgun: any future refactor that moves or
//! bypasses the gate would export secret plaintext into `active-core`,
//! where a secret is a plain string. The fix makes the arm return `Err`
//! exactly like the `Blob` and `ContentAddressed` arms do, with the gate's
//! own message, and deletes the plaintext construction entirely.
//!
//! The arm is unreachable from any public entry point: `convert_node` is
//! private inside `mod bridge`, its only caller is `to_active_core`, and
//! the gate scans every node (`has_secret` / `Inode::is_secret` covers
//! both `Secret` literals and `SecretRef` locators). No integration test
//! can reach the arm past the gate, so the arm itself is pinned by the
//! unit test `bridge::tests::convert_node_refuses_a_secret_node` in
//! `src/interop.rs`, which calls `convert_node` directly with a `Secret`
//! node and asserts `Err`. The tests here pin the behaviour-preserving
//! public surface: a secret-bearing module is still refused by
//! `to_active_core` with exactly the same error as before the fix, in
//! every position a secret can sit, and the refusal never carries the
//! plaintext. The sibling `Blob` / `ContentAddressed` refusals and the
//! plain-module control pin the arms around the fix.

#![cfg(feature = "active-core")]

use active_infinity::interop::to_active_core;
use active_infinity::{InfinityModule, Inode, SecretBytes};

const CANARY: &str = "hunter2-canary-interop04";

/// The exact error the gate reports (and the arm now reports too):
/// `Error::Encode` displays as `cannot encode module: <message>`.
const SECRET_REFUSAL: &str = "cannot encode module: the active-core bridge does not export secret material; keep the module in Infinity";

/// A module whose root is a table holding the given nodes as fields.
fn table_module(fields: Vec<(&str, Inode)>) -> InfinityModule {
    let mut module = InfinityModule::new();
    let ids: Vec<(String, active_infinity::NodeId)> = fields
        .into_iter()
        .map(|(name, node)| (name.to_string(), module.push(node)))
        .collect();
    let root = module.push(Inode::Table { fields: ids });
    module.set_root(Some(root));
    module
}

/// A secret literal nested inside a table field -- the gate scans every
/// node, so position must not matter, and neither must the arm.
fn secret_in_table_module() -> InfinityModule {
    table_module(vec![("password", Inode::Secret(SecretBytes::from(CANARY)))])
}

/// Assert `to_active_core` refuses the module with the secret error, and
/// that the refusal never carries the plaintext.
fn assert_secret_refusal(module: &InfinityModule, what: &str) {
    let error =
        to_active_core(module).expect_err(&format!("{what} must be refused by to_active_core"));
    assert_eq!(error.code(), "infinity/encode", "{error}");
    assert_eq!(
        error.to_string(),
        SECRET_REFUSAL,
        "{what} must be refused with exactly the gate's message; got {error}"
    );
    assert!(
        !error.to_string().contains(CANARY),
        "{what}: the refusal must not carry the plaintext anywhere; got {error}"
    );
}

/// The finding's shape: a secret literal, nested in a table rather than at
/// the root, is still refused with exactly the pre-fix error. Behaviour
/// preserving by construction -- the gate trips before the arm either way.
#[test]
fn secret_literal_nested_in_a_table_is_refused() {
    let module = secret_in_table_module();
    assert!(module.has_secret(), "the fixture must carry a secret");
    assert_secret_refusal(&module, "a secret literal nested in a table");
}

/// The secret as the root itself: same refusal, same message.
#[test]
fn secret_literal_as_root_is_refused() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from(CANARY)));
    module.set_root(Some(secret));
    assert_secret_refusal(&module, "a secret literal as the root");
}

/// A `SecretRef` locator is a secret too (`Inode::is_secret` covers it),
/// so the gate refuses it with the same message -- the locator form must
/// never be the way around the refusal.
#[test]
fn secret_ref_locator_is_refused() {
    let mut module = InfinityModule::new();
    let locator = module.push(Inode::Str("env.TOKEN".to_string()));
    let secret_ref = module.push(Inode::SecretRef { locator });
    let root = module.push(Inode::Array {
        elements: vec![secret_ref],
    });
    module.set_root(Some(root));
    assert!(module.has_secret(), "the fixture must carry a secret");
    assert_secret_refusal(&module, "a SecretRef locator");
}

/// A secret node that nothing reaches is still a node in the arena, so the
/// gate -- which scans all nodes, not just the reachable cone -- refuses
/// the module. An unreachable secret is still a secret in the module.
#[test]
fn unreachable_secret_is_refused() {
    let mut module = InfinityModule::new();
    let _secret = module.push(Inode::Secret(SecretBytes::from(CANARY)));
    let root = module.push(Inode::Str("plain".to_string()));
    module.set_root(Some(root));
    assert!(module.has_secret(), "the fixture must carry a secret");
    assert_secret_refusal(&module, "an unreachable secret node");
}

/// Control: the sibling `Blob` arm still refuses with its own message,
/// unchanged by the fix.
#[test]
fn blob_module_is_still_refused_by_the_sibling_arm() {
    let hash = *blake3::hash(b"interop04-blob").as_bytes();
    let module = table_module(vec![(
        "data",
        Inode::Blob {
            hash,
            size: 13,
            tainted: false,
            media_type: "application/octet-stream".to_string(),
            payload: Some(b"interop04-blob".to_vec()),
        },
    )]);
    let error = to_active_core(&module).expect_err("a blob module must be refused");
    assert_eq!(error.code(), "infinity/encode", "{error}");
    assert_eq!(
        error.to_string(),
        "cannot encode module: active-core 1.4.0 has no blob value; keep the module in Infinity",
        "the Blob arm must keep its own message; got {error}"
    );
}

/// Control: the sibling `ContentAddressed` arm still refuses with its own
/// message, unchanged by the fix.
#[test]
fn content_addressed_module_is_still_refused_by_the_sibling_arm() {
    let mut module = InfinityModule::new();
    let media_type = module.push(Inode::Str("text/plain".to_string()));
    let data = module.push(Inode::Str("hello".to_string()));
    let addressed = module.push(Inode::ContentAddressed { media_type, data });
    let root = module.push(Inode::Array {
        elements: vec![addressed],
    });
    module.set_root(Some(root));
    let error = to_active_core(&module).expect_err("a content-addressed module must be refused");
    assert_eq!(error.code(), "infinity/encode", "{error}");
    assert_eq!(
        error.to_string(),
        "cannot encode module: active-core 1.4.0 has no ContentAddressed node kind",
        "the ContentAddressed arm must keep its own message; got {error}"
    );
}

/// Control: a plain module with no secret, blob, or content-addressed node
/// still lowers, unchanged by the fix.
#[test]
fn plain_module_still_lowers() {
    let module = table_module(vec![
        ("name", Inode::Str("infinity-integration".to_string())),
        ("port", Inode::Int(8080)),
        ("debug", Inode::Bool(true)),
    ]);
    let core = to_active_core(&module).expect("a plain module must still lower");
    assert_eq!(core.arena.len(), 4, "all four nodes must lower");
}
