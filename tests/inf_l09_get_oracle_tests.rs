//! INF-L09: `Store::get` must not distinguish "wrong key" from "absent"
//! (INF-STORE-01).
//!
//! The audit's probe P-O planted a valid image under another hash's name and
//! found **three** distinguishable `get` failure messages: "object does not
//! match its key" (hash mismatch), "object not found" (absent name) and
//! "object is absent or unreadable" (validation / oversized faults). A
//! prober who can plant (or observe) a file under a chosen filename learns
//! whether that name holds a corrupt/wrong-key object vs nothing at all --
//! the exact oracle the module doc (`src/store.rs`, threat model) says a
//! service must not forward.
//!
//! The fix collapses every `get` failure -- read fault, validation fault,
//! hash mismatch -- to the one generic message "object is absent or
//! unreadable" (code `infinity/store`). These tests pin that contract from
//! the outside, by planting files directly under object names and comparing
//! the full `Display` of the error, not just the code (every path already
//! shared the `infinity/store` code; the oracle was message-only).
//!
//! Planting shapes, one per failure branch of `get`:
//! - absent name: `read_bounded` reports NotFound ("object not found").
//! - valid image under another hash's name: the hash check ("object does
//!   not match its key").
//! - malformed planted bytes: `validate_canonical` fails (already generic).
//! - a directory at the object path: `read_bounded` refuses non-files
//!   ("object is not a regular file").
//! - an oversized planted file: `read_bounded` reports `Error::Limit`,
//!   already mapped to the generic message by `store_read_fault`.
//!
//! The remaining `read_bounded` messages ("cannot inspect object",
//! "cannot read object", "object changed while it was opened") are race
//! windows between metadata and open, not plantable deterministically; they
//! collapse through the same `store_read_fault` change, which maps *every*
//! error, not just non-`Store` ones.

use active_infinity::{content_hash, encode, InfinityModule, Inode, Limits, Store};

/// The one answer `get` gives for every failure (INF-L09).
const GENERIC: &str = "store failed: object is absent or unreadable";

fn module(label: &str) -> InfinityModule {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str(label.into()));
    let root = module.push(Inode::Table {
        fields: vec![("name".into(), name)],
    });
    module.set_root(Some(root));
    module
}

/// Object filename for a hash: `<64 lowercase hex>.ainf`.
fn object_name(hash: &[u8; 32]) -> String {
    let mut name = String::with_capacity(69);
    for byte in hash {
        name.push_str(&format!("{byte:02x}"));
    }
    name.push_str(".ainf");
    name
}

fn store_at(root: &std::path::Path) -> Store {
    Store::open(root).expect("store")
}

/// The full `Display` of a `get` failure, with its code asserted on the way.
fn get_failure(store: &Store, hash: &[u8; 32]) -> String {
    let error = store.get(hash).expect_err("get must fail here");
    assert_eq!(error.code(), "infinity/store", "error: {error}");
    error.to_string()
}

#[test]
fn absent_hash_get_fails_with_the_generic_message() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = store_at(directory.path());
    // No file was ever planted under this name.
    assert_eq!(get_failure(&store, &[0x11u8; 32]), GENERIC);
}

#[test]
fn wrong_key_image_get_fails_with_the_same_message_as_absent() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = store_at(directory.path());
    let image = encode(&module("planted")).expect("encode planted");
    let other = encode(&module("other")).expect("encode other");
    let other_hash = content_hash(&other).expect("hash other");
    // Plant a valid image under another hash's name: the audit's probe P-O.
    // `get` validates it fine, then the hash check must not speak up.
    std::fs::write(directory.path().join(object_name(&other_hash)), &image).expect("plant image");
    let wrong_key = get_failure(&store, &other_hash);
    let absent = get_failure(&store, &[0x11u8; 32]);
    assert_eq!(wrong_key, absent, "wrong-key vs absent must be one answer");
    assert_eq!(wrong_key, GENERIC);
}

#[test]
fn malformed_planted_file_get_fails_with_the_same_message_as_absent() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = store_at(directory.path());
    let hash = [0x22u8; 32];
    std::fs::write(
        directory.path().join(object_name(&hash)),
        b"not an image at all, just planted bytes",
    )
    .expect("plant garbage");
    assert_eq!(get_failure(&store, &hash), GENERIC);
    assert_eq!(get_failure(&store, &[0x11u8; 32]), GENERIC);
}

#[test]
fn directory_at_object_path_get_fails_with_the_same_message_as_absent() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = store_at(directory.path());
    let hash = [0x33u8; 32];
    std::fs::create_dir(directory.path().join(object_name(&hash))).expect("plant dir");
    let not_a_file = get_failure(&store, &hash);
    let absent = get_failure(&store, &[0x11u8; 32]);
    assert_eq!(not_a_file, absent, "non-file vs absent must be one answer");
    assert_eq!(not_a_file, GENERIC);
}

#[test]
fn oversized_planted_file_get_fails_with_the_same_message_as_absent() {
    let directory = tempfile::tempdir().expect("tempdir");
    // A 1 KiB ceiling, every other ceiling at its default: the planted file
    // is over the ceiling while staying far under the 1 GiB default.
    let limits = Limits {
        max_total_bytes: 1 << 10,
        ..Limits::default()
    };
    let store = Store::open_with_limits(directory.path(), limits).expect("store");
    let hash = [0x44u8; 32];
    std::fs::write(
        directory.path().join(object_name(&hash)),
        vec![0xABu8; 2 << 10],
    )
    .expect("plant oversized");
    assert_eq!(get_failure(&store, &hash), GENERIC);
    assert_eq!(get_failure(&store, &[0x11u8; 32]), GENERIC);
}

#[test]
fn all_get_failure_modes_are_indistinguishable() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = store_at(directory.path());
    let image = encode(&module("planted")).expect("encode planted");
    let other = encode(&module("other")).expect("encode other");
    let other_hash = content_hash(&other).expect("hash other");
    std::fs::write(directory.path().join(object_name(&other_hash)), &image).expect("plant image");
    let garbage_hash = [0x22u8; 32];
    std::fs::write(
        directory.path().join(object_name(&garbage_hash)),
        b"not an image at all, just planted bytes",
    )
    .expect("plant garbage");
    let dir_hash = [0x33u8; 32];
    std::fs::create_dir(directory.path().join(object_name(&dir_hash))).expect("plant dir");

    let messages = [
        ("absent", get_failure(&store, &[0x11u8; 32])),
        ("wrong-key", get_failure(&store, &other_hash)),
        ("malformed", get_failure(&store, &garbage_hash)),
        ("directory", get_failure(&store, &dir_hash)),
    ];
    for (label, message) in &messages {
        assert_eq!(
            message, GENERIC,
            "{label} must answer with the one generic message, got: {message}"
        );
    }
    let first = &messages[0].1;
    assert!(
        messages.iter().all(|(_, message)| message == first),
        "messages differ across failure modes: {messages:?}"
    );
}

#[test]
fn stored_object_still_gets() {
    // Positive control: collapsing the failure messages must not touch the
    // happy path.
    let directory = tempfile::tempdir().expect("tempdir");
    let store = store_at(directory.path());
    let image = encode(&module("stored")).expect("encode");
    let hash = store.put(&image).expect("put");
    assert_eq!(store.get(&hash).expect("get"), image);
}
