#![cfg(feature = "signatures")]

//! The store's authenticity path: a signed object verifies, and every way of
//! breaking the envelope is refused with `infinity/signature`.
//!
//! `Store::get` proves integrity only. `Store::get_verified` also requires a
//! detached envelope that covers exactly the requested bytes, and optionally
//! pins the signing key.

use std::fs;

use active_infinity::{decode, encode, InfinityModule, Inode, SignedImage, Store};

fn image(label: &str) -> Vec<u8> {
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Str(label.to_string()));
    module.set_root(Some(value));
    encode(&module).expect("encode")
}

fn sandbox(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "active-store-signature-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("sandbox");
    dir
}

fn name(hash: &[u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn a_signed_object_verifies_and_reports_its_key() {
    let dir = sandbox("round-trip");
    let store = Store::open(&dir).expect("store");
    let bytes = image("signed");
    let signed = SignedImage::sign_with_seed(bytes.clone(), &[9u8; 32]).expect("sign");
    let hash = store.put_signed(&signed).expect("put signed");

    assert_eq!(hash, signed.content_hash().expect("hash"));
    assert_eq!(store.get_verified(&hash, None).expect("verified"), bytes);
    assert_eq!(
        store
            .get_verified_with_key(&hash, &signed.public_key)
            .expect("verified with the raw key"),
        bytes
    );

    let stored = store
        .get_signature(&hash)
        .expect("signature")
        .expect("present");
    assert_eq!(stored.public_key, signed.public_key);
    assert_eq!(stored.image, bytes);

    // The raw path is untouched: it still returns the image and never requires
    // a signature.
    assert_eq!(store.get(&hash).expect("raw get"), bytes);
    fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn an_unsigned_object_is_refused_on_the_authenticity_path() {
    let dir = sandbox("unsigned");
    let store = Store::open(&dir).expect("store");
    let hash = store.put(&image("plain")).expect("put");
    let error = store
        .get_verified(&hash, None)
        .expect_err("an unsigned object must not verify");
    assert_eq!(error.code(), "infinity/signature");
    assert!(store.get_signature(&hash).expect("signature").is_none());
    fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn a_tampered_envelope_is_refused() {
    let dir = sandbox("tamper-envelope");
    let store = Store::open(&dir).expect("store");
    let signed = SignedImage::sign_with_seed(image("tampered"), &[3u8; 32]).expect("sign");
    let hash = store.put_signed(&signed).expect("put signed");

    let path = dir.join(format!("{}.sig", name(&hash)));
    let mut bytes = fs::read(&path).expect("read envelope");
    // The envelope is magic(4) + version(1) + public key(32) + signature(64) +
    // image. Flip a signature byte so the image stays valid and the signature
    // check is the one that fires.
    bytes[5 + 32 + 4] ^= 0x01;
    fs::write(&path, &bytes).expect("write tampered envelope");

    let error = store
        .get_verified(&hash, None)
        .expect_err("a tampered envelope must be refused");
    assert_eq!(error.code(), "infinity/signature");
    fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn an_envelope_for_another_object_is_refused() {
    let dir = sandbox("cross-object");
    let store = Store::open(&dir).expect("store");
    let first = SignedImage::sign_with_seed(image("first"), &[4u8; 32]).expect("sign first");
    let first_hash = store.put_signed(&first).expect("put first");
    let second = SignedImage::sign_with_seed(image("second"), &[4u8; 32]).expect("sign second");
    let second_hash = store.put(&second.image).expect("put second");

    // Copy the first object's envelope onto the second object's hash.
    let first_sig = dir.join(format!("{}.sig", name(&first_hash)));
    let second_sig = dir.join(format!("{}.sig", name(&second_hash)));
    fs::copy(&first_sig, &second_sig).expect("copy envelope");

    let error = store
        .get_signature(&second_hash)
        .expect_err("an envelope for another object must be refused");
    assert_eq!(error.code(), "infinity/signature");
    fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn a_trusted_key_pins_the_signer() {
    let dir = sandbox("trusted-key");
    let store = Store::open(&dir).expect("store");
    let signed = SignedImage::sign_with_seed(image("pinned"), &[5u8; 32]).expect("sign");
    let hash = store.put_signed(&signed).expect("put signed");

    store
        .get_verified_with_key(&hash, &signed.public_key)
        .expect("the trusted key verifies");
    let other = SignedImage::sign_with_seed(image("other"), &[6u8; 32]).expect("sign");
    let error = store
        .get_verified_with_key(&hash, &other.public_key)
        .expect_err("another key must not verify");
    assert_eq!(error.code(), "infinity/signature");
    assert!(error.to_string().contains("another key"), "{error}");
    fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn put_signed_refuses_an_envelope_that_does_not_verify() {
    let dir = sandbox("bad-envelope");
    let store = Store::open(&dir).expect("store");
    let mut signed = SignedImage::sign_with_seed(image("mutated"), &[7u8; 32]).expect("sign");
    // Corrupt the signature, leaving the image valid: the signature check is
    // the one that must refuse the envelope.
    signed.signature[0] ^= 0x01;
    let error = store
        .put_signed(&signed)
        .expect_err("an invalid envelope must not be stored");
    assert_eq!(error.code(), "infinity/signature");
    assert!(store.is_empty());
    fs::remove_dir_all(&dir).expect("cleanup");
}

/// A corrupted image inside an otherwise well-formed envelope is refused by
/// validation before the signature is even considered: a bad image is never
/// stored under a signature that claims it is canonical.
#[test]
fn put_signed_refuses_a_corrupted_image() {
    let dir = sandbox("corrupt-image");
    let store = Store::open(&dir).expect("store");
    let mut signed = SignedImage::sign_with_seed(image("corrupt"), &[10u8; 32]).expect("sign");
    let last = signed.image.len() - 1;
    signed.image[last] ^= 0x01;
    let error = store
        .put_signed(&signed)
        .expect_err("a corrupted image must not be stored");
    assert!(error.code().starts_with("infinity/"), "{error}");
    assert_ne!(
        error.code(),
        "infinity/signature",
        "the image is refused first"
    );
    assert!(store.is_empty());
    fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn the_signed_object_round_trips_through_the_same_bytes() {
    let dir = sandbox("canonical");
    let store = Store::open(&dir).expect("store");
    let signed = SignedImage::sign_with_seed(image("canonical"), &[8u8; 32]).expect("sign");
    let hash = store.put_signed(&signed).expect("put signed");
    let recovered = store.get_verified(&hash, None).expect("verified");
    let module = decode(&recovered).expect("decode");
    assert_eq!(encode(&module).expect("encode"), recovered);
    fs::remove_dir_all(&dir).expect("cleanup");
}
