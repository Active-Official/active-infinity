//! INF-16: a store enforces the limits its deployment configures.
//!
//! Before the fix, `Store::open` took only a root and every path hardcoded
//! `Limits::default()` (1 GiB objects): a deployment that wanted strict
//! limits — say 8 MiB objects — could not enforce them through the store at
//! all. The verifier's reproduction (W4, `w4_inf16_store_no_limits`) put a
//! 16,789,776-byte object into a store with no way to refuse it, and API
//! inspection found no `open_with_limits`/`with_limits` anywhere in the
//! crate.
//!
//! The fix adds `Store::open_with_limits` / `Store::with_limits` plus the
//! `limits()` and `object_limit()` accessors, and threads the configured
//! limits through `put`, `get`, `put_signed`, `get_signature`
//! (`put_module` and `get_verified` go through `put`/`get`/`get_signature`,
//! so they inherit the ceiling). `Store::open` is exactly
//! `open_with_limits(root, Limits::default())`, so default behaviour is
//! unchanged.
//!
//! The probe images: one 2 MiB materialised blob (over a 1 MiB ceiling, far
//! under the 1 GiB default) and 200 distinct 64 KiB blobs totalling
//! ~12.8 MiB (over `Limits::strict()`'s 8 MiB total ceiling while every
//! single blob stays under its 1 MiB blob ceiling, so the refusal is the
//! total-bytes ceiling and nothing else). The 2 MiB image is the
//! fail-before shape:
//! pre-fix the default store accepted it and `open_with_limits` did not
//! exist (compile error E0599).

use active_infinity::{encode, InfinityModule, Inode, Limits, Store};

/// A 1 MiB total ceiling, every other ceiling at its default: the strict
/// deployment's object cap, isolated from every other limit.
fn one_mebibyte() -> Limits {
    Limits {
        max_total_bytes: 1 << 20,
        ..Limits::default()
    }
}

/// One 2 MiB materialised blob as the module root: a valid canonical image
/// of ~2 MiB + header.
fn big_image() -> Vec<u8> {
    let payload = vec![0xABu8; 2 << 20];
    let hash = *blake3::hash(&payload).as_bytes();
    let mut module = InfinityModule::new();
    let blob = module.push(Inode::Blob {
        hash,
        size: payload.len() as u64,
        tainted: false,
        media_type: "application/octet-stream".to_string(),
        payload: Some(payload),
    });
    module.set_root(Some(blob));
    encode(&module).expect("encode 2 MiB module")
}

/// 200 nodes with 200 DISTINCT 64 KiB payloads: ~12.8 MiB of image, every
/// blob 64 KiB (under `Limits::strict()`'s 1 MiB blob ceiling), the total
/// over its 8 MiB ceiling. The payloads must be distinct: the encoder
/// stores one copy of a shared payload (the 100-node shared-payload image
/// in `decode_budget_tests` is only ~65 KiB on the wire — its 6.5 MB is
/// the decoded materialisation, not the image), so shared payloads would
/// never reach the total ceiling.
fn many_small_blobs_image() -> Vec<u8> {
    let mut module = InfinityModule::new();
    let mut elems = Vec::new();
    for i in 0..200u32 {
        // Distinct fill byte per blob, so each payload hashes differently
        // and the encoder stores all 200 copies.
        let payload = vec![(i % 251) as u8; 64 << 10];
        let hash = *blake3::hash(&payload).as_bytes();
        elems.push(module.push(Inode::Blob {
            hash,
            size: payload.len() as u64,
            tainted: false,
            media_type: "application/octet-stream".to_string(),
            payload: Some(payload),
        }));
    }
    let root = module.push(Inode::Array { elements: elems });
    module.set_root(Some(root));
    encode(&module).expect("encode 200-blob module")
}

/// A small module that fits under every ceiling used here.
fn small_image() -> Vec<u8> {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("stored".into()));
    let root = module.push(Inode::Table {
        fields: vec![("name".into(), name)],
    });
    module.set_root(Some(root));
    encode(&module).expect("encode small module")
}

#[test]
fn default_store_accepts_the_two_mebibyte_image() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open(directory.path()).expect("store");
    assert_eq!(
        store.object_limit(),
        1 << 30,
        "open keeps the 1 GiB default"
    );
    assert_eq!(store.limits(), Limits::default());
    let image = big_image();
    assert!(
        image.len() > (1 << 20),
        "probe image must exceed a 1 MiB ceiling: {} bytes",
        image.len()
    );
    let hash = store.put(&image).expect("default store accepts it");
    assert_eq!(store.get(&hash).expect("get"), image);
}

#[test]
fn open_with_limits_refuses_an_oversized_put() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open_with_limits(directory.path(), one_mebibyte()).expect("store");
    assert_eq!(store.object_limit(), 1 << 20);
    assert_eq!(store.limits().max_total_bytes, 1 << 20);
    let image = big_image();
    let error = store.put(&image).expect_err("a 1 MiB store must refuse it");
    assert_eq!(error.code(), "infinity/limit");
    assert!(
        error.to_string().contains("1048576"),
        "the refusal names the configured ceiling: {error}"
    );
    assert!(store.is_empty(), "a refused put writes nothing");
    // The refusal is the ceiling, not the image: the same bytes go in
    // through a default-limits handle over the same root.
    let loose = Store::open(directory.path()).expect("default store");
    loose.put(&image).expect("default store accepts it");
    assert_eq!(loose.len(), 1);
}

#[test]
fn open_with_limits_accepts_small_objects_and_round_trips_them() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open_with_limits(directory.path(), one_mebibyte()).expect("store");
    let image = small_image();
    assert!(image.len() < (1 << 20), "small image under the ceiling");
    let hash = store.put(&image).expect("put under the ceiling");
    assert_eq!(store.put(&image).expect("dedupe"), hash);
    assert_eq!(store.len(), 1);
    assert_eq!(store.get(&hash).expect("get"), image);
}

#[test]
fn with_limits_derives_a_limited_handle_and_leaves_the_original_alone() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open(directory.path()).expect("store");
    let limited = store.with_limits(one_mebibyte()).expect("with_limits");
    assert_eq!(limited.object_limit(), 1 << 20);
    assert_eq!(store.object_limit(), 1 << 30, "the original is unaffected");
    let image = big_image();
    let error = limited
        .put(&image)
        .expect_err("the derived handle refuses it");
    assert_eq!(error.code(), "infinity/limit");
    assert!(store.is_empty(), "the refused put wrote nothing");
    // The original handle still accepts the same image afterwards.
    let hash = store.put(&image).expect("original accepts it");
    assert_eq!(store.get(&hash).expect("get"), image);
    // An invalid configuration fails before touching anything.
    let zero = Limits {
        max_total_bytes: 0,
        ..Limits::default()
    };
    let error = store
        .with_limits(zero)
        .expect_err("a zero ceiling is an argument error");
    assert_eq!(error.code(), "infinity/invalid-argument");
}

#[test]
fn limited_get_refuses_an_object_above_its_ceiling() {
    let directory = tempfile::tempdir().expect("tempdir");
    let loose = Store::open(directory.path()).expect("default store");
    let image = big_image();
    let hash = loose.put(&image).expect("put under the loose handle");
    // The same root under a 1 MiB ceiling: the object is there, but this
    // handle must not read above its ceiling — and must not say why: the
    // refusal is the store's own code, exactly like an absent object
    // (otherwise the code would be an existence oracle for the name).
    let strict = Store::open_with_limits(directory.path(), one_mebibyte()).expect("store");
    let error = strict.get(&hash).expect_err("limited get must refuse it");
    assert_eq!(error.code(), "infinity/store");
    // The object itself is untouched: the loose handle still reads it.
    assert_eq!(loose.get(&hash).expect("loose get"), image);
}

#[test]
fn open_with_limits_rejects_a_zero_ceiling_before_creating_a_directory() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("never-created");
    let zero = Limits {
        max_total_bytes: 0,
        ..Limits::default()
    };
    let error = Store::open_with_limits(&root, zero).expect_err("zero ceiling refused");
    assert_eq!(error.code(), "infinity/invalid-argument");
    assert!(
        error.to_string().contains("max_total_bytes"),
        "the refusal names the field: {error}"
    );
    assert!(!root.exists(), "a bad configuration creates no directory");
}

#[test]
fn strict_profile_limits_apply_to_the_store() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open_with_limits(directory.path(), Limits::strict()).expect("store");
    assert_eq!(store.object_limit(), 8 << 20);
    let image = many_small_blobs_image();
    assert!(
        image.len() > (8 << 20),
        "probe image must exceed the 8 MiB strict ceiling: {} bytes",
        image.len()
    );
    let error = store.put(&image).expect_err("strict store must refuse it");
    assert_eq!(error.code(), "infinity/limit");
    assert!(store.is_empty());
    let loose = Store::open(directory.path()).expect("default store");
    loose.put(&image).expect("default store accepts it");
}

#[cfg(feature = "signatures")]
#[test]
fn limited_put_signed_is_refused_and_writes_no_envelope() {
    use active_infinity::SignedImage;
    use ed25519_dalek::SigningKey;

    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open_with_limits(directory.path(), one_mebibyte()).expect("store");
    let image = big_image();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let signed = SignedImage::sign(image, &key).expect("sign");
    let error = store
        .put_signed(&signed)
        .expect_err("a 1 MiB store must refuse the signed oversized image");
    assert_eq!(error.code(), "infinity/limit");
    assert!(store.is_empty(), "no object and no envelope were written");
}

#[cfg(feature = "signatures")]
#[test]
fn limited_get_signature_is_refused_for_an_envelope_above_its_ceiling() {
    use active_infinity::SignedImage;
    use ed25519_dalek::SigningKey;

    let directory = tempfile::tempdir().expect("tempdir");
    let loose = Store::open(directory.path()).expect("default store");
    let image = big_image();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let signed = SignedImage::sign(image, &key).expect("sign");
    let hash = loose.put_signed(&signed).expect("put_signed");
    // The envelope (~2 MiB image + overhead) exceeds the 1 MiB ceiling
    // plus the envelope overhead, so the limited handle refuses the read
    // with the limit code — `get_signature` has no existence-oracle
    // mapping to apply, unlike `get`.
    let strict = Store::open_with_limits(directory.path(), one_mebibyte()).expect("store");
    let error = strict
        .get_signature(&hash)
        .expect_err("limited get_signature must refuse it");
    assert_eq!(error.code(), "infinity/limit");
    // The loose handle still reads the envelope, and the limited handle's
    // authenticity path refuses through `get` with the store code.
    assert!(loose
        .get_signature(&hash)
        .expect("loose get_signature")
        .is_some());
    let error = strict
        .get_verified(&hash, None)
        .expect_err("limited get_verified must refuse it");
    assert_eq!(error.code(), "infinity/store");
}
