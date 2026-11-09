#![no_main]
//! The content-addressed store takes hostile images: `put` must validate
//! before publishing, `get` must return exactly the bytes that were put, an
//! unsigned object must refuse `get_verified`, and a signed object must
//! verify back to the same bytes (INF-POLY-05).

use libfuzzer_sys::fuzz_target;

use active_infinity::{SignedImage, Store};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fresh store directory per iteration, so no state leaks between runs.
fn tempdir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fuzz-store-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("a temp store directory");
    dir
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 || data.len() > 65_536 {
        return;
    }
    // Length-prefixed split, so a seed can name a whole image exactly:
    // [image_len:u16 LE][image][probe...].
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let (image, probe) = if data.len() - 2 < len {
        (&data[2..], &[][..])
    } else {
        data[2..].split_at(len)
    };
    let dir = tempdir();
    let store = Store::open(&dir).expect("a temp store opens");
    match store.put(image) {
        Ok(hash) => {
            assert!(store.contains(&hash), "a put object is contained");
            let back = store.get(&hash).expect("a put object reads back");
            assert_eq!(back, image, "the store returns exactly the bytes put");
            // The same image puts idempotently to the same address.
            assert_eq!(
                store.put(image).expect("a repeat put succeeds"),
                hash,
                "a repeat put keeps the address"
            );
            // Unsigned: a verified read refuses (no signature is stored).
            if let Err(error) = store.get_verified(&hash, None) {
                assert!(
                    error.code().starts_with("infinity/"),
                    "unverified read refusal without a codec code: {error}"
                );
            } else {
                panic!("an unsigned object verified");
            }
            // Signing the same image publishes a verifiable object at the
            // same address.
            let signed =
                SignedImage::sign_with_seed(image.to_vec(), &[7u8; 32]).expect("a put image signs");
            assert_eq!(
                store.put_signed(&signed).expect("a signed object stores"),
                hash,
                "the signature does not change the address"
            );
            let verified = store
                .get_verified(&hash, None)
                .expect("a signed object verifies");
            assert_eq!(verified, image, "a verified read returns the put bytes");
        }
        Err(error) => assert!(
            error.code().starts_with("infinity/"),
            "store put refusal without a codec code: {error}"
        ),
    }
    // A hash that was never put must refuse with a codec code (or, when the
    // probe happens to name the put object, return exactly those bytes).
    if probe.len() >= 32 {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&probe[..32]);
        match store.get(&hash) {
            Ok(back) => assert_eq!(back, image, "a colliding probe reads the put bytes"),
            Err(error) => assert!(
                error.code().starts_with("infinity/"),
                "store get refusal without a codec code: {error}"
            ),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
});
