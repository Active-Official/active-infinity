//! C-4.1/C-4.2/C-4.5 store, signature and projection agreement.

use active_infinity::{content_hash, encode, InfinityModule, Inode, Store};

fn module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("stored".into()));
    let secret = module.push(Inode::Secret(active_infinity::SecretBytes::from(
        "store-canary",
    )));
    let root = module.push(Inode::Table {
        fields: vec![("name".into(), name), ("secret".into(), secret)],
    });
    module.set_root(Some(root));
    module
}

#[test]
fn store_round_trips_deduplicates_and_reprojects() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open(directory.path()).expect("store");
    let image = encode(&module()).expect("encode");
    let hash = store.put(&image).expect("put");
    assert_eq!(store.len(), 1);
    assert!(store.contains(&hash));
    assert_eq!(store.put(&image).expect("dedupe"), hash);
    assert_eq!(store.len(), 1);
    let restored = store.get(&hash).expect("get");
    assert_eq!(restored, image);
    assert_eq!(content_hash(&restored).unwrap(), hash);

    let instance = active_infinity::decode(&restored).expect("decode");
    #[cfg(feature = "json")]
    {
        let json = active_infinity::interop::to_redacted_json(&instance).expect("json");
        assert!(!json.contains("store-canary"));
    }
    let proto = active_infinity::to_protobuf(&instance).expect("protobuf");
    assert!(!String::from_utf8_lossy(&proto).contains("store-canary"));
}

#[test]
fn store_rejects_a_non_image() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open(directory.path()).expect("store");
    let error = store.put(b"not an image").expect_err("reject");
    assert_eq!(error.code(), "infinity/magic");
    assert!(store.is_empty());
}

#[cfg(feature = "signatures")]
#[test]
fn signed_store_object_verifies_and_rejects_tampering() {
    use active_infinity::SignedImage;
    use ed25519_dalek::SigningKey;

    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open(directory.path()).expect("store");
    let image = encode(&module()).expect("encode");
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let signed = SignedImage::sign(image, &key).expect("sign");
    let envelope = signed.to_bytes();
    let parsed = SignedImage::from_bytes(&envelope).expect("verify");
    let hash = store.put(&parsed.image).expect("put");
    assert_eq!(parsed.content_hash().unwrap(), hash);
    let mut tampered = envelope;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(SignedImage::from_bytes(&tampered).is_err());
}
