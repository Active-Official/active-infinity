//! Marathon I-10: signature envelopes and proof sidecars.
//!
//! The envelope certifies a canonical image, bounds its input, and reports every
//! rejection under one code. A sidecar accepts exactly the fields its version
//! defines and tolerates a decimal string where an integer may lose precision.

#![cfg(any(feature = "signatures", feature = "json"))]

#[cfg(feature = "signatures")]
use active_infinity::Limits;
use active_infinity::{encode, InfinityModule, Inode};

fn module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("signed".into()));
    let secret = module.push(Inode::Secret(active_infinity::SecretBytes::from(
        "signature-canary",
    )));
    let root = module.push(Inode::Table {
        fields: vec![("name".into(), name), ("secret".into(), secret)],
    });
    module.set_root(Some(root));
    module
}

#[cfg(feature = "signatures")]
fn image_hash(image: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&image[..16]);
    hasher.update(&[0u8; 32]);
    hasher.update(&image[48..]);
    *hasher.finalize().as_bytes()
}

/// A structurally valid image that re-encodes to different bytes: the canonical
/// flag is cleared and the header hash is rewritten so integrity alone passes.
#[cfg(feature = "signatures")]
fn non_canonical(image: &[u8]) -> Vec<u8> {
    let mut doctored = image.to_vec();
    doctored[8] &= !1;
    let hash = image_hash(&doctored);
    doctored[16..48].copy_from_slice(&hash);
    doctored
}

#[cfg(feature = "signatures")]
fn envelope(image: Vec<u8>, key: &ed25519_dalek::SigningKey) -> Vec<u8> {
    use ed25519_dalek::Signer;

    let mut message = b"active-infinity/signed-image/v1\0".to_vec();
    message.extend_from_slice(&image);
    let signature = key.sign(&message);
    let mut out = b"AISG".to_vec();
    out.push(1);
    out.extend_from_slice(&key.verifying_key().to_bytes());
    out.extend_from_slice(&signature.to_bytes());
    out.extend_from_slice(&image);
    out
}

#[cfg(feature = "signatures")]
#[test]
fn sign_refuses_a_non_canonical_image() {
    use active_infinity::SignedImage;
    use ed25519_dalek::SigningKey;

    let image = encode(&module()).expect("encode");
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let error = SignedImage::sign(non_canonical(&image), &key)
        .expect_err("a signature must certify reproducible bytes");
    assert_eq!(error.code(), "infinity/not-canonical", "{error}");
    assert!(SignedImage::sign(image, &key).is_ok());
}

#[cfg(feature = "signatures")]
#[test]
fn from_bytes_refuses_a_non_canonical_envelope() {
    use active_infinity::SignedImage;
    use ed25519_dalek::SigningKey;

    let key = SigningKey::from_bytes(&[10u8; 32]);
    let bytes = envelope(non_canonical(&encode(&module()).expect("encode")), &key);
    let error = SignedImage::from_bytes(&bytes).expect_err("the envelope is refused");
    assert_eq!(error.code(), "infinity/signature", "{error}");
    assert!(error.to_string().contains("does not validate"), "{error}");
}

#[cfg(feature = "signatures")]
#[test]
fn from_bytes_maps_every_image_fault_to_the_signature_code() {
    use active_infinity::SignedImage;
    use ed25519_dalek::SigningKey;

    let key = SigningKey::from_bytes(&[11u8; 32]);
    let bytes = envelope(b"not an image".to_vec(), &key);
    let error = SignedImage::from_bytes(&bytes).expect_err("the envelope is refused");
    assert_eq!(error.code(), "infinity/signature", "{error}");
}

#[cfg(feature = "signatures")]
#[test]
fn from_bytes_refuses_an_oversized_envelope_before_copying_it() {
    use active_infinity::SignedImage;

    let limit = Limits::default().max_total_bytes.saturating_add(4096) as usize;
    // Zeroed pages: the allocation is lazy, and the length check must run
    // before the image is copied out of the buffer.
    let bytes = vec![0u8; limit + 1];
    let error = SignedImage::from_bytes(&bytes).expect_err("the envelope is refused");
    assert_eq!(error.code(), "infinity/limit", "{error}");
}

#[cfg(feature = "signatures")]
#[test]
fn the_debug_form_does_not_print_the_image() {
    use active_infinity::SignedImage;
    use ed25519_dalek::SigningKey;

    let signed = SignedImage::sign(
        encode(&module()).expect("encode"),
        &SigningKey::from_bytes(&[7u8; 32]),
    )
    .expect("sign");
    let text = format!("{signed:?}");
    assert!(text.contains("image_bytes"), "{text}");
    // Derived Debug would print the Vec as decimal bytes; "signature-canary"
    // would appear as 115, 105, 103, ...
    assert!(!text.contains("115, 105, 103"), "the image leaked: {text}");
}

#[cfg(feature = "json")]
#[test]
fn a_sidecar_with_an_unknown_field_is_refused() {
    use active_infinity::Proof;

    let proof = Proof::issue(&encode(&module()).expect("encode")).expect("issue");
    let mut value: serde_json::Value = serde_json::from_str(&proof.to_json()).expect("json");
    value["admin"] = serde_json::Value::Bool(true);
    let error = Proof::from_json(&value.to_string()).expect_err("an unknown field is refused");
    assert_eq!(error.code(), "infinity/proof", "{error}");
}

#[cfg(feature = "json")]
#[test]
fn a_u64_field_may_arrive_as_a_decimal_string() {
    use active_infinity::Proof;

    let proof = Proof::issue(&encode(&module()).expect("encode")).expect("issue");
    let mut value: serde_json::Value = serde_json::from_str(&proof.to_json()).expect("json");
    value["dialect_hash"] = serde_json::Value::String(proof.dialect_hash.to_string());
    let parsed = Proof::from_json(&value.to_string()).expect("a decimal string parses");
    assert_eq!(parsed, proof);
}

/// A 64-byte string whose bytes are not all ASCII used to slice mid-character and
/// abort the verifier. The length check counts bytes, so only an ASCII guard can
/// keep the hex parser on whole characters.
#[cfg(feature = "json")]
#[test]
fn a_non_ascii_hash_is_refused_without_panicking() {
    use active_infinity::Proof;

    let proof = Proof::issue(&encode(&module()).expect("encode")).expect("issue");
    let mut value: serde_json::Value = serde_json::from_str(&proof.to_json()).expect("json");
    // One ASCII byte, 31 two-byte characters and a closing ASCII byte: 64
    // bytes total, with a character boundary that falls on every odd index.
    let hash = format!("a{}a", "\u{e9}".repeat(31));
    assert_eq!(hash.len(), 64, "the probe is 64 bytes wide");
    value["content_hash"] = serde_json::Value::String(hash);
    let error = Proof::from_json(&value.to_string()).expect_err("a non-ASCII hash is refused");
    assert_eq!(error.code(), "infinity/proof", "{error}");
}

/// A canonical decimal has no sign and no leading zero. Accepting either would
/// make two spellings of one value hash differently across implementations.
#[cfg(feature = "json")]
#[test]
fn a_numeric_string_must_be_canonical_decimal() {
    use active_infinity::Proof;

    let proof = Proof::issue(&encode(&module()).expect("encode")).expect("issue");
    let mut value: serde_json::Value = serde_json::from_str(&proof.to_json()).expect("json");
    value["dialect_hash"] = serde_json::Value::String("007".into());
    let error = Proof::from_json(&value.to_string()).expect_err("a leading zero is refused");
    assert_eq!(error.code(), "infinity/proof", "{error}");

    value["dialect_hash"] = serde_json::Value::String("+42".into());
    let error = Proof::from_json(&value.to_string()).expect_err("a sign is refused");
    assert_eq!(error.code(), "infinity/proof", "{error}");

    value["dialect_hash"] = serde_json::Value::String(String::new());
    let error = Proof::from_json(&value.to_string()).expect_err("an empty string is refused");
    assert_eq!(error.code(), "infinity/proof", "{error}");

    value["dialect_hash"] = serde_json::Value::String("0".into());
    let parsed = Proof::from_json(&value.to_string()).expect("zero is canonical");
    assert_eq!(parsed.dialect_hash, 0);
}
