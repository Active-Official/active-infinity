//! Detached Ed25519 signature envelope for a canonical image.
//!
//! Signature is supply-chain evidence, not identity: the content hash remains
//! the Blake3 hash of the image. The envelope binds the image bytes and the
//! public key with a domain separator.
//!
//! Both [`SignedImage::sign`] and [`SignedImage::verify`] prove the canonical
//! form. A signature over a structurally valid image that does not re-encode to
//! itself would certify bytes no honest producer can reproduce and no store
//! accepts, so it is refused up front with `infinity/not-canonical`. Every
//! failure while parsing or verifying an envelope is reported as
//! `infinity/signature`: a caller that monitors that one code sees every
//! rejected envelope.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::layout::Limits;
use crate::{validate_canonical, Error, Result};

const MAGIC: [u8; 4] = *b"AISG";
const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"active-infinity/signed-image/v1\0";
/// Magic, version, public key and signature ahead of the image.
const HEADER: usize = 4 + 1 + 32 + 64;

/// A detached signed image.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedImage {
    /// Canonical image bytes.
    pub image: Vec<u8>,
    /// Ed25519 public key.
    pub public_key: [u8; 32],
    /// Ed25519 signature over `DOMAIN || image`.
    pub signature: [u8; 64],
}

impl std::fmt::Debug for SignedImage {
    /// Prints the envelope's metadata, never the image.
    ///
    /// The image carries the secret heap, so the derived `Debug` would print it
    /// as a decimal byte list into any log or panic message.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedImage")
            .field("image_bytes", &self.image.len())
            .field("public_key", &hex(&self.public_key))
            .field("signature", &hex(&self.signature[..8]))
            .finish()
    }
}

impl SignedImage {
    /// Validate and sign an image.
    pub fn sign(image: Vec<u8>, key: &SigningKey) -> Result<Self> {
        validate_canonical(&image, Limits::default())?;
        let mut message = Vec::with_capacity(DOMAIN.len() + image.len());
        message.extend_from_slice(DOMAIN);
        message.extend_from_slice(&image);
        let signature = key.sign(&message);
        Ok(Self {
            image,
            public_key: key.verifying_key().to_bytes(),
            signature: signature.to_bytes(),
        })
    }

    /// Sign an image from a raw 32-byte Ed25519 seed.
    ///
    /// A CLI or a deployment that keeps its key as bytes does not have to take
    /// a dependency on the signature crate to use the envelope.
    pub fn sign_with_seed(image: Vec<u8>, seed: &[u8; 32]) -> Result<Self> {
        let key = SigningKey::from_bytes(seed);
        Self::sign(image, &key)
    }

    /// Verify the image, public key and signature. Fail closed on any mismatch.
    ///
    /// The image must be canonical: a signature certifies bytes that re-encode
    /// to themselves. Any image fault is reported as `infinity/signature`, the
    /// envelope's code; a resource ceiling (`infinity/limit`) is passed through
    /// so a caller counting on that code still sees it.
    pub fn verify(&self) -> Result<()> {
        verify_parts(&self.image, &self.public_key, &self.signature)
    }

    /// Content hash of the signed image.
    ///
    /// A malformed image is an envelope fault (`infinity/signature`); a
    /// resource ceiling is passed through.
    pub fn content_hash(&self) -> Result<[u8; 32]> {
        crate::content_hash(&self.image).map_err(|error| match error {
            Error::Limit { .. } => error,
            _ => Error::Signature("the envelope's image does not validate"),
        })
    }

    /// Serialize the detached envelope.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + self.image.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.image);
        out
    }

    /// Parse and verify a detached envelope.
    ///
    /// The input is bounded before the image is copied: an envelope is a
    /// canonical image plus a fixed header, so anything past the codec ceiling
    /// is refused with `infinity/limit`. Every other failure is
    /// `infinity/signature`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let limit = envelope_limit();
        if bytes.len() as u64 > limit {
            return Err(Error::Limit {
                kind: "signature envelope bytes",
                limit,
            });
        }
        if bytes.len() < HEADER || bytes[..4] != MAGIC {
            return Err(Error::Signature("bad envelope magic or length"));
        }
        if bytes[4] != VERSION {
            return Err(Error::Signature("unsupported envelope version"));
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&bytes[5..37]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[37..101]);
        // Verify the borrowed image first: copying a gigabyte-scale envelope
        // before the canonical proof would double the transient memory for an
        // input that is about to be refused.
        let image = &bytes[HEADER..];
        verify_parts(image, &public_key, &signature)?;
        Ok(Self {
            image: image.to_vec(),
            public_key,
            signature,
        })
    }
}

/// Verify an image, key and signature without owning the image.
///
/// Split out so [`SignedImage::from_bytes`] can prove a borrowed slice before
/// copying it. Every image fault is `infinity/signature` except a resource
/// ceiling, which keeps `infinity/limit`.
fn verify_parts(image: &[u8], public_key: &[u8; 32], signature: &[u8; 64]) -> Result<()> {
    validate_canonical(image, Limits::default()).map_err(|error| match error {
        Error::Limit { .. } => error,
        _ => Error::Signature("the signed image does not validate"),
    })?;
    let key =
        VerifyingKey::from_bytes(public_key).map_err(|_| Error::Signature("invalid public key"))?;
    let signature = Signature::from_bytes(signature);
    let mut message = Vec::with_capacity(DOMAIN.len() + image.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(image);
    key.verify(&message, &signature)
        .map_err(|_| Error::Signature("signature does not verify"))?;
    Ok(())
}

/// Largest envelope accepted: the codec's image ceiling plus the fixed header
/// and room for a future extension.
fn envelope_limit() -> u64 {
    Limits::default().max_total_bytes.saturating_add(4096)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode, InfinityModule, Inode};

    fn image() -> Vec<u8> {
        let mut module = InfinityModule::new();
        let root = module.push(Inode::Str("signed-image".into()));
        module.set_root(Some(root));
        encode(&module).expect("encode")
    }

    #[test]
    fn signature_round_trips_and_rejects_tampering() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let signed = SignedImage::sign(image(), &key).expect("sign");
        let bytes = signed.to_bytes();
        let parsed = SignedImage::from_bytes(&bytes).expect("verify envelope");
        assert_eq!(parsed.image, signed.image);
        assert_eq!(
            parsed.content_hash().unwrap(),
            signed.content_hash().unwrap()
        );

        let mut tampered = bytes;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(SignedImage::from_bytes(&tampered).is_err());
    }

    /// A resource ceiling is a caller-facing contract, not an envelope fault.
    /// The verifier keeps `infinity/limit` so a caller that budgets on that code
    /// still sees it; every other image fault collapses to `infinity/signature`.
    #[test]
    fn a_ceiling_fault_keeps_the_limit_code() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut doctored = image();
        // The node count is the second word of the first section descriptor,
        // right after the 64-byte fixed prefix. Declaring u32::MAX nodes trips
        // `validate_counts` before the content hash is recomputed.
        doctored[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(&doctored);
        let signature = key.sign(&message);
        let mut bytes = MAGIC.to_vec();
        bytes.push(VERSION);
        bytes.extend_from_slice(&key.verifying_key().to_bytes());
        bytes.extend_from_slice(&signature.to_bytes());
        bytes.extend_from_slice(&doctored);
        let error = SignedImage::from_bytes(&bytes).expect_err("the image is refused");
        assert_eq!(error.code(), "infinity/limit", "{error}");
    }

    /// `content_hash` reports envelope faults under the envelope's code, so a
    /// caller that matches on `infinity/signature` does not miss a malformed
    /// image behind a different error.
    #[test]
    fn content_hash_reports_the_envelope_code_for_a_corrupt_image() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let signed = SignedImage {
            image: b"not an image".to_vec(),
            public_key: key.verifying_key().to_bytes(),
            signature: [0u8; 64],
        };
        let error = signed.content_hash().expect_err("the image is refused");
        assert_eq!(error.code(), "infinity/signature", "{error}");
    }
}
