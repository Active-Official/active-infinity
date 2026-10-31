//! Detached Ed25519 signature envelope for a canonical image.
//!
//! Signature is supply-chain evidence, not identity: the content hash remains
//! the Blake3 hash of the image. The envelope binds the image bytes and the
//! public key with a domain separator.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::{content_hash, validate, Error, Result};

const MAGIC: [u8; 4] = *b"AISG";
const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"active-infinity/signed-image/v1\0";

/// A detached signed image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedImage {
    /// Canonical image bytes.
    pub image: Vec<u8>,
    /// Ed25519 public key.
    pub public_key: [u8; 32],
    /// Ed25519 signature over `DOMAIN || image`.
    pub signature: [u8; 64],
}

impl SignedImage {
    /// Validate and sign an image.
    pub fn sign(image: Vec<u8>, key: &SigningKey) -> Result<Self> {
        validate(&image)?;
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
    pub fn verify(&self) -> Result<()> {
        validate(&self.image)?;
        let key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| Error::Signature("invalid public key"))?;
        let signature = Signature::from_bytes(&self.signature);
        let mut message = Vec::with_capacity(DOMAIN.len() + self.image.len());
        message.extend_from_slice(DOMAIN);
        message.extend_from_slice(&self.image);
        key.verify(&message, &signature)
            .map_err(|_| Error::Signature("signature does not verify"))?;
        Ok(())
    }

    /// Content hash of the signed image.
    pub fn content_hash(&self) -> Result<[u8; 32]> {
        content_hash(&self.image)
    }

    /// Serialize the detached envelope.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 32 + 64 + self.image.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.image);
        out
    }

    /// Parse and verify a detached envelope.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 + 1 + 32 + 64 || bytes[..4] != MAGIC {
            return Err(Error::Signature("bad envelope magic or length"));
        }
        if bytes[4] != VERSION {
            return Err(Error::Signature("unsupported envelope version"));
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&bytes[5..37]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[37..101]);
        let envelope = Self {
            image: bytes[101..].to_vec(),
            public_key,
            signature,
        };
        envelope.verify()?;
        Ok(envelope)
    }
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
}
