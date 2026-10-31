//! Local content-addressed store.
//!
//! The key is the Blake3 content hash of a validated canonical image. Paths are
//! derived only from the hash; callers never supply a path. Writes are atomic
//! and a second put of identical bytes is a deduplicated no-op.

use std::fs;
use std::path::{Path, PathBuf};

#[cfg(feature = "signatures")]
use crate::SignedImage;
use crate::{content_hash, encode, validate, Error, InfinityModule, Result};

/// A local directory store keyed by the canonical Blake3 hash.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Open or create a store directory.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|_| Error::Store("cannot create store directory"))?;
        Ok(Self { root })
    }

    /// Store directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Put a validated canonical image. Returns its content hash.
    ///
    /// Canonical is enforced, not assumed: a structurally valid image that
    /// re-encodes differently would otherwise get a second key for one logical
    /// module, and a signature over it would bind bytes nobody can reproduce.
    pub fn put(&self, image: &[u8]) -> Result<[u8; 32]> {
        crate::validate::validate_canonical(image, crate::layout::Limits::default())?;
        let hash = content_hash(image)?;
        let path = self.path_for(&hash);
        if let Ok(existing) = fs::read(&path) {
            if existing == image {
                return Ok(hash);
            }
            return Err(Error::Store("hash collision or corrupt existing object"));
        }
        let temp = path.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        fs::write(&temp, image).map_err(|_| Error::Store("cannot write object"))?;
        match fs::rename(&temp, &path) {
            Ok(()) => Ok(hash),
            Err(_) if path.exists() => {
                let _ = fs::remove_file(&temp);
                let existing =
                    fs::read(&path).map_err(|_| Error::Store("cannot read raced object"))?;
                if existing == image {
                    Ok(hash)
                } else {
                    Err(Error::Store("object exists with different bytes"))
                }
            }
            Err(_) => {
                let _ = fs::remove_file(&temp);
                Err(Error::Store("cannot commit object"))
            }
        }
    }

    /// Encode and store a module.
    pub fn put_module(&self, module: &InfinityModule) -> Result<[u8; 32]> {
        self.put(&encode(module)?)
    }

    /// Get an object by hash. Revalidates and rechecks the hash before return.
    pub fn get(&self, hash: &[u8; 32]) -> Result<Vec<u8>> {
        let path = self.path_for(hash);
        let image = fs::read(&path).map_err(|_| Error::Store("object not found"))?;
        validate(&image)?;
        let actual = content_hash(&image)?;
        if &actual != hash {
            return Err(Error::Store("object hash mismatch"));
        }
        Ok(image)
    }

    /// Whether the store contains an object for this hash.
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.path_for(hash).is_file()
    }

    #[cfg(feature = "signatures")]
    /// Store a signed image and keep its detached envelope.
    ///
    /// The envelope is verified before anything is written, so a store never
    /// holds a signature that does not match its object. The image is stored
    /// through [`Store::put`], which validates it and deduplicates bytes.
    pub fn put_signed(&self, signed: &SignedImage) -> Result<[u8; 32]> {
        signed.verify()?;
        let hash = signed.content_hash()?;
        self.put(&signed.image)?;
        let path = self.path_for_signature(&hash);
        let temp = path.with_extension(format!(
            "sig-tmp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        fs::write(&temp, signed.to_bytes()).map_err(|_| Error::Store("cannot write signature"))?;
        fs::rename(&temp, &path).map_err(|_| {
            let _ = fs::remove_file(&temp);
            Error::Store("cannot commit signature")
        })?;
        Ok(hash)
    }

    #[cfg(feature = "signatures")]
    /// The verified detached envelope for a stored object, if one exists.
    ///
    /// `None` means the object was stored without a signature; an envelope that
    /// fails verification, or one that covers a different object, is an error.
    pub fn get_signature(&self, hash: &[u8; 32]) -> Result<Option<SignedImage>> {
        let path = self.path_for_signature(hash);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Store("cannot read signature")),
        };
        let signed = SignedImage::from_bytes(&bytes)?;
        if &signed.content_hash()? != hash {
            return Err(Error::Signature(
                "the signature covers a different object than the requested hash",
            ));
        }
        Ok(Some(signed))
    }

    #[cfg(feature = "signatures")]
    /// Get an object and require a verified signature over exactly those bytes.
    ///
    /// This is the authenticity path: [`Store::get`] proves integrity only.
    /// `trusted` pins the signing key; without it the envelope proves that the
    /// image and its key are self-consistent, which is not the same as
    /// authorship.
    pub fn get_verified(
        &self,
        hash: &[u8; 32],
        trusted: Option<&ed25519_dalek::VerifyingKey>,
    ) -> Result<Vec<u8>> {
        let image = self.get(hash)?;
        let signed = self
            .get_signature(hash)?
            .ok_or(Error::Signature("no signature for the object"))?;
        if signed.image != image {
            return Err(Error::Signature("the signature covers different bytes"));
        }
        if let Some(key) = trusted {
            if key.to_bytes() != signed.public_key {
                return Err(Error::Signature("the object was signed by another key"));
            }
        }
        Ok(image)
    }

    /// [`Store::get_verified`] with the trusted key as raw bytes.
    ///
    /// A caller that keeps a public key as hex or bytes does not need the
    /// signature crate's types to pin a signer.
    #[cfg(feature = "signatures")]
    pub fn get_verified_with_key(&self, hash: &[u8; 32], public_key: &[u8; 32]) -> Result<Vec<u8>> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
            .map_err(|_| Error::Signature("invalid public key"))?;
        self.get_verified(hash, Some(&key))
    }

    /// Number of stored objects.
    pub fn len(&self) -> usize {
        fs::read_dir(&self.root)
            .map(|entries| {
                entries
                    .filter_map(std::result::Result::ok)
                    .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "ainf"))
                    .count()
            })
            .unwrap_or(0)
    }

    /// True when the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn path_for(&self, hash: &[u8; 32]) -> PathBuf {
        let name: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
        self.root.join(format!("{name}.ainf"))
    }

    #[cfg(feature = "signatures")]
    fn path_for_signature(&self, hash: &[u8; 32]) -> PathBuf {
        let name: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
        self.root.join(format!("{name}.sig"))
    }
}
