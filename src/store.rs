//! Local content-addressed store.
//!
//! The key is the Blake3 content hash of a validated canonical image. Paths are
//! derived only from the hash; callers never supply a path. Writes are atomic
//! and a second put of identical bytes is a deduplicated no-op.

use std::fs;
use std::path::{Path, PathBuf};

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
    pub fn put(&self, image: &[u8]) -> Result<[u8; 32]> {
        validate(image)?;
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
}
