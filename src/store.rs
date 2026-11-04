//! Local content-addressed store.
//!
//! The key is the Blake3 content hash of a validated canonical image. Paths are
//! derived only from the hash; callers never supply a path. Writes are atomic
//! and a second put of identical bytes is a deduplicated no-op.
//!
//! # Threat model
//!
//! The store directory is trusted to hold objects, not to authenticate its
//! readers: it is created `0700` and objects are written `0600` on Unix, but a
//! local user who can already see the directory can read every image, secrets
//! included. A failed lookup is also an existence oracle, so a service in front
//! of a store must map every `infinity/store` failure to one response instead of
//! forwarding [`std::fmt::Display`].

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::layout::Limits;
#[cfg(feature = "signatures")]
use crate::SignedImage;
use crate::{encode, validate::validate_canonical, Error, InfinityModule, Result};

/// Temporary slots a single put may try before giving up. Each attempt is an
/// exclusive create, so an occupied slot costs one failed open, never a write.
const SCRATCH_ATTEMPTS: u64 = 64;
/// Envelope overhead over the image: magic, version, key and signature.
#[cfg(feature = "signatures")]
const SIGNATURE_OVERHEAD: u64 = 4096;
/// Scratch files older than this are crashes, not work in progress.
const STALE_SCRATCH: Duration = Duration::from_secs(24 * 60 * 60);

/// A local directory store keyed by the canonical Blake3 hash.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
    /// Device/inode (or volume/file index) captured when the store was opened.
    /// Every write re-checks it: a root swapped for a symlink or another
    /// directory after validation must not receive objects.
    root_id: Option<(u64, u64)>,
    /// Scratch slot counter, seeded from the clock so a planted run of slot
    /// names cannot exhaust the attempt budget. The names are not a secret:
    /// they are only ever opened with `create_new`, so an occupied name costs a
    /// retry and can never redirect a write.
    scratch: Arc<AtomicU64>,
}

impl Store {
    /// Open or create a store directory.
    ///
    /// A root that is a symbolic link or not a directory is refused: following
    /// a link would let whoever controls the link choose where objects land.
    /// The directory is created owner-only on Unix.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        let identity = match fs::symlink_metadata(&root) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(Error::Store("store root is a symbolic link"));
                }
                if !meta.is_dir() {
                    return Err(Error::Store("store root is not a directory"));
                }
                if is_group_or_world_writable(&meta) {
                    // Anyone who can write the directory can plant or replace
                    // objects; a shared store is not a store.
                    return Err(Error::Store("store root is group- or world-writable"));
                }
                root_identity(&meta)
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                create_store_dir(&root)?;
                fs::symlink_metadata(&root)
                    .ok()
                    .and_then(|meta| root_identity(&meta))
            }
            Err(_) => return Err(Error::Store("cannot inspect store directory")),
        };
        let store = Self {
            root,
            root_id: identity,
            scratch: Arc::new(AtomicU64::new(scratch_seed())),
        };
        store.sweep_stale_scratch();
        Ok(store)
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
        let limit = object_limit();
        let meta = validate_canonical(image, Limits::default())?;
        let hash = meta.content_hash;
        let path = self.path_for(&hash);
        match fs::symlink_metadata(&path) {
            Ok(existing) => {
                if !existing.is_file() {
                    return Err(Error::Store("object path is not a regular file"));
                }
                // Read through the same bound as `get`: a planted oversized
                // file must not be pulled into memory to compare it.
                // An occupant's size or content is store state, not the
                // caller's input: report one store code so a caller cannot
                // distinguish absent, oversized and mismatched objects.
                let stored = read_bounded(&path, limit)
                    .map_err(|_| Error::Store("object exists with different bytes"))?;
                if stored == image {
                    return Ok(hash);
                }
                return Err(Error::Store("object exists with different bytes"));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Store("cannot inspect object")),
        }
        self.store_bytes(&path, image, limit)?;
        Ok(hash)
    }

    /// Encode and store a module.
    pub fn put_module(&self, module: &InfinityModule) -> Result<[u8; 32]> {
        self.put(&encode(module)?)
    }

    /// Get an object by hash.
    ///
    /// The bytes are read under the default size ceiling, proven canonical and
    /// checked against the requested key before they are returned. A symbolic
    /// link at the object path is refused; objects are regular files.
    pub fn get(&self, hash: &[u8; 32]) -> Result<Vec<u8>> {
        // One answer for "no such object": a planted file larger than the
        // ceiling must not be distinguishable from an absent one by its code
        // (cross-cutting pass 1, #9).
        let image = read_bounded(&self.path_for(hash), object_limit()).map_err(store_read_fault)?;
        // Every fault a planted object can raise is the store's own code: the
        // path is derived from the caller's hash, so a validation code would
        // distinguish an absent name from a malformed one (pass 2, #9).
        let meta = validate_canonical(&image, Limits::default()).map_err(|error| match error {
            Error::Store(_) => error,
            _ => Error::Store("object is absent or unreadable"),
        })?;
        if &meta.content_hash != hash {
            return Err(Error::Store("object does not match its key"));
        }
        Ok(image)
    }

    /// Whether the store contains a regular object file for this hash.
    ///
    /// This is a snapshot: a `contains` answer does not reserve the object, so
    /// a later `get` can still fail. It never reports a symbolic link or a
    /// directory as an object.
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        fs::symlink_metadata(self.path_for(hash)).is_ok_and(|meta| meta.is_file())
    }

    #[cfg(feature = "signatures")]
    /// Store a signed image and keep its detached envelope.
    ///
    /// The envelope is verified before anything is written, so a store never
    /// holds a signature that does not match its object. The image is stored
    /// through [`Store::put`], which validates it and deduplicates bytes.
    ///
    /// One object has one envelope: re-storing the identical envelope is a
    /// no-op on every platform, and a second envelope for the same image (a
    /// different signer, or different signature bytes) is refused rather than
    /// replacing evidence that may already be pinned by a reader.
    pub fn put_signed(&self, signed: &SignedImage) -> Result<[u8; 32]> {
        signed.verify()?;
        let hash = self.put(&signed.image)?;
        let path = self.path_for_signature(&hash);
        self.store_bytes(
            &path,
            &signed.to_bytes(),
            object_limit().saturating_add(SIGNATURE_OVERHEAD),
        )?;
        Ok(hash)
    }

    #[cfg(feature = "signatures")]
    /// The verified detached envelope for a stored object, if one exists.
    ///
    /// `None` means the object was stored without a signature; an envelope that
    /// fails verification, or one that covers a different object, is an error.
    pub fn get_signature(&self, hash: &[u8; 32]) -> Result<Option<SignedImage>> {
        let path = self.path_for_signature(hash);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Store("cannot inspect signature")),
            Ok(meta) if !meta.is_file() => {
                return Err(Error::Store("signature path is not a regular file"))
            }
            Ok(_) => {}
        }
        let bytes = read_bounded(&path, object_limit().saturating_add(SIGNATURE_OVERHEAD))?;
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
        // No byte comparison is needed: `get` proved that `image` hashes to
        // `hash`, and `get_signature` proved that the envelope's image does
        // too. Comparing the buffers would only add a length-dependent timing
        // signal over secret-bearing bytes.
        if let Some(key) = trusted {
            // A small-order key verifies every message under a forged
            // signature, so it cannot be a trust anchor.
            if key.is_weak() {
                return Err(Error::Signature("the trusted key is weak"));
            }
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

    /// Refuse to use a root that changed since it was opened.
    fn ensure_root(&self) -> Result<()> {
        let meta = fs::symlink_metadata(&self.root)
            .map_err(|_| Error::Store("store root is unavailable"))?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(Error::Store("store root changed since it was opened"));
        }
        if let (Some(expected), Some(actual)) = (self.root_id, root_identity(&meta)) {
            if expected != actual {
                return Err(Error::Store("store root changed since it was opened"));
            }
        }
        Ok(())
    }

    /// Number of stored objects.
    ///
    /// A directory that cannot be read counts as empty; use [`Store::try_len`]
    /// when the difference matters.
    pub fn len(&self) -> usize {
        self.try_len().unwrap_or(0)
    }

    /// Number of stored objects, failing when the directory cannot be read.
    ///
    /// Only regular files named `<64 lowercase hex>.ainf` count: a hand-placed
    /// name, a directory or a link is not an object.
    pub fn try_len(&self) -> Result<usize> {
        let mut count = 0;
        for entry in
            fs::read_dir(&self.root).map_err(|_| Error::Store("cannot read store directory"))?
        {
            let entry = entry.map_err(|_| Error::Store("cannot read store directory"))?;
            if !is_object_name(&entry.file_name()) {
                continue;
            }
            if entry.file_type().is_ok_and(|kind| kind.is_file()) {
                count += 1;
            }
        }
        Ok(count)
    }

    /// True when the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn path_for(&self, hash: &[u8; 32]) -> PathBuf {
        self.root.join(format!("{}.ainf", hex32(hash)))
    }

    #[cfg(feature = "signatures")]
    fn path_for_signature(&self, hash: &[u8; 32]) -> PathBuf {
        self.root.join(format!("{}.sig", hex32(hash)))
    }

    /// Write `bytes` to a fresh scratch file and commit it at `dest` without
    /// replacing an existing object.
    fn store_bytes(&self, dest: &Path, bytes: &[u8], limit: u64) -> Result<()> {
        self.ensure_root()?;
        let name = dest
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(Error::Store("invalid object name"))?;
        let (mut file, temp) = self.scratch_file(name)?;
        let written = file.write_all(bytes).and_then(|()| file.sync_all());
        drop(file);
        if written.is_err() {
            let _ = fs::remove_file(&temp);
            return Err(Error::Store("cannot write object"));
        }
        self.commit(&temp, dest, bytes, limit)
    }

    /// Create a new scratch file under the store root.
    ///
    /// `create_new` is the load-bearing part: it is `O_CREAT|O_EXCL`, which
    /// refuses a path that already exists, symbolic link or not, on Unix and
    /// Windows alike. A pre-planted name therefore costs one retry instead of
    /// redirecting the write into somebody else's file.
    fn scratch_file(&self, name: &str) -> Result<(File, PathBuf)> {
        for _ in 0..SCRATCH_ATTEMPTS {
            let slot = self.scratch.fetch_add(1, Ordering::Relaxed);
            let path = self
                .root
                .join(format!(".{name}.tmp.{}.{slot}", std::process::id()));
            match create_new_file(&path) {
                Ok(file) => return Ok((file, path)),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(Error::Store("cannot create a temporary object")),
            }
        }
        Err(Error::Store("cannot create a temporary object"))
    }

    /// Give the scratch file its final name without clobbering an existing
    /// object.
    ///
    /// A hard link is the atomic no-replace primitive that both Unix and
    /// Windows provide. Filesystems without hard links fall back to a rename
    /// guarded by an existence check; that window is harmless because readers
    /// validate what they find and refuse a partial object.
    fn commit(&self, temp: &Path, dest: &Path, bytes: &[u8], limit: u64) -> Result<()> {
        match fs::hard_link(temp, dest) {
            Ok(()) => {
                let _ = fs::remove_file(temp);
                Ok(())
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(temp);
                self.compare_existing(dest, bytes, limit)
            }
            Err(_) if dest.exists() => {
                let _ = fs::remove_file(temp);
                self.compare_existing(dest, bytes, limit)
            }
            Err(_) => {
                // Filesystems without hard links: an exclusive create cannot
                // replace a concurrently planted object, unlike a rename on
                // Unix. The object becomes visible while it is written, so a
                // reader may see a partial file and refuse it (validation is
                // fail-closed).
                match create_new_file(dest) {
                    Ok(mut file) => {
                        let written = file.write_all(bytes).and_then(|()| file.sync_all());
                        drop(file);
                        let _ = fs::remove_file(temp);
                        if written.is_ok() {
                            Ok(())
                        } else {
                            let _ = fs::remove_file(dest);
                            Err(Error::Store("cannot commit object"))
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                        let _ = fs::remove_file(temp);
                        self.compare_existing(dest, bytes, limit)
                    }
                    Err(_) => {
                        let _ = fs::remove_file(temp);
                        Err(Error::Store("cannot commit object"))
                    }
                }
            }
        }
    }

    /// A raced or pre-existing object is accepted only when it is byte-identical.
    fn compare_existing(&self, dest: &Path, bytes: &[u8], limit: u64) -> Result<()> {
        let existing = read_bounded(dest, limit)
            .map_err(|_| Error::Store("object exists with different bytes"))?;
        if existing == bytes {
            Ok(())
        } else {
            Err(Error::Store("object exists with different bytes"))
        }
    }

    /// Remove scratch files left behind by a process that died mid-write.
    ///
    /// Only names this store creates are considered, and only after a day, so
    /// a concurrent writer's file is never touched.
    fn sweep_stale_scratch(&self) {
        if self.ensure_root().is_err() {
            return;
        }
        let Ok(entries) = fs::read_dir(&self.root) else {
            return;
        };
        let now = SystemTime::now();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !is_scratch_name(name) {
                continue;
            }
            let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let Ok(modified) = meta.modified() else {
                continue;
            };
            if now
                .duration_since(modified)
                .is_ok_and(|age| age > STALE_SCRATCH)
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// A stable identity for the store directory, when the platform exposes one.
#[cfg(unix)]
fn root_identity(meta: &fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.dev(), meta.ino()))
}

#[cfg(windows)]
fn root_identity(_meta: &fs::Metadata) -> Option<(u64, u64)> {
    // The Windows file index/volume serial metadata is still unstable
    // (`windows_by_handle`). The per-write re-check still refuses a root
    // replaced by a symbolic link or a non-directory; a directory swapped for
    // another directory at the same path is caught by the OS ACL model, not by
    // an inode pin.
    None
}

#[cfg(not(any(unix, windows)))]
fn root_identity(_meta: &fs::Metadata) -> Option<(u64, u64)> {
    None
}

#[cfg(unix)]
fn is_group_or_world_writable(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o022 != 0
}

#[cfg(not(unix))]
fn is_group_or_world_writable(_meta: &fs::Metadata) -> bool {
    false
}

/// A starting slot that no other `Store` open in this process shares.
///
/// The clock alone is not enough: its resolution is coarse enough that two
/// stores opened in one tick started at the same slot, and a tenant that
/// planted that run of names could exhaust both stores' attempt budgets
/// (cross-cutting pass 3, #3). The process id separates processes, the atomic
/// counter separates opens inside one process, and the clock separates runs.
fn scratch_seed() -> u64 {
    static OPENS: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    let sequence = OPENS.fetch_add(1, Ordering::Relaxed);
    nanos
        ^ u64::from(std::process::id()).rotate_left(32)
        ^ sequence.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// The largest object `get` will read: the codec's own ceiling for one image.
fn object_limit() -> u64 {
    Limits::default().max_total_bytes
}

/// Read a regular file no larger than `limit`, refusing links and directories.
///
/// The size is checked from metadata before any allocation, and the read is
/// bounded again so a file that grows after the check still cannot exceed the
/// ceiling.
fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|error| match error.kind() {
        ErrorKind::NotFound => Error::Store("object not found"),
        _ => Error::Store("cannot inspect object"),
    })?;
    if !meta.is_file() {
        return Err(Error::Store("object is not a regular file"));
    }
    if meta.len() > limit {
        return Err(Error::Limit {
            kind: "store object bytes",
            limit,
        });
    }
    let file = File::open(path).map_err(|_| Error::Store("cannot read object"))?;
    // `symlink_metadata` checked the path, but `open` follows links: re-check
    // the opened file. A swapped FIFO blocks `open`; a swapped directory or
    // symlink is caught here. On Unix the device/inode pair also catches a
    // regular file swapped for another regular file between the two calls.
    let opened = file
        .metadata()
        .map_err(|_| Error::Store("cannot inspect object"))?;
    if !opened.is_file() {
        return Err(Error::Store("object is not a regular file"));
    }
    if let (Some(expected), Some(actual)) = (root_identity(&meta), root_identity(&opened)) {
        if expected != actual {
            return Err(Error::Store("object changed while it was opened"));
        }
    }
    let reserve = usize::try_from(opened.len())
        .unwrap_or(usize::MAX)
        .min(1 << 20);
    let mut bytes = Vec::with_capacity(reserve);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Store("cannot read object"))?;
    if bytes.len() as u64 > limit {
        return Err(Error::Limit {
            kind: "store object bytes",
            limit,
        });
    }
    Ok(bytes)
}

fn create_new_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn create_store_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(path)
            .map_err(|_| Error::Store("cannot create store directory"))
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path).map_err(|_| Error::Store("cannot create store directory"))
    }
}

/// `<64 lowercase hex>.ainf`, the only name `len` counts.
fn is_object_name(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(stem) = name.strip_suffix(".ainf") else {
        return false;
    };
    stem.len() == 64
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A scratch name: `.` + object name + `.tmp.` + pid + `.` + slot.
fn is_scratch_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix('.') else {
        return false;
    };
    match rest.rsplit_once(".tmp.") {
        Some((inner, tail)) => {
            if !is_scratch_inner(inner) {
                return false;
            }
            let mut parts = tail.split('.');
            matches!(
                (parts.next(), parts.next()),
                (Some(pid), Some(slot))
                    if !pid.is_empty()
                        && pid.bytes().all(|byte| byte.is_ascii_digit())
                        && !slot.is_empty()
                        && slot.bytes().all(|byte| byte.is_ascii_digit())
            ) && parts.next().is_none()
        }
        None => false,
    }
}

/// The inner name of a scratch file: an object name (`<64 hex>.ainf`) or an
/// envelope name (`<64 hex>.sig`).
fn is_scratch_inner(inner: &str) -> bool {
    if is_object_name(std::ffi::OsStr::new(inner)) {
        return true;
    }
    let Some(stem) = inner.strip_suffix(".sig") else {
        return false;
    };
    stem.len() == 64
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex32(hash: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in hash {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Report any object-read fault as the store's own code.
///
/// The path is derived from a hash the caller chose, so an over-sized planted
/// object would otherwise answer `infinity/limit` and tell a prober that the
/// name exists.
fn store_read_fault(error: Error) -> Error {
    match error {
        Error::Store(_) => error,
        _ => Error::Store("object is absent or unreadable"),
    }
}
