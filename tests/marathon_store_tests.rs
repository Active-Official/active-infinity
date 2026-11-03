//! Marathon I-08: the local store's write, commit, read and inventory paths.
//!
//! Each case pins one property the store promises and the pre-hardening code
//! did not hold: canonical-only reads, bounded reads, no write through a
//! planted path, one envelope per object, and an inventory that counts objects
//! rather than file names.

use std::fs;
use std::path::Path;

use active_infinity::{encode, InfinityModule, Inode, Store};

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

fn hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Blake3 over the image with the header hash field zeroed, matching the
/// encoder: an image can be re-hashed after a deliberate header change so the
/// reader's first check (integrity) passes and a later one (canonical form) is
/// the one under test.
fn image_hash(image: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&image[..16]);
    hasher.update(&[0u8; 32]);
    hasher.update(&image[48..]);
    *hasher.finalize().as_bytes()
}

fn object_path(root: &Path, hash: &[u8; 32]) -> std::path::PathBuf {
    root.join(format!("{}.ainf", hex(hash)))
}

#[test]
fn get_refuses_a_non_canonical_image_planted_at_its_hash() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open(directory.path()).expect("store");
    let image = encode(&module()).expect("encode");
    let mut doctored = image.clone();
    // Clear the canonical flag. The bytes stay structurally valid and their
    // stored hash can be made to agree, so only a canonical proof refuses it.
    doctored[8] &= !1;
    assert_ne!(doctored, image);
    let hash = image_hash(&doctored);
    doctored[16..48].copy_from_slice(&hash);
    assert_eq!(image_hash(&doctored), hash);
    fs::write(object_path(directory.path(), &hash), &doctored).expect("plant");

    let error = store
        .get(&hash)
        .expect_err("a non-canonical object is refused");
    // One code for every planted or absent object: the name comes from the
    // caller's hash, so a validation code would be an existence oracle
    // (pass 2, #9).
    assert_eq!(error.code(), "infinity/store", "{error}");
}

#[test]
fn get_refuses_an_object_larger_than_the_read_limit() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open(directory.path()).expect("store");
    let hash = [0x11u8; 32];
    let path = object_path(directory.path(), &hash);
    let file = fs::File::create(&path).expect("create");
    // One byte past the default image ceiling. Sparse, so this is cheap; the
    // point is that the store must refuse it from the file size alone rather
    // than allocate and read a gigabyte.
    file.set_len((1u64 << 30) + 8).expect("set len");
    drop(file);

    let error = store
        .get(&hash)
        .expect_err("an oversized object is refused");
    // One answer for "no such object": an over-sized planted file must not be
    // distinguishable from an absent one (cross-cutting pass 1, #9).
    let absent = Store::open(directory.path())
        .expect("store")
        .get(&[0x22u8; 32])
        .expect_err("an absent object is refused");
    assert_eq!(error.code(), "infinity/store", "{error}");
    assert_eq!(error.code(), absent.code(), "the two answers differ");
    assert!(
        store.contains(&hash),
        "the file exists; the read is what fails"
    );
}

#[test]
fn put_refuses_an_oversized_occupant_with_the_store_code() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open(directory.path()).expect("store");
    let image = encode(&module()).expect("encode");
    let hash = image_hash(&image);
    let path = object_path(directory.path(), &hash);
    let file = fs::File::create(&path).expect("create");
    file.set_len((1u64 << 30) + 8).expect("set len");
    drop(file);

    // The occupant is store state, not the caller's input: one store code for
    // absent, oversized and mismatched objects. The read is still bounded (this
    // returns immediately instead of pulling a gigabyte into memory).
    let error = store
        .put(&image)
        .expect_err("an oversized occupant is refused");
    assert_eq!(error.code(), "infinity/store", "{error}");
}

#[cfg(unix)]
#[test]
fn get_refuses_a_symlinked_object() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open(directory.path()).expect("store");
    let image = encode(&module()).expect("encode");
    let hash = store.put(&image).expect("put");
    let path = object_path(directory.path(), &hash);
    let elsewhere = directory.path().join("elsewhere.bin");
    fs::rename(&path, &elsewhere).expect("move");
    std::os::unix::fs::symlink(&elsewhere, &path).expect("symlink");
    assert!(fs::symlink_metadata(&path)
        .expect("link")
        .file_type()
        .is_symlink());

    let error = store.get(&hash).expect_err("a symlinked object is refused");
    assert_eq!(error.code(), "infinity/store", "{error}");
    assert!(
        !store.contains(&hash),
        "contains reports regular files only"
    );
}

/// Plant something at a path the store might otherwise write through. A
/// symlink is the sharper case (a write lands in the victim file); creating one
/// needs a privilege on Windows, where a hard link is the portable equivalent
/// because a truncating write still reaches the victim's inode.
fn plant_link(target: &Path, link: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).expect("symlink");
    #[cfg(windows)]
    fs::hard_link(target, link).expect("hard link");
}

#[test]
fn len_counts_objects_not_file_names() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open(directory.path()).expect("store");
    let image = encode(&module()).expect("encode");
    store.put(&image).expect("put");

    fs::write(directory.path().join("garbage.ainf"), b"not an object").expect("garbage");
    fs::write(directory.path().join("short.ainf"), b"not an object").expect("short");
    fs::write(
        directory.path().join(format!("{}.AINF", hex(&[0xab; 32]))),
        b"uppercase",
    )
    .expect("uppercase");
    fs::create_dir(directory.path().join(format!("{}.ainf", hex(&[0xcd; 32])))).expect("directory");
    fs::write(directory.path().join(".hidden.ainf"), b"hidden").expect("hidden");

    assert_eq!(store.len(), 1);
}

#[cfg(feature = "signatures")]
#[test]
fn put_signed_accepts_the_same_envelope_twice() {
    use active_infinity::SignedImage;

    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open(directory.path()).expect("store");
    let image = encode(&module()).expect("encode");
    let signed = SignedImage::sign_with_seed(image, &[21u8; 32]).expect("sign");
    let first = store.put_signed(&signed).expect("first put");
    let second = store
        .put_signed(&signed)
        .expect("a duplicate envelope is a no-op");
    assert_eq!(first, second);
    assert_eq!(store.len(), 1);
}

#[cfg(feature = "signatures")]
#[test]
fn put_signed_refuses_a_second_envelope_for_the_same_image() {
    use active_infinity::SignedImage;

    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open(directory.path()).expect("store");
    let image = encode(&module()).expect("encode");
    let first = SignedImage::sign_with_seed(image.clone(), &[31u8; 32]).expect("sign");
    let hash = store.put_signed(&first).expect("first put");

    let second = SignedImage::sign_with_seed(image, &[32u8; 32]).expect("sign");
    let error = store
        .put_signed(&second)
        .expect_err("one object has one envelope");
    assert_eq!(error.code(), "infinity/store", "{error}");

    // The trusted envelope is still the first one.
    let stored = store
        .get_signature(&hash)
        .expect("signature")
        .expect("present");
    assert_eq!(stored.public_key, first.public_key);
}

#[test]
fn put_does_not_write_through_a_planted_scratch_path() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = Store::open(directory.path()).expect("store");
    let image = encode(&module()).expect("encode");
    let hash = image_hash(&image);
    let victim = directory.path().join("victim.txt");
    fs::write(&victim, b"victim bytes").expect("victim");
    // The first scratch slot of this store instance is guessable, so an
    // attacker can occupy it. An exclusive create must step over it instead of
    // writing through it.
    let planted =
        directory
            .path()
            .join(format!(".{}.ainf.tmp.{}.0", hex(&hash), std::process::id()));
    plant_link(&victim, &planted);

    let stored = store.put(&image).expect("put");
    assert_eq!(stored, hash);
    assert_eq!(fs::read(&victim).expect("victim"), b"victim bytes");
    assert_eq!(store.get(&hash).expect("get"), image);
}

#[cfg(unix)]
#[test]
fn store_objects_and_directory_are_private() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("private");
    let store = Store::open(&root).expect("store");
    let image = encode(&module()).expect("encode");
    let hash = store.put(&image).expect("put");

    let directory_mode = fs::metadata(&root).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(directory_mode, 0o700, "store directory is owner-only");
    let object_mode = fs::metadata(object_path(&root, &hash))
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(object_mode, 0o600, "objects are owner-only");
}

#[cfg(unix)]
#[test]
fn open_refuses_a_symlinked_root() {
    let directory = tempfile::tempdir().expect("tempdir");
    let victim = directory.path().join("victim");
    fs::create_dir(&victim).expect("victim dir");
    let root = directory.path().join("store");
    std::os::unix::fs::symlink(&victim, &root).expect("symlink root");

    let error = Store::open(&root).expect_err("a symlinked root is refused");
    assert_eq!(error.code(), "infinity/store", "{error}");
    assert!(fs::read_dir(&victim)
        .expect("victim then read")
        .next()
        .is_none());
}

#[cfg(unix)]
#[test]
fn a_group_or_world_writable_root_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("shared");
    fs::create_dir(&root).expect("create");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).expect("chmod");
    let error = Store::open(&root).expect_err("a writable-by-others root is refused");
    assert_eq!(error.code(), "infinity/store", "{error}");

    // Readable by others is allowed (the at-rest exposure is documented); only
    // writability lets another user plant or replace objects.
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("chmod");
    Store::open(&root).expect("a 0755 root is accepted");
}

#[cfg(unix)]
#[test]
fn a_root_swapped_for_a_symlink_is_refused_on_write() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("store");
    let store = Store::open(&root).expect("store");
    let image = encode(&module()).expect("encode");
    store.put(&image).expect("first put");

    // Replace the validated directory with a symlink to another directory.
    let moved = directory.path().join("moved");
    fs::rename(&root, &moved).expect("move");
    let elsewhere = directory.path().join("elsewhere");
    fs::create_dir(&elsewhere).expect("elsewhere");
    std::os::unix::fs::symlink(&elsewhere, &root).expect("symlink");

    let second = encode(&{
        let mut module = InfinityModule::new();
        let root = module.push(Inode::Int(7));
        module.set_root(Some(root));
        module
    })
    .expect("encode second");
    let error = store.put(&second).expect_err("a swapped root is refused");
    assert_eq!(error.code(), "infinity/store", "{error}");
    assert!(fs::read_dir(&elsewhere)
        .expect("elsewhere")
        .next()
        .is_none());
}
