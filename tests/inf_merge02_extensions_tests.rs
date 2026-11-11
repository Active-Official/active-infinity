//! INF-MERGE-02: identical non-UTF-8 extensions + any secret used to be a
//! spurious `<extensions>` conflict.
//!
//! `extensions_key` returned `None` whenever secrets were non-empty and any
//! extension payload was not UTF-8, and `metadata_plan` treated either side
//! being `None` as an `<extensions>` conflict without comparing left vs right
//! or consulting base. These tests pin the fix: a non-UTF-8 payload next to a
//! secret is compared by a redaction-safe key (the payload with secret bytes
//! replaced, then blake3-hashed), so identical sets merge clean, a one-sided
//! change is adopted, and only a genuine two-sided change conflicts.

use active_infinity::merge::{merge, ConflictKind, Merge};
use active_infinity::{InfinityModule, Inode, SecretBytes};

/// A payload that is not valid UTF-8: 0xff and 0xfe never appear in UTF-8.
const BINARY_A: &[u8] = b"\x00\xff\xfe\x80\x01binary-a";
/// A second non-UTF-8 payload, distinct from [`BINARY_A`].
const BINARY_B: &[u8] = b"\x00\xff\xfe\x80\x02binary-b";
/// A third non-UTF-8 payload, distinct from both.
const BINARY_C: &[u8] = b"\x00\xff\xfe\x80\x03binary-c";

fn int_fields(fields: &[(&str, i64)]) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut entries = Vec::new();
    for (name, value) in fields {
        let id = module.push(Inode::Int(*value));
        entries.push((name.to_string(), id));
    }
    let root = module.push(Inode::Table { fields: entries });
    module.set_root(Some(root));
    module
}

/// Push a secret node into the module. The node need not be reachable: the
/// merge's secret walk sees every node in the arena, so an unreferenced
/// secret is exactly the "any secret" of the finding.
fn with_secret(module: &mut InfinityModule, secret: &[u8]) {
    let _ = module.push(Inode::Secret(SecretBytes::new(secret.to_vec())));
}

fn conflicts(result: Merge) -> Vec<active_infinity::Conflict> {
    match result {
        Merge::Conflicts(conflicts) => conflicts,
        Merge::Clean(_) => panic!("expected conflicts"),
    }
}

fn clean_module(result: Merge) -> InfinityModule {
    match result {
        Merge::Clean(module) => *module,
        Merge::Conflicts(found) => panic!("expected a clean merge, got {found:?}"),
    }
}

/// The audit probe verbatim: an identical secret and an identical binary
/// extension on all three sides. Before the fix this is
/// `Conflicts([<extensions> KindMismatch])`; after it, a clean no-op merge.
#[test]
fn identical_nonutf8_extensions_with_a_secret_merge_clean() {
    let mut base = int_fields(&[("a", 1)]);
    with_secret(&mut base, b"test-secret");
    base.set_extensions(vec![(7, BINARY_A.to_vec())]);
    let mut left = int_fields(&[("a", 1)]);
    with_secret(&mut left, b"test-secret");
    left.set_extensions(vec![(7, BINARY_A.to_vec())]);
    let mut right = int_fields(&[("a", 1)]);
    with_secret(&mut right, b"test-secret");
    right.set_extensions(vec![(7, BINARY_A.to_vec())]);

    let merged = clean_module(merge(&base, &left, &right).expect("merge"));
    assert_eq!(merged.extensions(), &[(7, BINARY_A.to_vec())]);
}

/// The case a base-first shortcut alone would not fix: only the right side
/// changes the binary extension, next to a secret. The redaction-safe key
/// compares, the base consult sees the left side unchanged, and the right
/// set is adopted.
#[test]
fn a_one_sided_nonutf8_extension_change_with_a_secret_is_adopted() {
    let mut base = int_fields(&[("a", 1)]);
    with_secret(&mut base, b"test-secret");
    base.set_extensions(vec![(7, BINARY_A.to_vec())]);
    let mut left = int_fields(&[("a", 1)]);
    with_secret(&mut left, b"test-secret");
    left.set_extensions(vec![(7, BINARY_A.to_vec())]);
    let mut right = int_fields(&[("a", 1)]);
    with_secret(&mut right, b"test-secret");
    right.set_extensions(vec![(7, BINARY_B.to_vec())]);

    let merged = clean_module(merge(&base, &left, &right).expect("merge"));
    assert_eq!(merged.extensions(), &[(7, BINARY_B.to_vec())]);
}

/// A genuine two-sided change still conflicts, and it conflicts exactly once,
/// on `<extensions>`: the fix must not make every binary extension merge.
#[test]
fn different_nonutf8_extensions_on_both_sides_with_a_secret_still_conflict() {
    let mut base = int_fields(&[("a", 1)]);
    with_secret(&mut base, b"test-secret");
    base.set_extensions(vec![(7, BINARY_A.to_vec())]);
    let mut left = int_fields(&[("a", 1)]);
    with_secret(&mut left, b"test-secret");
    left.set_extensions(vec![(7, BINARY_B.to_vec())]);
    let mut right = int_fields(&[("a", 1)]);
    with_secret(&mut right, b"test-secret");
    right.set_extensions(vec![(7, BINARY_C.to_vec())]);

    let found = conflicts(merge(&base, &left, &right).expect("merge"));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].field, "<extensions>");
    assert_eq!(found[0].kind, ConflictKind::KindMismatch);
}

/// Adding a binary extension on one side only, next to a secret, is adopted.
/// The base and left keys are both the empty set, so the base consult takes
/// the right side.
#[test]
fn a_nonutf8_extension_added_on_one_side_with_a_secret_is_adopted() {
    let mut base = int_fields(&[("a", 1)]);
    with_secret(&mut base, b"test-secret");
    let mut left = int_fields(&[("a", 1)]);
    with_secret(&mut left, b"test-secret");
    let mut right = int_fields(&[("a", 1)]);
    with_secret(&mut right, b"test-secret");
    right.set_extensions(vec![(7, BINARY_A.to_vec())]);

    let merged = clean_module(merge(&base, &left, &right).expect("merge"));
    assert_eq!(merged.extensions(), &[(7, BINARY_A.to_vec())]);
}

/// Two payloads that differ only in the secret bytes they carry redact alike,
/// exactly as the UTF-8 branch already behaves: the hash is over the redacted
/// bytes, not the raw payload. The secrets are the same length on purpose, so
/// the length prefix in the key cannot distinguish them either.
#[test]
fn extensions_differing_only_in_secret_bytes_merge_clean() {
    let mut base = int_fields(&[("a", 1)]);
    with_secret(&mut base, b"s3cr3t-base-0001");
    let mut base_payload = b"prefix-".to_vec();
    base_payload.extend_from_slice(b"s3cr3t-base-0001");
    base.set_extensions(vec![(7, base_payload)]);
    let mut left = int_fields(&[("a", 1)]);
    with_secret(&mut left, b"s3cr3t-left-0001");
    let mut left_payload = b"prefix-".to_vec();
    left_payload.extend_from_slice(b"s3cr3t-left-0001");
    left.set_extensions(vec![(7, left_payload.clone())]);
    let mut right = int_fields(&[("a", 1)]);
    with_secret(&mut right, b"s3cr3t-right-001");
    let mut right_payload = b"prefix-".to_vec();
    right_payload.extend_from_slice(b"s3cr3t-right-001");
    right.set_extensions(vec![(7, right_payload)]);

    let merged = clean_module(merge(&base, &left, &right).expect("merge"));
    assert_eq!(merged.extensions(), &[(7, left_payload)]);
}

/// The binary twin of `extensions_differing_only_in_secret_bytes_merge_clean`:
/// the payloads are not UTF-8 (a 0xff byte on each side of the secret), so
/// they take the new hash branch. The hash must be over the redacted bytes:
/// a hash of the raw payload would distinguish the three secrets and this
/// merge would conflict, which is exactly the behaviour the UTF-8 branch
/// already refuses to have.
#[test]
fn binary_extensions_differing_only_in_secret_bytes_merge_clean() {
    let mut base = int_fields(&[("a", 1)]);
    with_secret(&mut base, b"s3cr3t-base-0001");
    let mut base_payload = vec![0xff];
    base_payload.extend_from_slice(b"s3cr3t-base-0001");
    base_payload.push(0xfe);
    base.set_extensions(vec![(7, base_payload)]);
    let mut left = int_fields(&[("a", 1)]);
    with_secret(&mut left, b"s3cr3t-left-0001");
    let mut left_payload = vec![0xff];
    left_payload.extend_from_slice(b"s3cr3t-left-0001");
    left_payload.push(0xfe);
    left.set_extensions(vec![(7, left_payload.clone())]);
    let mut right = int_fields(&[("a", 1)]);
    with_secret(&mut right, b"s3cr3t-right-001");
    let mut right_payload = vec![0xff];
    right_payload.extend_from_slice(b"s3cr3t-right-001");
    right_payload.push(0xfe);
    right.set_extensions(vec![(7, right_payload)]);

    let merged = clean_module(merge(&base, &left, &right).expect("merge"));
    assert_eq!(merged.extensions(), &[(7, left_payload)]);
}

/// The untouched UTF-8 branch: identical text extensions next to a secret
/// already merged clean before this fix, and still do.
#[test]
fn identical_utf8_extensions_with_a_secret_still_merge_clean() {
    let mut base = int_fields(&[("a", 1)]);
    with_secret(&mut base, b"test-secret");
    base.set_extensions(vec![(7, b"text extension".to_vec())]);
    let mut left = int_fields(&[("a", 1)]);
    with_secret(&mut left, b"test-secret");
    left.set_extensions(vec![(7, b"text extension".to_vec())]);
    let mut right = int_fields(&[("a", 1)]);
    with_secret(&mut right, b"test-secret");
    right.set_extensions(vec![(7, b"text extension".to_vec())]);

    let merged = clean_module(merge(&base, &left, &right).expect("merge"));
    assert_eq!(merged.extensions(), &[(7, b"text extension".to_vec())]);
}

/// The untouched no-secret branch: identical binary extensions with no secret
/// in the module already merged clean (hex key), and still do.
#[test]
fn identical_nonutf8_extensions_without_a_secret_merge_clean() {
    let base = {
        let mut module = int_fields(&[("a", 1)]);
        module.set_extensions(vec![(7, BINARY_A.to_vec())]);
        module
    };
    let left = {
        let mut module = int_fields(&[("a", 1)]);
        module.set_extensions(vec![(7, BINARY_A.to_vec())]);
        module
    };
    let right = {
        let mut module = int_fields(&[("a", 1)]);
        module.set_extensions(vec![(7, BINARY_A.to_vec())]);
        module
    };

    let merged = clean_module(merge(&base, &left, &right).expect("merge"));
    assert_eq!(merged.extensions(), &[(7, BINARY_A.to_vec())]);
}

/// The key sorts by tag, so the same set stored in a different order compares
/// equal even on the new binary-plus-secret path.
#[test]
fn extension_order_does_not_matter_with_a_secret_and_binary_payloads() {
    let mut base = int_fields(&[("a", 1)]);
    with_secret(&mut base, b"test-secret");
    base.set_extensions(vec![(3, BINARY_A.to_vec()), (7, BINARY_B.to_vec())]);
    let mut left = int_fields(&[("a", 1)]);
    with_secret(&mut left, b"test-secret");
    left.set_extensions(vec![(7, BINARY_B.to_vec()), (3, BINARY_A.to_vec())]);
    let mut right = int_fields(&[("a", 1)]);
    with_secret(&mut right, b"test-secret");
    right.set_extensions(vec![(3, BINARY_A.to_vec()), (7, BINARY_B.to_vec())]);

    let merged = clean_module(merge(&base, &left, &right).expect("merge"));
    assert_eq!(merged.extensions().len(), 2);
    assert!(merged.extensions().contains(&(3, BINARY_A.to_vec())));
    assert!(merged.extensions().contains(&(7, BINARY_B.to_vec())));
}

/// A mixed set (one text payload, one binary payload) next to a secret: the
/// text half takes the redacted-text branch, the binary half the hash branch,
/// and a one-sided change to the binary half is still adopted.
#[test]
fn mixed_utf8_and_binary_extensions_with_a_secret_merge_on_a_one_sided_change() {
    let mut base = int_fields(&[("a", 1)]);
    with_secret(&mut base, b"test-secret");
    base.set_extensions(vec![
        (3, b"text extension".to_vec()),
        (7, BINARY_A.to_vec()),
    ]);
    let mut left = int_fields(&[("a", 1)]);
    with_secret(&mut left, b"test-secret");
    left.set_extensions(vec![
        (3, b"text extension".to_vec()),
        (7, BINARY_A.to_vec()),
    ]);
    let mut right = int_fields(&[("a", 1)]);
    with_secret(&mut right, b"test-secret");
    right.set_extensions(vec![
        (3, b"text extension".to_vec()),
        (7, BINARY_B.to_vec()),
    ]);

    let merged = clean_module(merge(&base, &left, &right).expect("merge"));
    assert_eq!(
        merged.extensions(),
        &[(3, b"text extension".to_vec()), (7, BINARY_B.to_vec()),]
    );
}

/// The secret itself need not be UTF-8: the byte-level redaction compares
/// against the raw secret bytes, where the text path's lossy conversion would
/// never match its own copy.
#[test]
fn a_nonutf8_secret_with_nonutf8_extensions_merges_clean() {
    let mut base = int_fields(&[("a", 1)]);
    with_secret(&mut base, &[0xff, 0x00, 0x41, 0xfe]);
    base.set_extensions(vec![(7, BINARY_A.to_vec())]);
    let mut left = int_fields(&[("a", 1)]);
    with_secret(&mut left, &[0xff, 0x00, 0x41, 0xfe]);
    left.set_extensions(vec![(7, BINARY_A.to_vec())]);
    let mut right = int_fields(&[("a", 1)]);
    with_secret(&mut right, &[0xff, 0x00, 0x41, 0xfe]);
    right.set_extensions(vec![(7, BINARY_A.to_vec())]);

    let merged = clean_module(merge(&base, &left, &right).expect("merge"));
    assert_eq!(merged.extensions(), &[(7, BINARY_A.to_vec())]);
}
