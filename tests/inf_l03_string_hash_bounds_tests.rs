//! Regression tests for INF-L03: `Validated::string()` / `hash_entry()` slice
//! without per-call bounds checks.
//!
//! Audit (`AUDIT-REPORT.md:787`, at 6aad041): `src/validate.rs:~390` —
//! `string()` does `&buf[heap+start..heap+end]` and `hash_entry()` does
//! `&buf[offset..offset+32]` with only the *validation-time* invariant as
//! guard; a validator bug or a future code path that mutates `ends` would
//! panic instead of erroring. `blob()`/`secret()` do check end vs ends.
//! Fix: use `buf.get(..)` in `string()`/`hash_entry()` (as `node()` already
//! does). Related: `string_heap_len()`/`blob_heap_len()` use `.unwrap_or(0)`
//! on `read_u32`, silently masking a truncated table — unreachable after
//! `validate_layout`, but the masking pattern is the same class.
//!
//! The fix (record `records/F2-INF/INF-L03.md`):
//!
//! - `string()`: checked arithmetic for the absolute range, the range checked
//!   against `ends[Strings]` (as `blob()`/`secret()` already do), then
//!   `buf.get(start..end)`; any fault is `Error::StringRef(id)`. The `ends`
//!   check is load-bearing, not belt-and-braces: `get` alone only proves the
//!   range is inside the *buffer*, and an end past the section end but inside
//!   the buffer would silently read the next section's bytes as a "string".
//! - `hash_entry()`: `checked_add(32)` plus `buf.get(offset..end)`;
//!   any fault is the same `Error::Offset { section: "hashes", .. }` the
//!   out-of-range index already returns — the shape `node()` already uses.
//! - `blob_entry()`: the same unchecked 32-byte slice, found en route —
//!   `buf.get(offset..end)` with `Error::Blob { reason: "entry out of range" }`.
//! - `string_heap_len()`/`blob_heap_len()`: no more `unwrap_or(0)` on a
//!   buffer read. Both lengths are now derived from the validated `ends`
//!   (`section_end` computes the strings end from this same heap-length word
//!   and the blobs end from the summed entry lengths, and `check_blobs`
//!   proves the payloads contiguous), so the values are provably identical
//!   and no read can fail at all.
//!
//! Why there IS a public-path fail-before probe for `string()` but NOT for
//! `hash_entry()`/`blob_entry()`: `string()`'s range is *data-dependent* —
//! both ends come from the offset table, which lives in caller-owned memory.
//! A caller that mutates the buffer after validation (a shared mapping, a
//! reused `Vec`, a validator bug that mis-records `ends`) reaches the old
//! unchecked slice with attacker-controlled ends. The tests below reproduce
//! exactly that: the image bytes sit in an `UnsafeCell`, the `Validated` is
//! built over them, and the table words are then rewritten through the cell
//! — the sanctioned interior-mutability pattern, so the mutation while the
//! shared borrow is live is sound. Before the fix the accessor panics; after
//! the fix it returns `Error::StringRef`. `hash_entry()`/`blob_entry()` take
//! only an index, and their offsets are index-derived and layout-validated,
//! so no public API (and no buffer mutation) can push their slice out of
//! range — the same "no public-path probe" reasoning INF-L01 records for
//! `decode.rs`. Their half of the fix is defence in depth, pinned by the
//! round-trip tests below and by code review.

use std::cell::UnsafeCell;

use active_infinity::ir::{ProvEntry, ProvValue, Provenance};
use active_infinity::layout::{DecodeOpts, Section};
use active_infinity::{encode, InfinityModule, Inode, Validated};

/// Fixture: one string node, one blob node, a table root naming both, and a
/// provenance block carrying one hash entry — so the image has a non-empty
/// string heap, blob table, and hash table. Returns the module, the blob
/// payload hash, and the provenance hash, so `blob_entry` / `hash_entry` can
/// each be checked against the right value.
fn fixture_module() -> (InfinityModule, [u8; 32], [u8; 32]) {
    let payload = vec![0x5Au8; 256];
    let hash = *blake3::hash(&payload).as_bytes();
    let mut module = InfinityModule::new();
    let text = module.push(Inode::Str("hello".to_string()));
    let blob = module.push(Inode::Blob {
        hash,
        size: payload.len() as u64,
        tainted: false,
        media_type: "application/octet-stream".to_string(),
        payload: Some(payload),
    });
    let root = module.push(Inode::Table {
        fields: vec![("greeting".to_string(), text), ("data".to_string(), blob)],
    });
    module.set_root(Some(root));
    let prov_hash = [0xABu8; 32];
    module.set_provenance(Some(Provenance {
        producer: Some("inf-l03-probe".to_string()),
        timestamp_ms: 0,
        model: None,
        tool: None,
        parent: None,
        entries: vec![ProvEntry {
            key: "parent-hash".to_string(),
            value: ProvValue::Hash(prov_hash),
        }],
    }));
    (module, hash, prov_hash)
}

/// Build the fixture image inside an `UnsafeCell` and validate a view over
/// it. The cell is what lets a test rewrite the table words *after*
/// validation — the buffer-mutated-under-a-validated-view scenario INF-L03
/// is about — without moving the bytes the `Validated` borrows.
fn validated_cell() -> UnsafeCell<Vec<u8>> {
    let (module, _, _) = fixture_module();
    let image = encode(&module).expect("encode fixture module");
    UnsafeCell::new(image)
}

fn validated(cell: &UnsafeCell<Vec<u8>>) -> Validated<'_> {
    let bytes: &[u8] = unsafe { &*cell.get() };
    Validated::new(bytes, DecodeOpts::default()).expect("validate fixture image")
}

/// Rewrite one little-endian `u32` word of the image bytes through the cell.
fn poke_u32(cell: &UnsafeCell<Vec<u8>>, at: usize, value: u32) {
    unsafe {
        let base = (*cell.get()).as_mut_ptr();
        let le = value.to_le_bytes();
        base.add(at).copy_from_nonoverlapping(le.as_ptr(), 4);
    }
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"))
}

/// The string-table entry for string `id`: (start word, end word) offsets.
fn string_entry(validated: &Validated<'_>, id: u32) -> (usize, u32, u32) {
    let span = validated.span(Section::Strings);
    let table = span.offset as usize + id as usize * 4;
    let bytes = validated.buf();
    (table, read_u32(bytes, table), read_u32(bytes, table + 4))
}

#[test]
fn inf_l03_string_end_u32_max_errors_not_panics() {
    let cell = validated_cell();
    let validated = validated(&cell);
    // Corrupt string 0's end word to u32::MAX: the old
    // `&buf[heap+start..heap+end]` panics (range end far past the buffer);
    // the fix reports `Error::StringRef(0)`.
    let (table, _, _) = string_entry(&validated, 0);
    poke_u32(&cell, table + 4, u32::MAX);
    let error = validated
        .string(0)
        .expect_err("a u32::MAX string end must error");
    assert_eq!(error.code(), "infinity/string-ref", "{error:?}");
}

#[test]
fn inf_l03_string_inverted_range_errors_not_panics() {
    let cell = validated_cell();
    let validated = validated(&cell);
    // Swap string 0's start/end words so start > end: the old slice panics
    // ("slice index starts at .. but ends at .."); the fix reports
    // `Error::StringRef(0)` via `buf.get`, which returns `None` for an
    // inverted range.
    let (table, start, end) = string_entry(&validated, 0);
    assert!(end > start, "fixture string 0 must be non-empty");
    poke_u32(&cell, table, end);
    poke_u32(&cell, table + 4, start);
    let error = validated
        .string(0)
        .expect_err("an inverted string range must error");
    assert_eq!(error.code(), "infinity/string-ref", "{error:?}");
}

#[test]
fn inf_l03_string_end_past_section_but_inside_buffer_errors() {
    let cell = validated_cell();
    let validated = validated(&cell);
    // Push string 0's end 16 bytes past the string heap. The range is still
    // inside the buffer (later sections follow), so `buf.get` alone would
    // succeed and hand back the next section's bytes as a "string" — this
    // case is what the `ends[Strings]` check exists for.
    let heap_len = validated.string_heap_len();
    let buf_len = validated.buf().len();
    let heap_start = validated.span(Section::Strings).offset as usize
        + (validated.span(Section::Strings).count as usize + 1) * 4;
    assert!(
        heap_start + heap_len as usize + 16 <= buf_len,
        "the corrupted end must stay inside the buffer for this case to mean anything"
    );
    let (table, _, _) = string_entry(&validated, 0);
    poke_u32(&cell, table + 4, heap_len + 16);
    let error = validated
        .string(0)
        .expect_err("a string end past the section end must error");
    assert_eq!(error.code(), "infinity/string-ref", "{error:?}");
}

#[test]
fn inf_l03_hash_entry_round_trip() {
    let cell = validated_cell();
    let validated = validated(&cell);
    let (_, _, prov_hash) = fixture_module();
    let count = validated.header().span(Section::Hashes).count;
    assert_eq!(count, 1, "the fixture carries exactly one hash");
    assert_eq!(
        validated.hash_entry(0).expect("hash entry 0"),
        prov_hash,
        "hash_entry must return the provenance hash verbatim"
    );
    // `provenance()` reads the hash through `hash_entry`, so the round-trip
    // pins the accessor on its only in-crate path too.
    let provenance = validated
        .provenance()
        .expect("provenance parses")
        .expect("provenance present");
    assert_eq!(provenance.producer.as_deref(), Some("inf-l03-probe"));
    assert_eq!(provenance.entries.len(), 1);
    assert_eq!(provenance.entries[0].key, "parent-hash");
    assert_eq!(
        provenance.entries[0].value,
        ProvValue::Hash(prov_hash),
        "the provenance hash entry must survive the round-trip"
    );
}

#[test]
fn inf_l03_blob_entry_round_trip() {
    let cell = validated_cell();
    let validated = validated(&cell);
    let (_, hash, _) = fixture_module();
    let count = validated.header().span(Section::Blobs).count;
    assert_eq!(count, 1, "the fixture carries exactly one blob");
    let (got_hash, off, len) = validated.blob_entry(0).expect("blob entry 0");
    assert_eq!(got_hash, hash, "blob_entry must return the payload hash");
    assert_eq!(off, 0, "the first blob payload starts at the heap start");
    assert_eq!(len, 256, "the blob payload is 256 bytes");
    let payload = validated.blob(0).expect("blob 0");
    assert_eq!(payload, vec![0x5Au8; 256].as_slice());
    assert_eq!(validated.blob_heap_len(), 256);
}

#[test]
fn inf_l03_heap_len_functions_match_the_raw_table() {
    let cell = validated_cell();
    let validated = validated(&cell);
    let bytes = validated.buf();
    // String heap length, read straight off the raw bytes: the last word of
    // the offset table. This is the definition `string_heap_len` must match
    // after the ends-derived rewrite — no shared code between the two sides.
    let strings = validated.span(Section::Strings);
    let expected_strings = read_u32(bytes, strings.offset as usize + strings.count as usize * 4);
    assert_eq!(validated.string_heap_len(), expected_strings);
    assert_eq!(validated.meta().string_bytes, expected_strings);
    // Blob heap length, read straight off the raw bytes: the last entry's
    // offset + length (payloads are contiguous from the heap start).
    let blobs = validated.span(Section::Blobs);
    let last = blobs.offset as usize + (blobs.count as usize - 1) * 40;
    let expected_blobs = read_u32(bytes, last + 32) + read_u32(bytes, last + 36);
    assert_eq!(validated.blob_heap_len(), expected_blobs);
    assert_eq!(validated.meta().blob_bytes, expected_blobs);
    // Behaviour pin: every string in the heap still reads back verbatim.
    let mut strings_read: Vec<&str> = Vec::new();
    for id in 0..strings.count {
        strings_read.push(validated.string(id).expect("string reads back"));
    }
    strings_read.sort_unstable();
    assert_eq!(
        strings_read,
        [
            "application/octet-stream",
            "data",
            "greeting",
            "hello",
            "inf-l03-probe",
            "parent-hash",
        ],
        "the string heap is unchanged by the fix"
    );
}
