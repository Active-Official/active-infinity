//! Regression tests for INF-11: `BlobKey` contains the full payload bytes;
//! `encode` clones every blob payload per node (INF-BLOBKEY-01).
//!
//! `BlobKey = ([u8; 32], u64, Option<Vec<u8>>)` (`src/canonical.rs:44`,
//! at HEAD `6f18110`) carries the *full payload bytes* of a blob, and
//! three separate sites clone those bytes per `Blob` node:
//!
//! 1. `prepare()` clones every payload into the `blobs: Vec<BlobPayload>`
//!    table (`src/canonical.rs:379-386`) — one full clone per node, all
//!    simultaneously live in the table before `dedup()`;
//! 2. `prepare()` clones every surviving payload *again* into the
//!    `blob_index` key (`src/canonical.rs:395-399`);
//! 3. `build_node_tables` clones the payload per `Blob` node to build
//!    the lookup key (`src/encode.rs:809-817`) — and the `HashMap` lookup
//!    then hashes the full payload bytes on every node.
//!
//! A module with N `Blob` nodes sharing one large payload therefore pays
//! N full payload clones (transient allocation + memcpy) during encode;
//! a 512 MiB blob x 1000 nodes = 512 GiB of transient cloning. The
//! payload is redundant in the key: a materialised payload must
//! Blake3-hash to its entry hash (checked in `prepare`), so
//! `(hash, size, payload.is_some())` identifies it up to a Blake3
//! collision — exactly the same collision assumption the format already
//! makes for content addressing.
//!
//! Spec clauses (AUDIT-REPORT.md §INF-11, W4-R1-INF-CORE §INF-11,
//! CONFIRMED by W4 probe `w4_inf11_blob_encode_time`): encode of 200
//! `Blob` nodes sharing a 16 MiB payload took **9.0–14.3 s** vs **7–18 ms**
//! for the 200x16 KiB control — ~1000x — with a 16,786,352-byte image.
//!
//! The fix (audit recommendation): key blobs by
//! `(hash, size, payload.is_some())` and compare payload bytes only on
//! a `(hash, size)` collision; drop the `Vec<u8>` from `BlobKey`.
//!
//! Measurement: wall time alone cannot separate "the module itself
//! holds 3.2 GiB" from "encode cloned it three more times", so the
//! headline probe measures allocation exactly, with a counting global
//! allocator that records the peak live bytes during `encode()` (see
//! `reset_alloc_window` / `peak_live_above_baseline`). The module's own
//! 3.2 GiB is built *before* the window opens, so the window holds
//! only what `encode()` itself allocates: pre-fix that is the
//! normalised-arena clones (one per node — structural, the prepared
//! arena owns the nodes) *plus* the `blobs`-table clones (one per
//! node) *plus* the per-node lookup-key clones, i.e. ~6.4 GiB peak;
//! post-fix it is the normalised-arena clones alone, i.e. ~3.2 GiB.
//! The assertion budget (4.5 GiB) sits between the two with ~1.2 GiB
//! of margin on each side. Wall time is printed for the record, not
//! asserted tightly: it is machine-load dependent, and the module
//! build itself dominates it post-fix.
//!
//! Fail-before note: `shared_blob_encode_allocates_once_per_distinct_payload`
//! is the designed fail-before leg — it fails pre-fix on the peak-live
//! assertion and passes post-fix. Every other test in this file is a
//! pin: it passes pre-fix and must keep passing post-fix, proving the
//! fix changed no canonical byte and no refusal (no dialect bump, §2.5
//! of the record).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use active_infinity::{
    content_hash_hex, decode, encode, hash_image, validate_canonical, validate_with, DecodeOpts,
    InfinityModule, Inode, Limits, NodeId, Section, Validated,
};

// ---------------------------------------------------------------------------
// Counting allocator: exact transient-allocation measurement.
// ---------------------------------------------------------------------------

/// Live heap bytes tracked by the counting allocator below.
static LIVE_BYTES: AtomicU64 = AtomicU64::new(0);
/// High-water mark of live bytes since the last `reset_alloc_window()`.
static PEAK_SINCE_RESET: AtomicU64 = AtomicU64::new(0);
/// Live bytes at the last `reset_alloc_window()` — the baseline the peak
/// is measured above.
static BASELINE_LIVE_BYTES: AtomicU64 = AtomicU64::new(0);

/// A `System` allocator that counts live bytes. Every heap allocation in
/// this test binary — the harness, the crate under test, the test code —
/// routes through it, so the peak is exact for the measured window (see
/// the serialisation lock below: no two tests in this binary run at once,
/// and no other binary shares this process).
struct CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let live = LIVE_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed)
                + layout.size() as u64;
            PEAK_SINCE_RESET.fetch_max(live, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE_BYTES.fetch_sub(layout.size() as u64, Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            // Free the old block first, then count the new one: the peak
            // is the live bytes *after* the move, not the transient
            // old-plus-new sum (which would overstate the peak whenever
            // realloc grows in place).
            LIVE_BYTES.fetch_sub(layout.size() as u64, Ordering::Relaxed);
            let live = LIVE_BYTES.fetch_add(new_size as u64, Ordering::Relaxed) + new_size as u64;
            PEAK_SINCE_RESET.fetch_max(live, Ordering::Relaxed);
        }
        new_ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            let live = LIVE_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed)
                + layout.size() as u64;
            PEAK_SINCE_RESET.fetch_max(live, Ordering::Relaxed);
        }
        ptr
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// Open a measurement window: the peak watermark restarts from the live
/// bytes right now. Anything allocated before this call (the module under
/// test, the harness) is baseline, not signal.
fn reset_alloc_window() {
    let live = LIVE_BYTES.load(Ordering::Relaxed);
    BASELINE_LIVE_BYTES.store(live, Ordering::Relaxed);
    PEAK_SINCE_RESET.store(live, Ordering::Relaxed);
}

/// Peak live bytes above the `reset_alloc_window()` baseline, in bytes.
fn peak_live_above_baseline() -> u64 {
    PEAK_SINCE_RESET
        .load(Ordering::Relaxed)
        .saturating_sub(BASELINE_LIVE_BYTES.load(Ordering::Relaxed))
}

/// No two tests in this binary run concurrently: the counters are
/// process-wide, so a second test allocating mid-measurement would
/// pollute the peak. Every test in this file takes the lock for its
/// whole body. The lock is recovered from poisoning (`into_inner`):
/// the fail-before leg is *expected* to fail pre-fix, and a poisoned
/// lock must not take the pin tests down with it.
static MEASURE_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// Builders.
// ---------------------------------------------------------------------------

/// W4's shape, exactly: `n` `Blob` nodes sharing one payload, under an
/// `Array` root. Each node holds its *own* `Vec` clone of the payload —
/// that is the module's own representation (3.2 GiB for 200x16 MiB), and
/// it is built before the measurement window opens.
fn shared_blob_module(n: usize, payload: &[u8]) -> InfinityModule {
    let hash = *blake3::hash(payload).as_bytes();
    let mut module = InfinityModule::new();
    let mut ids = Vec::new();
    for _ in 0..n {
        ids.push(module.push(Inode::Blob {
            hash,
            size: payload.len() as u64,
            tainted: false,
            media_type: "application/octet-stream".into(),
            payload: Some(payload.to_vec()),
        }));
    }
    let root = module.push(Inode::Array { elements: ids });
    module.set_root(Some(root));
    module
}

/// Assert a module encodes, validates canonical, decodes, and re-encodes
/// to identical bytes (the canonical fixed point).
fn assert_fixed_point(module: &InfinityModule, what: &str) -> Vec<u8> {
    let image = encode(module).unwrap_or_else(|e| panic!("{what}: encode failed: {e}"));
    validate_canonical(&image, Limits::default())
        .unwrap_or_else(|e| panic!("{what}: not canonical: {e}"));
    let decoded = decode(&image).unwrap_or_else(|e| panic!("{what}: decode failed: {e}"));
    let re_encoded = encode(&decoded).unwrap_or_else(|e| panic!("{what}: re-encode failed: {e}"));
    assert_eq!(
        re_encoded, image,
        "{what}: encode/decode must be a fixed point"
    );
    image
}

/// Blob table of a structurally validated image: (hash, heap offset,
/// length) per entry.
///
/// Lenient options only: the default options prove canonicality, which
/// decodes — and decode charges the decoded-bytes budget, which an image
/// with many shared payloads can exceed (see the NOTE in the headline
/// probe). The table read needs the structure, not the decode; the
/// canonical proof for a shape lives in `assert_fixed_point`.
fn blob_table(image: &[u8]) -> Vec<([u8; 32], u32, u32)> {
    let opts = DecodeOpts {
        verify_canonical: false,
        ..DecodeOpts::default()
    };
    let validated = Validated::new(image, opts).expect("image validates structurally");
    let count = validated.span(Section::Blobs).count;
    (0..count)
        .map(|id| validated.blob_entry(id).expect("blob entry exists"))
        .collect()
}

/// Lowercase hex of 32 bytes (a content-hash digest for printing and
/// golden-pinning).
fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The `Blob` nodes of a decoded module, in node order.
fn decoded_blobs(module: &InfinityModule) -> Vec<&Inode> {
    module
        .nodes()
        .iter()
        .filter(|node| matches!(node, Inode::Blob { .. }))
        .collect()
}

// ---------------------------------------------------------------------------
// The probe: fail-before / pass-after.
// ---------------------------------------------------------------------------

/// 200 `Blob` nodes sharing one 16 MiB payload (W4's shape).
///
/// Pre-fix `encode()` clones the payload once per node into the blobs
/// table, once more per surviving entry into the `blob_index` key, and
/// once more per node for the encode-side lookup key — ~6.4 GiB peak
/// live above baseline. Post-fix the only per-node payload copy is the
/// normalised arena's own (structural: `Prepared` owns the nodes), so
/// the peak is ~3.2 GiB. The 4.5 GiB budget sits between the two with
/// ~1.2 GiB of margin on each side; the image length pins the
/// canonical bytes (W4: 16,786,352).
#[test]
fn shared_blob_encode_allocates_once_per_distinct_payload() {
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let payload = vec![0xABu8; 16 * 1024 * 1024];
    let module = shared_blob_module(200, &payload);
    reset_alloc_window();
    let start = Instant::now();
    let image = encode(&module).expect("encode succeeds");
    let elapsed = start.elapsed();
    let peak = peak_live_above_baseline();
    println!(
        "INF-11 encode 200x16MiB shared blob: {:?}, image {} bytes, \
         peak live above baseline {} bytes ({:.2} GiB)",
        elapsed,
        image.len(),
        peak,
        peak as f64 / (1u64 << 30) as f64
    );
    assert_eq!(
        image.len(),
        16_786_352,
        "image length pins the canonical bytes (W4's number)"
    );
    // The digests pin the canonical bytes (record §4): they must be
    // identical before and after the fix. They are printed — and
    // asserted — before the budget assertion, so a fail-before run
    // still reports the digests it is about to compare. The digests
    // are pure hashes of the bytes, not validation results:
    // `hash_image` hashes the image with the hash field zeroed (the
    // format's own content hash, which the encoder also stores), and
    // the raw Blake3 covers every byte including the stored hash field
    // — together with the length they pin the image byte for byte (up
    // to a Blake3 collision, the format's own assumption). Neither
    // `content_hash_hex` nor plain `validate` can read this image (see
    // the NOTE below): both funnel through the default decode path,
    // which charges the decoded-bytes budget.
    let content_digest = hash_image(&image).expect("content hash");
    let raw_digest = *blake3::hash(&image).as_bytes();
    println!(
        "INF-11 200x16MiB image content hash {}",
        hex32(&content_digest)
    );
    println!("INF-11 200x16MiB image raw blake3 {}", hex32(&raw_digest));
    assert_eq!(
        hex32(&content_digest),
        "4e42ca8f98d0c7c3decaf0e2b5daa9be92f18933ac66e8f520e1ea54b56ea080",
        "200x16MiB canonical bytes moved — the fix is not allocation-only"
    );
    assert_eq!(
        hex32(&raw_digest),
        "c08344400fb0178afa97781e0a470f9d00f7960a6106a7c19b637a91c3739087",
        "200x16MiB image bytes moved — the fix is not allocation-only"
    );
    assert!(
        peak < 4_500_000_000,
        "encode peak live {peak} bytes exceeds the 4.5 GiB budget: the payload \
         is still being cloned per node (pre-fix peak is ~6.4 GiB)"
    );
    // Drop the 3.2 GiB module before the checks below: decode clones one
    // payload per node (INF-01's decode-side accounting, out of scope
    // here), and holding both modules at once would double the peak for
    // no signal.
    drop(module);
    // The image is structurally valid under lenient options (structural
    // checks only — no decode, so no decoded-bytes charge).
    let lenient = DecodeOpts {
        verify_canonical: false,
        ..DecodeOpts::default()
    };
    validate_with(&image, lenient).expect("image validates structurally");
    // NOTE (not a regression — read before "fixing" this): this module
    // does NOT validate canonical, does NOT decode, and is NOT readable
    // by `content_hash_hex` or plain `validate`, under default limits —
    // before the fix as well as after. The default options prove
    // canonicality (INF-02), the proof decodes, and decode charges one
    // payload per `Blob` node (`decoded_payload_bytes`, INF-01):
    // 200 nodes x 16 MiB = 3.2 GiB of decoded bytes against the
    // 256 MiB `decoded bytes` limit (`Limits::max_decoded_bytes`). The
    // image is therefore encode-legal but over the decode budget, and
    // the verdicts below are printed (not asserted) so the record can
    // quote them; the fixed-point proof for this shape lives in
    // `shared_blob_image_is_a_fixed_point_within_the_decode_budget`,
    // which uses 8 nodes (128 MiB decoded) instead of 200.
    match validate_canonical(&image, Limits::default()) {
        Ok(_) => println!("INF-11 200x16MiB validate_canonical: Ok"),
        Err(error) => println!(
            "INF-11 200x16MiB validate_canonical: Err({error}) (code {})",
            error.code()
        ),
    }
    match decode(&image) {
        Ok(_) => println!("INF-11 200x16MiB decode: Ok"),
        Err(error) => println!(
            "INF-11 200x16MiB decode: Err({error}) (code {})",
            error.code()
        ),
    }
    match content_hash_hex(&image) {
        Ok(hash) => println!("INF-11 200x16MiB content_hash_hex: Ok({hash})"),
        Err(error) => println!(
            "INF-11 200x16MiB content_hash_hex: Err({error}) (code {})",
            error.code()
        ),
    }
    // The blob table holds the payload exactly once.
    let table = blob_table(&image);
    assert_eq!(table.len(), 1, "one distinct payload = one table entry");
    assert_eq!(table[0].2, 16 * 1024 * 1024, "entry length is the payload");
}

/// The same shared-payload shape as the headline probe, but sized to fit
/// the decode budget: 8 nodes x 16 MiB = 128 MiB of decoded bytes against
/// the 256 MiB `decoded bytes` limit, so the image must be a full
/// canonical fixed point (encode → validate canonical → decode →
/// re-encode identical). This is the fixed-point proof the 200-node
/// module cannot give: its 3.2 GiB of decoded bytes exceed the budget
/// by construction, before the fix as well as after (see the NOTE in
/// `shared_blob_encode_allocates_once_per_distinct_payload`).
#[test]
fn shared_blob_image_is_a_fixed_point_within_the_decode_budget() {
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let payload = vec![0xABu8; 16 * 1024 * 1024];
    let module = shared_blob_module(8, &payload);
    let image = assert_fixed_point(&module, "8x16MiB shared blob");
    println!("INF-11 8x16MiB shared-blob image: {} bytes", image.len());
    let table = blob_table(&image);
    assert_eq!(table.len(), 1, "one distinct payload = one table entry");
    assert_eq!(table[0].2, 16 * 1024 * 1024, "entry length is the payload");
}

// ---------------------------------------------------------------------------
// Pins: canonical bytes and refusals must not move (no dialect bump).
// ---------------------------------------------------------------------------

/// A mixed module exercising every blob presence class at once:
/// two nodes sharing one payload, one distinct payload of the same
/// size, one detached blob, one tainted blob, and one empty-payload
/// blob. The content hash pins the canonical bytes: the fix is
/// allocation-only, so the hash must be identical before and after
/// (captured pre-fix; see the record §4).
#[test]
fn mixed_blobs_keep_their_canonical_bytes() {
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let shared = vec![0x11u8; 1024];
    let shared_hash = *blake3::hash(&shared).as_bytes();
    let other = vec![0x22u8; 1024];
    let other_hash = *blake3::hash(&other).as_bytes();
    let empty_hash = *blake3::hash(&[]).as_bytes();
    let detached_hash = *blake3::hash(b"detached").as_bytes();
    let tainted_hash = *blake3::hash(b"tainted").as_bytes();

    let mut module = InfinityModule::new();
    let mut ids = Vec::new();
    // Two nodes sharing one payload: one table entry, two node records.
    for _ in 0..2 {
        ids.push(module.push(Inode::Blob {
            hash: shared_hash,
            size: shared.len() as u64,
            tainted: false,
            media_type: "application/octet-stream".into(),
            payload: Some(shared.clone()),
        }));
    }
    // One distinct payload of the same size: a second entry.
    ids.push(module.push(Inode::Blob {
        hash: other_hash,
        size: other.len() as u64,
        tainted: false,
        media_type: "application/octet-stream".into(),
        payload: Some(other.clone()),
    }));
    // One detached blob (no payload): its own entry.
    ids.push(module.push(Inode::Blob {
        hash: detached_hash,
        size: 8,
        tainted: false,
        media_type: "application/octet-stream".into(),
        payload: None,
    }));
    // One tainted blob: its own entry, never carrying bytes.
    ids.push(module.push(Inode::Blob {
        hash: tainted_hash,
        size: 7,
        tainted: true,
        media_type: "application/octet-stream".into(),
        payload: None,
    }));
    // One empty-payload blob: same entry class as a detached blob.
    ids.push(module.push(Inode::Blob {
        hash: empty_hash,
        size: 0,
        tainted: false,
        media_type: "application/octet-stream".into(),
        payload: Some(Vec::new()),
    }));
    let root = module.push(Inode::Array { elements: ids });
    module.set_root(Some(root));

    let image = assert_fixed_point(&module, "mixed blobs");
    let hash_hex = content_hash_hex(&image).expect("content hash");
    println!(
        "INF-11 mixed-blobs image: {} bytes, content hash {hash_hex}",
        image.len()
    );
    // Golden pin, captured pre-fix (record §4): the fix must not move a
    // single canonical byte.
    assert_eq!(
        hash_hex, "d9aad3895fe3a57b94692493d46e0e91418d97b8bebad8d6c1c897fbd53b0b41",
        "mixed-blobs canonical bytes moved — the fix is not allocation-only"
    );
    // Five presence classes, five table entries: shared (x2 nodes),
    // other, detached, tainted, empty. The entries are ordered by
    // (hash, size) and the heap holds the two materialised payloads.
    let table = blob_table(&image);
    assert_eq!(table.len(), 5, "one entry per distinct blob, got {table:?}");
    let heap: u64 = table.iter().map(|entry| entry.2 as u64).sum();
    assert_eq!(heap, 2048, "heap holds the two 1 KiB payloads only");
    // The decoded module keeps every node's payload class.
    let decoded = decode(&image).expect("decode succeeds");
    let blobs = decoded_blobs(&decoded);
    assert_eq!(blobs.len(), 6, "six blob nodes survive the round trip");
    let materialised = blobs
        .iter()
        .filter(|node| {
            matches!(
                node,
                Inode::Blob {
                    payload: Some(_),
                    ..
                }
            )
        })
        .count();
    // Shared (2) + other (1) + empty (1): decode sets the payload flag
    // from the node record's flag bit, and the empty node carries
    // `Some(vec![])`, so it round-trips as materialised-but-empty.
    // Detached and tainted stay `None`.
    assert_eq!(materialised, 4, "four nodes carry a payload after decode");
}

/// An empty-payload blob and a detached blob with the same hash and size
/// encode to the same `(hash, offset, 0)` record: keying them apart
/// would emit two duplicate records the validator refuses
/// (`src/canonical.rs`, pre-fix comment on the `BlobPayload` push).
#[test]
fn empty_payload_and_detached_blobs_share_one_table_entry() {
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let hash = *blake3::hash(&[]).as_bytes();
    let mut module = InfinityModule::new();
    let ids = vec![
        module.push(Inode::Blob {
            hash,
            size: 0,
            tainted: false,
            media_type: "application/octet-stream".into(),
            payload: Some(Vec::new()),
        }),
        module.push(Inode::Blob {
            hash,
            size: 0,
            tainted: false,
            media_type: "application/octet-stream".into(),
            payload: None,
        }),
    ];
    let root = module.push(Inode::Array { elements: ids });
    module.set_root(Some(root));
    let image = assert_fixed_point(&module, "empty + detached");
    let table = blob_table(&image);
    assert_eq!(
        table.len(),
        1,
        "empty-payload and detached blobs share one entry, got {table:?}"
    );
    assert_eq!(table[0].2, 0, "the shared entry carries no bytes");
}

/// A materialised blob and a detached blob with the same hash and size
/// are *different* table entries: collapsing them would point the
/// detached node's record at the materialised payload (and change the
/// canonical bytes). This is why the presence bit stays in the key.
#[test]
fn materialised_and_detached_blobs_with_same_hash_are_separate_entries() {
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let payload = b"same-hash-payload".to_vec();
    let hash = *blake3::hash(&payload).as_bytes();
    let mut module = InfinityModule::new();
    let ids = vec![
        module.push(Inode::Blob {
            hash,
            size: payload.len() as u64,
            tainted: false,
            media_type: "application/octet-stream".into(),
            payload: Some(payload.clone()),
        }),
        module.push(Inode::Blob {
            hash,
            size: payload.len() as u64,
            tainted: false,
            media_type: "application/octet-stream".into(),
            payload: None,
        }),
    ];
    let root = module.push(Inode::Array { elements: ids });
    module.set_root(Some(root));
    let image = assert_fixed_point(&module, "materialised + detached");
    let table = blob_table(&image);
    assert_eq!(
        table.len(),
        2,
        "materialised and detached blobs are separate entries, got {table:?}"
    );
    // The entries differ in length (payload vs 0); the heap holds the
    // payload once.
    let mut lens: Vec<u32> = table.iter().map(|entry| entry.2).collect();
    lens.sort_unstable();
    assert_eq!(lens, vec![0, payload.len() as u32]);
    // The decoded nodes keep their own payload class.
    let decoded = decode(&image).expect("decode succeeds");
    let blobs = decoded_blobs(&decoded);
    assert_eq!(blobs.len(), 2);
    assert!(
        matches!(
            blobs[0],
            Inode::Blob {
                payload: Some(_),
                ..
            }
        ),
        "first node stays materialised"
    );
    assert!(
        matches!(blobs[1], Inode::Blob { payload: None, .. }),
        "second node stays detached"
    );
}

/// Two distinct payloads of the same size are both kept: the dedup key
/// is the hash, not the size.
#[test]
fn two_distinct_payloads_of_the_same_size_are_both_kept() {
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let first = vec![0x31u8; 512];
    let second = vec![0x32u8; 512];
    let first_hash = *blake3::hash(&first).as_bytes();
    let second_hash = *blake3::hash(&second).as_bytes();
    let mut module = InfinityModule::new();
    let ids = vec![
        module.push(Inode::Blob {
            hash: first_hash,
            size: 512,
            tainted: false,
            media_type: "application/octet-stream".into(),
            payload: Some(first.clone()),
        }),
        module.push(Inode::Blob {
            hash: second_hash,
            size: 512,
            tainted: false,
            media_type: "application/octet-stream".into(),
            payload: Some(second.clone()),
        }),
    ];
    let root = module.push(Inode::Array { elements: ids });
    module.set_root(Some(root));
    let image = assert_fixed_point(&module, "two distinct payloads");
    let table = blob_table(&image);
    assert_eq!(table.len(), 2, "two distinct payloads = two entries");
    let heap: u64 = table.iter().map(|entry| entry.2 as u64).sum();
    assert_eq!(heap, 1024, "heap holds both payloads");
    let decoded = decode(&image).expect("decode succeeds");
    let blobs = decoded_blobs(&decoded);
    assert_eq!(blobs.len(), 2);
    for (node, want) in blobs.iter().zip([&first, &second]) {
        match node {
            Inode::Blob {
                payload: Some(got), ..
            } => assert_eq!(got, want, "payload bytes survive the round trip"),
            other => panic!("expected a materialised blob, got {other:?}"),
        }
    }
}

/// A tainted blob must not carry a payload — refused at `prepare()`,
/// before any table is built.
#[test]
fn tainted_blob_with_payload_is_still_refused() {
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let payload = b"tainted-bytes".to_vec();
    let hash = *blake3::hash(&payload).as_bytes();
    let mut module = InfinityModule::new();
    let node = module.push(Inode::Blob {
        hash,
        size: payload.len() as u64,
        tainted: true,
        media_type: "application/octet-stream".into(),
        payload: Some(payload),
    });
    module.set_root(Some(node));
    let error = encode(&module).expect_err("tainted + payload must be refused");
    assert_eq!(error.code(), "infinity/encode");
    assert!(
        error.to_string().contains("tainted"),
        "diagnostic names the tainted rule: {error}"
    );
}

/// A payload that does not hash to its entry hash is refused: the
/// verification this fix restructures (once per distinct payload
/// instead of once per node) must still fire for the first occurrence.
#[test]
fn blob_payload_hash_mismatch_is_still_refused() {
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let payload = b"these-bytes".to_vec();
    let wrong_hash = *blake3::hash(b"other-bytes").as_bytes();
    let mut module = InfinityModule::new();
    let node = module.push(Inode::Blob {
        hash: wrong_hash,
        size: payload.len() as u64,
        tainted: false,
        media_type: "application/octet-stream".into(),
        payload: Some(payload),
    });
    module.set_root(Some(node));
    let error = encode(&module).expect_err("hash mismatch must be refused");
    assert_eq!(error.code(), "infinity/encode");
    assert!(
        error.to_string().contains("hash mismatch"),
        "diagnostic names the hash mismatch: {error}"
    );
}

/// A payload whose length disagrees with the declared size is refused.
#[test]
fn blob_payload_length_mismatch_is_still_refused() {
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let payload = b"twelve-bytes".to_vec();
    let hash = *blake3::hash(&payload).as_bytes();
    let mut module = InfinityModule::new();
    let node = module.push(Inode::Blob {
        hash,
        size: payload.len() as u64 + 1,
        tainted: false,
        media_type: "application/octet-stream".into(),
        payload: Some(payload),
    });
    module.set_root(Some(node));
    let error = encode(&module).expect_err("length mismatch must be refused");
    assert_eq!(error.code(), "infinity/encode");
    assert!(
        error.to_string().contains("length disagrees"),
        "diagnostic names the length disagreement: {error}"
    );
}

/// Two modules that are the same logical module built in opposite
/// arena order are structurally equal and encode to identical bytes.
/// This guards `prepared_eq` after the `BlobPayload` equality change:
/// the table comparison must not depend on which node carried the
/// representative payload.
#[test]
fn structurally_equal_modules_with_shared_blobs_agree() {
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let payload = vec![0x77u8; 4096];
    let hash = *blake3::hash(&payload).as_bytes();
    let other = vec![0x88u8; 512];
    let other_hash = *blake3::hash(&other).as_bytes();
    // Build the same logical module in opposite arena order: the push
    // order is reversed, but the Array always lists [shared, shared,
    // other] *by role*, so the canonical pre-order traversal from the
    // root visits the same nodes in the same order. (An earlier form of
    // this test reversed the Array elements too, which builds a genuinely
    // different module — [other, shared, shared] — and correctly fails
    // equality. The arena order is the only thing that varies here.)
    let build = |reverse: bool| {
        let mut module = InfinityModule::new();
        // (role, hash, bytes): roles 0/1 are the two shared-payload
        // nodes, role 2 is the distinct payload.
        let mut spec: Vec<(usize, [u8; 32], Vec<u8>)> = vec![
            (0, hash, payload.clone()),
            (1, hash, payload.clone()),
            (2, other_hash, other.clone()),
        ];
        if reverse {
            spec.reverse();
        }
        let mut by_role: [Option<NodeId>; 3] = [None, None, None];
        for (role, blob_hash, bytes) in spec {
            let id = module.push(Inode::Blob {
                hash: blob_hash,
                size: bytes.len() as u64,
                tainted: false,
                media_type: "application/octet-stream".into(),
                payload: Some(bytes),
            });
            by_role[role] = Some(id);
        }
        let elements = vec![
            by_role[0].expect("shared node 0"),
            by_role[1].expect("shared node 1"),
            by_role[2].expect("other node"),
        ];
        let root = module.push(Inode::Array { elements });
        module.set_root(Some(root));
        module
    };
    let forward = build(false);
    let reversed = build(true);
    assert!(
        forward
            .try_structurally_eq(&reversed)
            .expect("equality is decidable"),
        "arena order must not change structural equality"
    );
    assert!(
        reversed
            .try_structurally_eq(&forward)
            .expect("equality is decidable"),
        "structural equality is symmetric"
    );
    let forward_image = encode(&forward).expect("forward encodes");
    let reversed_image = encode(&reversed).expect("reversed encodes");
    assert_eq!(
        forward_image, reversed_image,
        "arena order must not change the canonical bytes"
    );
}
