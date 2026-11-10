//! INF-COMPRESS-01: `decompress` with the documented 1 GiB ceiling must not
//! allocate the full ceiling up front for a frame that records no content
//! size.
//!
//! The defect (AUDIT-REPORT.md:906, W4 CONFIRMED, W18-R2-E re-confirmed):
//! `zstd::bulk::decompress` does `Vec::with_capacity(capacity)` where
//! `capacity` falls back to the caller's `max_output` when the frame carries
//! no content size, so a 35-byte payload decompressed with a 1 GiB ceiling
//! commits 1 GiB of virtual memory. W4 measured it as 1026.8 MiB private
//! bytes against a 3.6 MiB working set while holding the Vec for 2 s — the
//! 1 GiB is committed-but-untouched memory, so a working-set measurement
//! would miss it entirely.
//!
//! These tests measure the allocation itself with a counting global
//! allocator (peak live heap bytes during the call), not RSS, plus a
//! hold variant mirroring W4's `w4_compress01_alloc_hold` so the private
//! bytes can be sampled externally with `rss_watch.ps1`.

#![cfg(feature = "zstd")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Live heap bytes (allocated minus freed) and the peak of that figure.
static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let live = LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Serialises the allocation measurements: the harness runs the tests in
/// this binary on several threads, and a concurrent test's allocations
/// would otherwise land inside another test's peak window.
static MEASURE_LOCK: Mutex<()> = Mutex::new(());

fn lock_measure() -> std::sync::MutexGuard<'static, ()> {
    MEASURE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Peak live heap bytes attributable to `f`, in bytes.
fn peak_live_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let live_before = LIVE_BYTES.load(Ordering::Relaxed);
    PEAK_BYTES.store(live_before, Ordering::Relaxed);
    let value = f();
    let peak = PEAK_BYTES.load(Ordering::Relaxed);
    (value, peak.saturating_sub(live_before))
}

/// A zstd frame with NO content-size field, from the streaming encoder
/// (which cannot know the total size up front).
fn sizeless_frame(payload: &[u8]) -> Vec<u8> {
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).expect("streaming encoder");
    encoder.write_all(payload).expect("encode");
    let frame = encoder.finish().expect("finish");
    // Frame header descriptor, byte 4: bit 5 (0x20) is the content-size flag.
    assert_eq!(
        frame[4] & 0x20,
        0,
        "streaming encoder must not record a content size"
    );
    frame
}

/// The same, compressed with a dictionary (streaming encoder, so still
/// size-less).
fn sizeless_frame_with_dictionary(payload: &[u8], dictionary: &[u8]) -> Vec<u8> {
    let mut reader =
        zstd::stream::read::Encoder::with_dictionary(std::io::Cursor::new(payload), 3, dictionary)
            .expect("streaming dictionary encoder");
    let mut frame = Vec::new();
    reader.read_to_end(&mut frame).expect("encode");
    assert_eq!(
        frame[4] & 0x20,
        0,
        "streaming encoder must not record a content size"
    );
    frame
}

const PAYLOAD: &[u8] = b"hello world, this is a tiny payload";
const CEILING: usize = 1 << 30;
/// 8 MiB: 128x below the 1 GiB defect, ~20x above the ~0.4 MiB a streaming
/// decode of a 35-byte payload actually needs (128 KiB read chunk +
/// ~128 KiB decoder input buffer + output growth).
const PEAK_BOUND: usize = 8 << 20;

#[test]
fn sizeless_frame_decompress_does_not_allocate_the_ceiling() {
    use active_infinity::compress::decompress;
    let frame = sizeless_frame(PAYLOAD);
    let _guard = lock_measure();
    let (out, peak) = peak_live_during(|| decompress(&frame, CEILING).expect("decompress"));
    assert_eq!(out.as_slice(), PAYLOAD);
    println!("INF-COMPRESS-01 decompress(max=1GiB) peak live heap = {peak} bytes");
    assert!(
        peak < PEAK_BOUND,
        "decompress allocated {peak} bytes for a 35-byte payload with a 1 GiB ceiling (bound {PEAK_BOUND})"
    );
}

#[test]
fn sizeless_frame_decompress_with_dictionary_does_not_allocate_the_ceiling() {
    use active_infinity::compress::{decompress_with_dictionary, train_dictionary};
    // A dictionary trained from representative payloads, as the module's
    // own `dictionary_round_trips` test does.
    let samples: Vec<Vec<u8>> = (0..32u8)
        .map(|seed| {
            let mut sample = PAYLOAD.to_vec();
            sample.push(seed);
            sample
        })
        .collect();
    let dictionary = train_dictionary(&samples, 4_096).expect("train dictionary");
    let frame = sizeless_frame_with_dictionary(PAYLOAD, &dictionary);
    let _guard = lock_measure();
    let (out, peak) = peak_live_during(|| {
        decompress_with_dictionary(&frame, CEILING, &dictionary).expect("decompress")
    });
    assert_eq!(out.as_slice(), PAYLOAD);
    println!("INF-COMPRESS-01 decompress_with_dictionary(max=1GiB) peak live heap = {peak} bytes");
    assert!(
        peak < PEAK_BOUND,
        "decompress_with_dictionary allocated {peak} bytes for a 35-byte payload with a 1 GiB ceiling (bound {PEAK_BOUND})"
    );
}

/// Hold variant mirroring W4's `w4_compress01_alloc_hold`: the allocation
/// lives only ~90 us in the tests above, too short for an external
/// sampler to see. This performs the identical call, then holds the
/// returned Vec alive for 2 s so `rss_watch.ps1` can sample the
/// process's private bytes. W4 measured 1026.8 MiB private bytes on the
/// old code; the fixed code holds a 35-byte Vec.
#[test]
fn sizeless_frame_decompress_hold() {
    use active_infinity::compress::decompress;
    let frame = sizeless_frame(PAYLOAD);
    let out = {
        let _guard = lock_measure();
        decompress(&frame, CEILING).expect("decompress")
    };
    assert_eq!(out.len(), PAYLOAD.len());
    println!(
        "INF-COMPRESS-01-HOLD holding {}-byte Vec (capacity {}) for 2 s",
        out.len(),
        out.capacity()
    );
    std::thread::sleep(std::time::Duration::from_secs(2));
    drop(out);
}
