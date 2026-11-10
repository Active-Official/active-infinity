//! Regression tests for round-1 finding INF-08 (AUDIT-REPORT.md §B.3):
//! `SecretBytes` Clone / Prepared-secrets transcription + Debug/Display exist
//! (redacted) contrary to the lib.rs claim; zeroize covers `len` only, spare
//! capacity not zeroed.
//!
//! Verdicts, proven by the fail-before probe run at HEAD `94527c1` and the
//! fix that followed (see the INF-08 record):
//!   (a) Clone / transcription — CONFIRMED and FIXED. `SecretBytes` still
//!       derives `Clone` (it must: `Inode` / `InfinityModule` derive it), now
//!       documented as the single sanctioned copy path. The `Prepared`
//!       second transcription is GONE: the encoder reads secret bytes from
//!       the prepared nodes (`Prepared::secret_bytes()`), and
//!       `reject_secret_copies` takes borrowed slices. `Prepared` no longer
//!       derives `Clone`.
//!   (b) Debug/Display — CONFIRMED and FIXED. `Display` is REMOVED, so
//!       `format!("{}", secret)` no longer compiles; the redacting `Debug`
//!       (`Secret(***)`) is kept, and lib.rs guarantee #3 now states exactly
//!       that. There is no test asserting Display here on purpose: the
//!       removal is proven by the full build (any `{}` use fails to compile)
//!       and by the two updated tests that used to pin it
//!       (`unit_tests::secrets_never_leak_through_debug_or_exports`,
//!       `redteam_tests` leak surfaces).
//!   (c) Zeroize spare capacity — NOT REPRODUCED. The audit's premise
//!       ("`Vec<u8>::zeroize` zeroes `len` only") is false for the pinned
//!       `zeroize` 1.9.1: its `Vec` impl zeroes `spare_capacity_mut()`
//!       first, then the elements. Proven two ways pre-fix: the heap-reuse
//!       probe below observed the marker in 0/100 iterations, while a
//!       control with a plain `Vec` (no zeroize) observed it in 95/100 —
//!       the allocator really does hand the freed block back, and
//!       `SecretBytes::drop` genuinely zeroes the spare. No `Drop` change
//!       was made; the test below stays as the guard that fails first if
//!       spare capacity ever survives a drop again.

use active_infinity::{content_hash, encode, InfinityModule, Inode, SecretBytes};

const CANARY: &str = "hunter2-canary-inf08";

fn secret_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from(CANARY)));
    let root = module.push(Inode::Array {
        elements: vec![secret],
    });
    module.set_root(Some(root));
    module
}

/// (b) Debug exists and is redacted: `Secret(***)`, never the bytes.
/// This is the behaviour the fix KEEPS (redacting Debug stays); it pins the
/// current fact so a future change cannot silently alter it.
#[test]
fn debug_is_redacted_constant() {
    let rendered = format!("{:?}", SecretBytes::from(CANARY));
    assert_eq!(rendered, "Secret(***)");
    assert!(!rendered.contains(CANARY));
}

/// (a) Clone is a live second copy: cloning a module and dropping the
/// original leaves the clone fully usable (it still encodes to identical
/// bytes). Clone is structurally required (`Inode` / `InfinityModule`
/// derive it); the fix keeps Clone and documents it as the single
/// sanctioned copy path.
#[test]
fn clone_is_a_live_second_copy() {
    let module = secret_module();
    let expected = encode(&module).unwrap();
    let cloned = module.clone();
    drop(module);
    let actual = encode(&cloned).unwrap();
    assert_eq!(actual, expected);
}

/// (c) Guard: a drop must zeroize the whole allocation, spare capacity
/// included.
///
/// Build a `Vec` whose `len` (8 bytes) holds the secret and whose spare
/// capacity (56 bytes) holds a distinctive marker, wrap it in a
/// `SecretBytes`, drop it, then ask the allocator for a fresh 64-byte block
/// and look for the marker. The marker must never be observed.
///
/// Best-effort by construction (it depends on the allocator handing the
/// freed block back for the next same-size request): the cycle is repeated
/// 100 times. Pre-fix this probe observed the marker in 0/100 iterations
/// while a plain-`Vec` control observed it in 95/100, which is what proved
/// sub-issue (c) NOT REPRODUCED — `zeroize` 1.9.1 already zeroes the spare.
/// The test stays as the guard: if a future `zeroize` version or a future
/// `Drop` edit ever lets spare capacity survive again, this fails first.
/// (If a future allocator stops reusing freed blocks the test passes
/// vacuously; that is recorded here, not hidden.)
#[test]
fn drop_zeroizes_spare_capacity() {
    const SPARE_MARKER: &[u8; 56] = b"INF08-SPARE-MARKER-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const SECRET: &[u8; 8] = b"INF08-42";
    let mut marker_hits = 0usize;
    let mut secret_hits = 0usize;
    for _ in 0..100 {
        let mut raw = vec![0u8; 64];
        raw[..8].copy_from_slice(SECRET);
        raw[8..].copy_from_slice(SPARE_MARKER);
        raw.truncate(8);
        assert_eq!(raw.capacity(), 64, "probe setup: capacity must be 64");
        let secret = SecretBytes::new(raw);
        drop(secret);
        // The probe buffer holds `MaybeUninit` slots: reading them back as
        // bytes is the sanctioned way to observe what the freed allocation
        // left behind (and the only way clippy accepts — `set_len` on a
        // `Vec<u8>` trips `clippy::uninit_vec`).
        let mut probe: Vec<std::mem::MaybeUninit<u8>> = Vec::with_capacity(64);
        // SAFETY: `MaybeUninit` is valid for any byte pattern; `set_len`
        // only marks the slots initialized-as-`MaybeUninit`, which is
        // always sound. Test-only.
        unsafe {
            probe.set_len(64);
        }
        let bytes: &[u8] = unsafe { std::slice::from_raw_parts(probe.as_ptr().cast::<u8>(), 64) };
        if bytes.windows(56).any(|w| w == SPARE_MARKER) {
            marker_hits += 1;
        }
        if bytes.windows(8).any(|w| w == SECRET) {
            secret_hits += 1;
        }
    }
    // The `len` bytes are zeroized; the secret must never be observed in a
    // recycled block.
    assert_eq!(secret_hits, 0, "secret bytes survived the drop");
    // The spare-capacity marker must never be observed either.
    assert_eq!(
        marker_hits, 0,
        "spare-capacity marker survived the drop in {marker_hits}/100 iterations"
    );
}

/// (a) The `Prepared.secrets` transcription is load-bearing for the secret
/// heap, so removing it must not change a single output byte. Golden values
/// recorded pre-fix at HEAD `94527c1` (fail-before probe run):
/// len 344, content hash
/// `113d003854fbee2c54f1995e996920202492b6b66bf38ce9123f6c1188cc934c`.
#[test]
fn secret_module_golden_hash() {
    let module = secret_module();
    let bytes = encode(&module).unwrap();
    assert_eq!(bytes.len(), 344, "encoded length changed");
    let hash = content_hash(&bytes).unwrap();
    let rendered = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        rendered, "113d003854fbee2c54f1995e996920202492b6b66bf38ce9123f6c1188cc934c",
        "encoded bytes changed"
    );
    let decoded = active_infinity::decode(&bytes).unwrap();
    assert_eq!(decoded, module);
}
