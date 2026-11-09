//! C ABI and WASM exports for Active Infinity.
//!
//! Every other language in the polyglot matrix calls the Rust reference through
//! this surface: there is one canonicalizer, one validator and one content hash,
//! so a binding cannot drift from the reference bytes.
//!
//! # Calling convention
//!
//! - Functions return `i32`: `0` success, `-1` invalid input, `-2` output buffer
//!   too small, `-3` internal panic (never aborts across the boundary).
//! - After a non-zero return, [`active_infinity_last_error`] returns the stable
//!   `infinity/...` code for the calling thread as a NUL-terminated string.
//!   The pointer stays valid until the next failing call on that thread.
//! - Output functions take `out` and `out_len`. On entry `*out_len` is the
//!   capacity of `out`; on success it is the number of bytes written. On
//!   `-2` it is the required size, so a caller can retry with a larger buffer.
//! - A null pointer with a non-zero length is invalid input, never UB.
//!
//! # Thread safety
//!
//! All functions are re-entrant. `last_error` is thread-local. No function
//! retains a pointer after it returns.
//!
//! # Panics
//!
//! The codec is `#![forbid(unsafe_code)]`; this shim catches any panic and
//! reports `-3` with `infinity/panic`. A panic never unwinds into C or WASM.

use std::alloc::Layout;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use active_infinity::{
    content_hash, decode, decode_with, encode, validate, validate_canonical, DecodeOpts, Limits,
};

/// ABI version. Bumped only for an incompatible layout or calling change.
pub const ABI_VERSION: u32 = 1;

/// Largest single `alloc` request. A host that asks for more is refused with a
/// null pointer (and, like every `alloc`/`free`, no change to `last_error`)
/// rather than aborting on an impossible allocation.
pub const MAX_ALLOC_BYTES: usize = 1 << 30;

/// Largest module name accepted, in bytes (excluding the NUL).
pub const MAX_NAME_BYTES: usize = 4 << 10;

/// Largest Active source accepted by `from_active`, in bytes.
pub const MAX_SOURCE_BYTES: usize = 16 << 20;

/// Allocation tag written ahead of every `alloc` buffer.
const ALLOC_MAGIC: u64 = u64::from_le_bytes(*b"AINFALLO");
/// Tag plus the stored length plus the stored generation, all little-endian
/// `u64` (INF-FFI-01). The generation is what makes a stale free after
/// address reuse detectable: a freed address handed out again carries a
/// newer generation, so a free naming the old generation is refused instead
/// of releasing the live buffer. The header is 24 bytes, still 8-aligned,
/// so the user pointer stays 8-aligned.
const ALLOC_HEADER: usize = 24;
/// Alignment of every `alloc` buffer. `u64` fields need no more, and a fixed
/// alignment makes the free layout explicit.
const ALLOC_ALIGN: usize = 8;

/// Every live allocation handed out by [`active_infinity_alloc`], keyed by
/// address with its generation (INF-FFI-01).
///
/// A tag cannot prove an address: a caller can plant a matching tag wherever it
/// likes. The registry is the authority, so a foreign pointer, a forged tag and
/// a double free are each a no-op instead of a free of memory this library never
/// allocated. The generation is the authority for reuse: a freed address
/// handed out again is recorded under a newer generation, so a stale free
/// naming the old generation is refused instead of releasing the live
/// buffer — the legacy `(ptr, len)` handle cannot carry a generation, which
/// is why [`active_infinity_free`] cannot close that case and the
/// generational [`active_infinity_free_gen`] exists.
static LIVE_ALLOCS: Mutex<BTreeMap<usize, u64>> = Mutex::new(BTreeMap::new());

/// One generation per allocation, minted in order (INF-FFI-01). Generation 0
/// is never handed out, so a zeroed header is never a valid generation.
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Mint the next generation, skipping 0 on wrap (a `u64` counter does not
/// wrap in practice; the skip keeps 0 reserved either way).
fn next_generation() -> u64 {
    let mut generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
    if generation == 0 {
        generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
    }
    generation
}

/// Largest number of buffers this process may hold at once.
///
/// Each live buffer costs a registry entry, so an allocation storm in one
/// tenant used to grow process-wide memory without a ceiling (cross-cutting
/// pass 3, #1). The caller sees a null return, the same refusal as an
/// over-sized request.
pub const MAX_LIVE_ALLOCATIONS: usize = 1 << 16;

fn live_allocations() -> Option<std::sync::MutexGuard<'static, BTreeMap<usize, u64>>> {
    // Fail closed: if the registry is poisoned its contents cannot be trusted,
    // and handing out or freeing an address it no longer tracks is worse than
    // refusing the call.
    LIVE_ALLOCS.lock().ok()
}

const OK: i32 = 0;
const INVALID: i32 = -1;
const BUFFER_TOO_SMALL: i32 = -2;
const PANIC: i32 = -3;

thread_local! {
    static LAST_ERROR: RefCell<CString> =
        RefCell::new(CString::new("infinity/ok").expect("static string"));
}

/// The exported symbol names, for the header/tripwire test.
pub const EXPORTS: &[&str] = &[
    "active_infinity_abi_version",
    "active_infinity_version",
    "active_infinity_ffi_version",
    "active_infinity_last_error",
    "active_infinity_alloc",
    "active_infinity_alloc_gen",
    "active_infinity_free",
    "active_infinity_free_gen",
    "active_infinity_validate",
    "active_infinity_validate_canonical",
    "active_infinity_validate_with_limits",
    "active_infinity_decode_with_limits",
    "active_infinity_limits_default",
    "active_infinity_content_hash",
    "active_infinity_reencode",
    "active_infinity_from_active",
    "active_infinity_redacted_json",
];

fn set_error(code: &str) {
    let text = CString::new(code.replace('\0', " ")).unwrap_or_else(|_| {
        CString::new("infinity/error").expect("static fallback must not contain NUL")
    });
    LAST_ERROR.with(|slot| *slot.borrow_mut() = text);
}

fn guarded(op: impl FnOnce() -> i32) -> i32 {
    match catch_unwind(AssertUnwindSafe(op)) {
        Ok(code) => code,
        Err(_) => {
            set_error("infinity/panic");
            PANIC
        }
    }
}

unsafe fn input<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    // `slice::from_raw_parts` requires a length no larger than `isize::MAX`.
    // A hostile `len` (for example `usize::MAX` from a JS host) would be
    // library UB before any ceiling comparison runs, so refuse it here.
    if len > isize::MAX as usize {
        return None;
    }
    // SAFETY: the caller guarantees `ptr` points to `len` readable bytes for the
    // duration of the call, as documented in the header.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

unsafe fn write_output(bytes: &[u8], out: *mut u8, out_len: *mut usize) -> i32 {
    if out_len.is_null() {
        set_error("infinity/null-out-len");
        return INVALID;
    }
    if (out_len as usize) % std::mem::align_of::<usize>() != 0 {
        // Dereferencing a misaligned `size_t*` is undefined behaviour, so the
        // shim refuses it before touching the pointer.
        set_error("infinity/out-len-misaligned");
        return INVALID;
    }
    // SAFETY: `out_len` is a caller-provided writable, aligned `size_t`.
    let capacity = unsafe { *out_len };
    // SAFETY: writing the required size is always allowed.
    unsafe { *out_len = bytes.len() };
    if bytes.is_empty() {
        set_error("infinity/ok");
        return OK;
    }
    if out.is_null() || capacity < bytes.len() {
        set_error("infinity/buffer-too-small");
        return BUFFER_TOO_SMALL;
    }
    // SAFETY: the caller guarantees `out` has `capacity` writable bytes.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    set_error("infinity/ok");
    OK
}

/// Copy at most `MAX_NAME_BYTES` bytes from a NUL-terminated C string.
///
/// `CStr::from_ptr` scans until a NUL with no bound; an unterminated name would
/// read past the caller's buffer. This walks at most the cap and stops at the
/// first NUL, so a hostile string is refused instead of read.
unsafe fn bounded_name<'a>(name: *const c_char) -> Option<&'a CStr> {
    let mut length = 0usize;
    // The cap counts name bytes; the terminator sits at index `MAX_NAME_BYTES`
    // for a name of exactly the limit, so the scan includes that index.
    while length <= MAX_NAME_BYTES {
        // SAFETY: the caller promises a NUL-terminated string; the cap keeps a
        // missing terminator from turning into an unbounded scan.
        if unsafe { *name.add(length) } == 0 {
            let bytes = unsafe { slice::from_raw_parts(name.cast::<u8>(), length + 1) };
            // SAFETY: the slice ends at the NUL just found.
            return Some(unsafe { CStr::from_bytes_with_nul_unchecked(bytes) });
        }
        length += 1;
    }
    None
}

/// ABI version of this library.
#[no_mangle]
pub extern "C" fn active_infinity_abi_version() -> u32 {
    ABI_VERSION
}

/// Codec version as a static NUL-terminated string.
///
/// This is the `active-infinity` version whose behaviour the shim exposes, not
/// the shim's own crate version: a consumer checking compatibility needs the
/// codec, and `active_infinity_ffi_version` reports the shim.
#[no_mangle]
pub extern "C" fn active_infinity_version() -> *const c_char {
    // A getter that panicked would unwind into C; null is the documented
    // "unavailable" answer and cannot happen for a static version string.
    catch_unwind(|| {
        static SLOT: std::sync::OnceLock<CString> = std::sync::OnceLock::new();
        version_pointer(&SLOT, active_infinity::VERSION)
    })
    .unwrap_or(ptr::null())
}

/// Shim version as a static NUL-terminated string.
#[no_mangle]
pub extern "C" fn active_infinity_ffi_version() -> *const c_char {
    catch_unwind(|| {
        static SLOT: std::sync::OnceLock<CString> = std::sync::OnceLock::new();
        version_pointer(&SLOT, env!("CARGO_PKG_VERSION"))
    })
    .unwrap_or(ptr::null())
}

fn version_pointer(slot: &'static std::sync::OnceLock<CString>, text: &str) -> *const c_char {
    slot.get_or_init(|| CString::new(text).expect("a version string has no NUL"))
        .as_ptr()
}

/// Stable error code from the last failing call on this thread.
#[no_mangle]
pub extern "C" fn active_infinity_last_error() -> *const c_char {
    catch_unwind(|| LAST_ERROR.with(|slot| slot.borrow().as_ptr())).unwrap_or(ptr::null())
}

/// Allocate `len` zeroed bytes in the module's linear memory.
///
/// WASM hosts have no other way to hand a buffer to the module. Release it with
/// [`active_infinity_free`] using the same length.
#[no_mangle]
pub extern "C" fn active_infinity_alloc(len: usize) -> *mut u8 {
    match catch_unwind(|| alloc_tagged(len)) {
        Ok((pointer, _generation)) => pointer,
        Err(_) => {
            set_error("infinity/panic");
            ptr::null_mut()
        }
    }
}

/// Allocate `len` zeroed bytes and report the allocation's generation.
///
/// The generational form of [`active_infinity_alloc`] (INF-FFI-01): the
/// generation is written to `*generation_out` and must be passed back to
/// [`active_infinity_free_gen`] with the pointer and the length. A stale
/// free — the same address freed, reused under a newer generation, then
/// freed again with the old generation — is refused instead of releasing
/// the live buffer. A null `generation_out` is refused with a null return:
/// without the generation the buffer cannot be freed generationally.
/// Like `active_infinity_alloc`, a null return means "allocation failed"
/// and `last_error` is unchanged.
///
/// # Safety
/// `generation_out` must be a writable `u64` (or null, which is refused).
#[no_mangle]
pub unsafe extern "C" fn active_infinity_alloc_gen(len: usize, generation_out: *mut u64) -> *mut u8 {
    if generation_out.is_null() {
        return ptr::null_mut();
    }
    match catch_unwind(|| alloc_tagged(len)) {
        Ok((pointer, generation)) => {
            if pointer.is_null() {
                return ptr::null_mut();
            }
            // SAFETY: `generation_out` is non-null (checked above) and the
            // caller provided a writable `u64`.
            unsafe { ptr::write(generation_out, generation) };
            pointer
        }
        Err(_) => {
            set_error("infinity/panic");
            ptr::null_mut()
        }
    }
}

fn alloc_tagged(len: usize) -> (*mut u8, u64) {
    // `alloc` and `free` never touch `last_error`: a binding may call them
    // between a failed FFI call and its read of the code, and an internal
    // allocation must not overwrite the failure it is about to report. A null
    // return means "allocation failed" (the ceiling or the allocator).
    if len > MAX_ALLOC_BYTES {
        return (ptr::null_mut(), 0);
    }
    let Some(total) = len.checked_add(ALLOC_HEADER) else {
        return (ptr::null_mut(), 0);
    };
    let Ok(layout) = Layout::from_size_align(total, ALLOC_ALIGN) else {
        return (ptr::null_mut(), 0);
    };
    // SAFETY: `total` is non-zero and the layout is valid for the allocator.
    let base = unsafe { std::alloc::alloc_zeroed(layout) };
    if base.is_null() {
        return (ptr::null_mut(), 0);
    }
    let generation = next_generation();
    // SAFETY: the allocation holds `ALLOC_HEADER` bytes at `base`.
    unsafe {
        ptr::copy_nonoverlapping(ALLOC_MAGIC.to_le_bytes().as_ptr(), base, 8);
        ptr::copy_nonoverlapping((len as u64).to_le_bytes().as_ptr(), base.add(8), 8);
        ptr::copy_nonoverlapping(generation.to_le_bytes().as_ptr(), base.add(16), 8);
    }
    // SAFETY: the allocation is at least `ALLOC_HEADER` bytes.
    let pointer = unsafe { base.add(ALLOC_HEADER) };
    let Some(mut live) = live_allocations() else {
        // SAFETY: `base` came from `alloc_zeroed` with this layout.
        unsafe { std::alloc::dealloc(base, layout) };
        return (ptr::null_mut(), 0);
    };
    if live.len() >= MAX_LIVE_ALLOCATIONS {
        // One tenant's allocation storm must not exhaust memory for every
        // caller in the process (cross-cutting pass 3, #1).
        // SAFETY: `base` came from `alloc_zeroed` with this layout.
        unsafe { std::alloc::dealloc(base, layout) };
        return (ptr::null_mut(), 0);
    }
    if live.insert(pointer as usize, generation).is_some() {
        // A fresh allocation cannot alias a live one; fail closed rather than
        // hand out two names for one buffer.
        // SAFETY: `base` came from `alloc_zeroed` with this layout.
        unsafe { std::alloc::dealloc(base, layout) };
        return (ptr::null_mut(), 0);
    }
    (pointer, generation)
}

/// Release a buffer from [`active_infinity_alloc`].
///
/// # Safety
/// `ptr` must come from `active_infinity_alloc(len)` and must not be used after.
/// The same `len` must be passed. A foreign pointer, a different length or a
/// double free is undefined behaviour in the C ABI; the tag makes a wrong
/// length a no-op (the buffer is leaked rather than corrupting the heap).
///
/// A double free is a no-op only while the address has not been reused. If an
/// allocation between the two frees returned the same address, the stale free
/// releases that newer buffer: the `(ptr, len)` handle cannot name which
/// generation it means, so no check inside this function can tell a stale
/// free from a legitimate free of the reused address (INF-FFI-01). The
/// header is validated BEFORE the address leaves the registry, so a stale
/// free with a different length no longer untracks the live buffer — but
/// the same-length reuse case is a residual risk of this legacy entry point.
/// Use [`active_infinity_alloc_gen`] / [`active_infinity_free_gen`], which
/// carry the generation and refuse a stale free outright. Always null the
/// pointer after freeing it; using a pointer after it was freed is
/// undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn active_infinity_free(ptr: *mut u8, len: usize) {
    // A panic must not unwind into C; `free` has no return code, so a caught
    // panic leaves the buffer live (a leak) rather than aborting the caller.
    let _ = catch_unwind(AssertUnwindSafe(|| free_tagged(ptr, len)));
}

fn free_tagged(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let Some(mut live) = live_allocations() else {
        // A poisoned registry cannot prove anything: leaking the buffer is the
        // safe failure (cross-cutting pass 3, #1).
        return;
    };
    if !live.contains_key(&(ptr as usize)) {
        // A foreign pointer or a double free: no-op. `free` never changes the
        // thread's code: a binding reads it after a failing call, and an
        // internal alloc/free between the failure and the read must not hide it.
        return;
    }
    // SAFETY: the registry proved this address came from `alloc_tagged`, so the
    // header behind it was written by this library.
    let base = unsafe { ptr.sub(ALLOC_HEADER) };
    let header = unsafe { slice::from_raw_parts(base, ALLOC_HEADER) };
    let magic = u64::from_le_bytes(header[..8].try_into().expect("8 bytes"));
    let stored = u64::from_le_bytes(header[8..16].try_into().expect("8 bytes"));
    if magic != ALLOC_MAGIC || stored != len as u64 {
        // A wrong length cannot be freed with the right layout. The buffer is
        // leaked, which is the safe failure — and, since the address is still
        // in the registry (INF-FFI-01: the header is checked BEFORE the
        // remove), a later legitimate free of this buffer still succeeds
        // instead of the buffer being untracked and leaked forever.
        return;
    }
    let Some(total) = len.checked_add(ALLOC_HEADER) else {
        return;
    };
    let Ok(layout) = Layout::from_size_align(total, ALLOC_ALIGN) else {
        return;
    };
    // The header proves this is the live allocation at this address, so the
    // remove and the deallocation are now safe.
    live.remove(&(ptr as usize));
    // Clear the tag so a stale copy never looks valid.
    unsafe { ptr::write_bytes(base, 0, ALLOC_HEADER) };
    // SAFETY: `base` came from `alloc_zeroed` with exactly this layout.
    unsafe { std::alloc::dealloc(base, layout) };
}

/// Release a buffer from [`active_infinity_alloc_gen`], generationally.
///
/// # Safety
/// `ptr` must come from `active_infinity_alloc_gen(len, generation_out)`
/// with the generation that call returned, and must not be used after. The
/// same `len` and the same generation must be passed. Returns 0 on success,
/// -1 when the handle is stale (the address was freed and reused under a
/// newer generation), foreign, already freed, or the wrong length. A refused
/// free never deallocates and never untracks the live buffer. Like
/// [`active_infinity_free`], this never changes `last_error`.
#[no_mangle]
pub unsafe extern "C" fn active_infinity_free_gen(
    ptr: *mut u8,
    len: usize,
    generation: u64,
) -> i32 {
    // A panic must not unwind into C; a caught panic refuses the free (a
    // leak) rather than aborting the caller.
    match catch_unwind(AssertUnwindSafe(|| free_gen_tagged(ptr, len, generation))) {
        Ok(code) => code,
        Err(_) => INVALID,
    }
}

/// Free only when the generation matches (INF-FFI-01).
///
/// Returns 0 on success, -1 when the handle is stale, foreign, already
/// freed, or the wrong length. A refusal never removes the address from
/// the registry and never deallocates, so a live buffer survives a stale
/// free.
fn free_gen_tagged(ptr: *mut u8, len: usize, generation: u64) -> i32 {
    if ptr.is_null() || generation == 0 {
        return INVALID;
    }
    let Some(mut live) = live_allocations() else {
        // A poisoned registry cannot prove anything: leaking the buffer is the
        // safe failure (cross-cutting pass 3, #1).
        return INVALID;
    };
    let Some(&recorded) = live.get(&(ptr as usize)) else {
        // A foreign pointer or a double free: refused.
        return INVALID;
    };
    if recorded != generation {
        // The address was freed and handed out again under a newer
        // generation. This is the stale free INF-FFI-01 names: refuse it
        // and leave the live buffer (and its registry entry) alone.
        return INVALID;
    }
    // SAFETY: the registry proved this address came from `alloc_tagged`, so the
    // header behind it was written by this library.
    let base = unsafe { ptr.sub(ALLOC_HEADER) };
    let header = unsafe { slice::from_raw_parts(base, ALLOC_HEADER) };
    let magic = u64::from_le_bytes(header[..8].try_into().expect("8 bytes"));
    let stored = u64::from_le_bytes(header[8..16].try_into().expect("8 bytes"));
    let stored_generation = u64::from_le_bytes(header[16..24].try_into().expect("8 bytes"));
    if magic != ALLOC_MAGIC || stored != len as u64 || stored_generation != generation {
        // A wrong length, or a header that disagrees with the registry:
        // refuse without removing, so the live buffer stays tracked.
        return INVALID;
    }
    let Some(total) = len.checked_add(ALLOC_HEADER) else {
        return INVALID;
    };
    let Ok(layout) = Layout::from_size_align(total, ALLOC_ALIGN) else {
        return INVALID;
    };
    live.remove(&(ptr as usize));
    // Clear the tag so a stale copy never looks valid.
    unsafe { ptr::write_bytes(base, 0, ALLOC_HEADER) };
    // SAFETY: `base` came from `alloc_zeroed` with exactly this layout.
    unsafe { std::alloc::dealloc(base, layout) };
    OK
}

/// Validate an AINF image. Returns 0 only for a structurally valid image
/// that is exactly the canonical encoding of its own content (INF-02):
/// the stored hash is verified and the canonical form is re-proved, so a
/// structurally valid but non-canonical image — slack, or a missing
/// canonical flag — is refused with `infinity/not-canonical`.
/// `active_infinity_validate_canonical` states the same requirement
/// explicitly; `active_infinity_reencode` is the repair path for an image
/// this function refuses.
///
/// # Safety
/// `ptr` must point to `len` readable bytes (or be null when `len` is 0).
#[no_mangle]
pub unsafe extern "C" fn active_infinity_validate(ptr: *const u8, len: usize) -> i32 {
    guarded(|| {
        // SAFETY: forwarded caller contract.
        let Some(bytes) = (unsafe { input(ptr, len) }) else {
            set_error("infinity/null-input");
            return INVALID;
        };
        match validate(bytes) {
            Ok(_) => {
                set_error("infinity/ok");
                OK
            }
            Err(error) => {
                set_error(error.code());
                INVALID
            }
        }
    })
}

/// Prove that an image is the canonical encoding of its own content.
///
/// `active_infinity_validate` already checks structure, the stored hash,
/// and the canonical form; this states the canonical requirement explicitly
/// (and, in the library, takes the limits as a parameter) and re-encodes,
/// refusing a structurally valid image that is not canonical. Dedup and
/// signature checks need this answer.
///
/// # Safety
/// `ptr` must point to `len` readable bytes (or be null when `len` is 0).
#[no_mangle]
pub unsafe extern "C" fn active_infinity_validate_canonical(ptr: *const u8, len: usize) -> i32 {
    guarded(|| {
        // SAFETY: forwarded caller contract.
        let Some(bytes) = (unsafe { input(ptr, len) }) else {
            set_error("infinity/null-input");
            return INVALID;
        };
        match validate_canonical(bytes, active_infinity::Limits::default()) {
            Ok(_) => {
                set_error("infinity/ok");
                OK
            }
            Err(error) => {
                set_error(error.code());
                INVALID
            }
        }
    })
}

/// The caller-visible form of [`Limits`] (INF-FFI-02).
///
/// One field per ceiling, in the same order as the Rust `Limits` struct, so a
/// binding can build it by name and the conversion is a field-by-field copy —
/// never a transmute, because the Rust struct is not `#[repr(C)]`. All
/// ceilings are `u32` except `max_total_bytes` and `max_decoded_bytes`
/// (`u64`). A ceiling of zero is refused (`infinity/invalid-argument`): the
/// Rust `Limits::check` rejects a zero ceiling before any decoding happens.
/// Pass a null pointer to the `*_with_limits` functions for
/// `Limits::default()`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ActiveInfinityLimits {
    pub max_nodes: u32,
    pub max_edges: u32,
    pub max_children: u32,
    pub max_fields: u32,
    pub max_parts: u32,
    pub max_strings: u32,
    pub max_string_bytes: u32,
    pub max_blobs: u32,
    pub max_blob_bytes: u32,
    pub max_annotations: u32,
    pub max_units: u32,
    pub max_types: u32,
    pub max_aux: u32,
    pub max_numbers: u32,
    pub max_secrets: u32,
    pub max_secret_bytes: u32,
    pub max_extensions: u32,
    pub max_prov_bytes: u32,
    pub max_prov_entries: u32,
    pub max_hashes: u32,
    pub max_bindings: u32,
    pub max_total_bytes: u64,
    pub max_decoded_bytes: u64,
    pub max_depth: u32,
}

fn limits_from_ffi(limits: &ActiveInfinityLimits) -> Limits {
    Limits {
        max_nodes: limits.max_nodes,
        max_edges: limits.max_edges,
        max_children: limits.max_children,
        max_fields: limits.max_fields,
        max_parts: limits.max_parts,
        max_strings: limits.max_strings,
        max_string_bytes: limits.max_string_bytes,
        max_blobs: limits.max_blobs,
        max_blob_bytes: limits.max_blob_bytes,
        max_annotations: limits.max_annotations,
        max_units: limits.max_units,
        max_types: limits.max_types,
        max_aux: limits.max_aux,
        max_numbers: limits.max_numbers,
        max_secrets: limits.max_secrets,
        max_secret_bytes: limits.max_secret_bytes,
        max_extensions: limits.max_extensions,
        max_prov_bytes: limits.max_prov_bytes,
        max_prov_entries: limits.max_prov_entries,
        max_hashes: limits.max_hashes,
        max_bindings: limits.max_bindings,
        max_total_bytes: limits.max_total_bytes,
        max_decoded_bytes: limits.max_decoded_bytes,
        max_depth: limits.max_depth,
    }
}

fn limits_to_ffi(limits: &Limits) -> ActiveInfinityLimits {
    ActiveInfinityLimits {
        max_nodes: limits.max_nodes,
        max_edges: limits.max_edges,
        max_children: limits.max_children,
        max_fields: limits.max_fields,
        max_parts: limits.max_parts,
        max_strings: limits.max_strings,
        max_string_bytes: limits.max_string_bytes,
        max_blobs: limits.max_blobs,
        max_blob_bytes: limits.max_blob_bytes,
        max_annotations: limits.max_annotations,
        max_units: limits.max_units,
        max_types: limits.max_types,
        max_aux: limits.max_aux,
        max_numbers: limits.max_numbers,
        max_secrets: limits.max_secrets,
        max_secret_bytes: limits.max_secret_bytes,
        max_extensions: limits.max_extensions,
        max_prov_bytes: limits.max_prov_bytes,
        max_prov_entries: limits.max_prov_entries,
        max_hashes: limits.max_hashes,
        max_bindings: limits.max_bindings,
        max_total_bytes: limits.max_total_bytes,
        max_decoded_bytes: limits.max_decoded_bytes,
        max_depth: limits.max_depth,
    }
}

/// Read a caller-supplied limits pointer, or `Limits::default()` for null.
///
/// # Safety
/// `limits` is null or points to a valid `ActiveInfinityLimits`.
unsafe fn limits_or_default(limits: *const ActiveInfinityLimits) -> Limits {
    if limits.is_null() {
        Limits::default()
    } else {
        // SAFETY: the caller guarantees a valid struct for the call.
        limits_from_ffi(unsafe { &*limits })
    }
}

/// Fill `limits` with the library defaults (INF-FFI-02).
///
/// A binding builds a narrowed budget by calling this, then overriding the
/// one ceiling it wants to tighten — it never has to hardcode the 24
/// defaults, so a future default change cannot silently desync the binding.
/// A null pointer is refused with `infinity/null-output`.
///
/// # Safety
/// `limits` must point to a writable `ActiveInfinityLimits`.
#[no_mangle]
pub unsafe extern "C" fn active_infinity_limits_default(limits: *mut ActiveInfinityLimits) -> i32 {
    guarded(|| {
        if limits.is_null() {
            set_error("infinity/null-output");
            return INVALID;
        }
        // SAFETY: the caller guarantees a writable struct.
        unsafe {
            *limits = limits_to_ffi(&Limits::default());
        }
        set_error("infinity/ok");
        OK
    })
}

/// Validate an image under caller-supplied limits (INF-FFI-02).
///
/// The limits-parameterized form of `active_infinity_validate_canonical`:
/// the stored hash is verified and the canonical form is re-proved, under
/// the caller's budget instead of `Limits::default()`. A null `limits`
/// pointer means the defaults. This is what makes the manifest's limit
/// vectors reproducible through a binding: `limit` is refused with
/// `infinity/limit` under `max_nodes: 1` and `too_deep` with
/// `infinity/depth` under `max_depth: 8` — both are accepted under the
/// defaults, because the budget is what makes them hostile.
///
/// # Safety
/// `ptr` must point to `len` readable bytes (or be null when `len` is 0);
/// `limits` is null or points to a valid `ActiveInfinityLimits`.
#[no_mangle]
pub unsafe extern "C" fn active_infinity_validate_with_limits(
    ptr: *const u8,
    len: usize,
    limits: *const ActiveInfinityLimits,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded caller contract.
        let Some(bytes) = (unsafe { input(ptr, len) }) else {
            set_error("infinity/null-input");
            return INVALID;
        };
        // SAFETY: forwarded caller contract.
        let limits = unsafe { limits_or_default(limits) };
        match validate_canonical(bytes, limits) {
            Ok(_) => {
                set_error("infinity/ok");
                OK
            }
            Err(error) => {
                set_error(error.code());
                INVALID
            }
        }
    })
}

/// Validate, decode and re-encode under caller-supplied limits (INF-FFI-02).
///
/// The limits-parameterized form of `active_infinity_reencode`: the input
/// is decoded leniently (the stored hash is still verified, only the
/// canonical-form proof is skipped) under the caller's budget, re-encoded,
/// and the OUTPUT is strict-validated under the same budget before it is
/// returned, so the output is always canonical. A null `limits` pointer
/// means the defaults. An image that exceeds the budget is refused with the
/// same code the reference reports (`infinity/limit`, `infinity/depth`,
/// ...). The canonical output is never larger than the input it repairs
/// (slack only adds bytes), so an input that fits the budget always yields
/// an output that fits it too.
///
/// # Safety
/// `ptr`/`len` describe a readable image; `limits` is null or points to a
/// valid `ActiveInfinityLimits`; `out`/`out_len` follow the calling
/// convention in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn active_infinity_decode_with_limits(
    ptr: *const u8,
    len: usize,
    limits: *const ActiveInfinityLimits,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded caller contract.
        let Some(bytes) = (unsafe { input(ptr, len) }) else {
            set_error("infinity/null-input");
            return INVALID;
        };
        // SAFETY: forwarded caller contract.
        let limits = unsafe { limits_or_default(limits) };
        let lenient = DecodeOpts {
            limits,
            verify_canonical: false,
            ..DecodeOpts::default()
        };
        match decode_with(bytes, lenient)
            .and_then(|module| encode(&module))
            .and_then(|canonical| validate_canonical(&canonical, limits).map(|_| canonical))
        {
            // SAFETY: forwarded caller contract for `out`/`out_len`.
            Ok(canonical) => unsafe { write_output(&canonical, out, out_len) },
            Err(error) => {
                set_error(error.code());
                INVALID
            }
        }
    })
}

/// Compute the Blake3 content hash of a canonical image into `out32`.
///
/// The hash is computed only for an image that passes the same proof as
/// `active_infinity_validate`: a structurally valid but non-canonical image
/// is refused with `infinity/not-canonical` instead of being hashed, because
/// the hash is the identity of the canonical form. Repair first with
/// `active_infinity_reencode`, then hash the repaired bytes.
///
/// # Safety
/// `ptr`/`len` describe a readable image; `out32` must point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn active_infinity_content_hash(
    ptr: *const u8,
    len: usize,
    out32: *mut u8,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded caller contract.
        let Some(bytes) = (unsafe { input(ptr, len) }) else {
            set_error("infinity/null-input");
            return INVALID;
        };
        if out32.is_null() {
            set_error("infinity/null-output");
            return INVALID;
        }
        match content_hash(bytes) {
            Ok(hash) => {
                // SAFETY: the caller guarantees 32 writable bytes.
                unsafe { std::ptr::copy_nonoverlapping(hash.as_ptr(), out32, 32) };
                set_error("infinity/ok");
                OK
            }
            Err(error) => {
                set_error(error.code());
                INVALID
            }
        }
    })
}

/// Validate, decode and re-encode an image into canonical bytes.
///
/// This is the encode path for a binding that receives AINF from another
/// producer, and the repair path for an image `active_infinity_validate`
/// refuses: the input need not already be canonical. It is decoded
/// leniently — the stored hash is still verified, only the canonical-form
/// proof is skipped (`DecodeOpts { verify_canonical: false, .. }`, the
/// deliberate opt-out the library documents for migration paths) —
/// re-encoded, and the OUTPUT is strict-validated before it is returned,
/// so the output is always canonical and byte-identical to what the
/// reference encoder emits for that content. A non-canonical input
/// therefore succeeds and the output differs from the input; that is the
/// repair, not a failure. This mirrors the schema `from_bytes` pattern
/// (lenient-decode, re-encode, strict-decode). (NF-INF02-01: the previous
/// implementation decoded strictly, so it could only ever echo
/// already-canonical bytes and the repair path was vacuous.)
///
/// # Safety
/// `ptr`/`len` describe a readable image; `out`/`out_len` follow the calling
/// convention in the crate docs.
#[no_mangle]
pub unsafe extern "C" fn active_infinity_reencode(
    ptr: *const u8,
    len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded caller contract.
        let Some(bytes) = (unsafe { input(ptr, len) }) else {
            set_error("infinity/null-input");
            return INVALID;
        };
        let lenient = DecodeOpts {
            verify_canonical: false,
            ..DecodeOpts::default()
        };
        match decode_with(bytes, lenient)
            .and_then(|module| encode(&module))
            .and_then(|canonical| validate(&canonical).map(|_| canonical))
        {
            // SAFETY: forwarded caller contract for `out`/`out_len`.
            Ok(canonical) => unsafe { write_output(&canonical, out, out_len) },
            Err(error) => {
                set_error(error.code());
                INVALID
            }
        }
    })
}

/// Compile Active text into a canonical AINF image.
///
/// `name` is the module name (a NUL-terminated UTF-8 string); it is used for
/// diagnostics and provenance, never for the hash.
///
/// # Safety
/// `source`/`source_len` describe UTF-8 bytes; `name` is NUL-terminated;
/// `out`/`out_len` follow the calling convention.
#[no_mangle]
pub unsafe extern "C" fn active_infinity_from_active(
    source: *const u8,
    source_len: usize,
    name: *const c_char,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    guarded(|| {
        // Check the declared length before building a slice from it: the cap is
        // what keeps a hostile length from reaching `from_raw_parts`.
        if source_len > MAX_SOURCE_BYTES {
            set_error("infinity/limit");
            return INVALID;
        }
        // SAFETY: forwarded caller contract.
        let Some(bytes) = (unsafe { input(source, source_len) }) else {
            set_error("infinity/null-input");
            return INVALID;
        };
        let Ok(text) = std::str::from_utf8(bytes) else {
            set_error("infinity/utf8");
            return INVALID;
        };
        if name.is_null() {
            set_error("infinity/null-name");
            return INVALID;
        }
        // SAFETY: the caller guarantees a NUL-terminated string; the helper
        // bounds the scan.
        let Some(name) = (unsafe { bounded_name(name) }) else {
            set_error("infinity/name-too-long");
            return INVALID;
        };
        let Ok(name) = name.to_str() else {
            set_error("infinity/utf8");
            return INVALID;
        };
        match active_infinity::interop::from_active_source(text, name)
            .and_then(|module| encode(&module))
        {
            // SAFETY: forwarded caller contract.
            Ok(image) => unsafe { write_output(&image, out, out_len) },
            Err(error) => {
                set_error(error.code());
                INVALID
            }
        }
    })
}

/// Render the redacted JSON projection of an image.
///
/// Secret values become the redaction marker; this is the only JSON the library
/// produces from a module with secrets. Bindings use it for redaction parity.
/// The input must be canonical (INF-02): a non-canonical image is refused
/// with `infinity/not-canonical`, the same as `active_infinity_validate`.
/// Repair it first with `active_infinity_reencode`, then read the repaired
/// bytes.
///
/// # Safety
/// `ptr`/`len` describe a readable image; `out`/`out_len` follow the calling
/// convention.
#[no_mangle]
pub unsafe extern "C" fn active_infinity_redacted_json(
    ptr: *const u8,
    len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded caller contract.
        let Some(bytes) = (unsafe { input(ptr, len) }) else {
            set_error("infinity/null-input");
            return INVALID;
        };
        match decode(bytes).and_then(|module| active_infinity::interop::to_redacted_json(&module)) {
            // SAFETY: forwarded caller contract.
            Ok(json) => unsafe { write_output(json.as_bytes(), out, out_len) },
            Err(error) => {
                set_error(error.code());
                INVALID
            }
        }
    })
}

/// Host-provided randomness for the WASM build.
///
/// The codec itself is deterministic; `active-core` reaches `getrandom` when it
/// materializes a secret. Keeping wasm-bindgen glue out of the module means a
/// host supplies exactly one import:
///
/// ```text
/// (import "env" "active_random_fill" (func $fill (param i32 i32) (result i32)))
/// ```
///
/// The host fills `len` bytes at `dest` and returns 0, or a non-zero error.
#[cfg(target_arch = "wasm32")]
mod wasm_random {
    use core::num::NonZeroU32;

    #[link(wasm_import_module = "env")]
    extern "C" {
        fn active_random_fill(dest: *mut u8, len: usize) -> u32;
    }

    fn fill(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
        if buffer.is_empty() {
            // A zero-length fill needs no host call and must not pass a
            // dangling pointer across the boundary.
            return Ok(());
        }
        // SAFETY: the host contract is to write `len` bytes at `dest`.
        let code = unsafe { active_random_fill(buffer.as_mut_ptr(), buffer.len()) };
        if code == 0 {
            return Ok(());
        }
        let custom = getrandom::Error::CUSTOM_START.saturating_add(code.max(1));
        match NonZeroU32::new(custom) {
            Some(code) => Err(getrandom::Error::from(code)),
            None => Err(getrandom::Error::from(
                NonZeroU32::new(getrandom::Error::CUSTOM_START + 1).expect("non-zero"),
            )),
        }
    }

    getrandom::register_custom_getrandom!(fill);
}
