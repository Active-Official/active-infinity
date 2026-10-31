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

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use active_infinity::{content_hash, decode, encode, validate, validate_canonical};

/// ABI version. Bumped only for an incompatible layout or calling change.
pub const ABI_VERSION: u32 = 1;

/// Largest single `alloc` request. A host that asks for more is refused with a
/// null pointer and `infinity/limit` rather than aborting on an impossible
/// allocation.
pub const MAX_ALLOC_BYTES: usize = 1 << 30;

/// Largest module name accepted, in bytes (excluding the NUL).
pub const MAX_NAME_BYTES: usize = 4 << 10;

/// Largest Active source accepted by `from_active`, in bytes.
pub const MAX_SOURCE_BYTES: usize = 16 << 20;

/// Allocation tag written ahead of every `alloc` buffer.
const ALLOC_MAGIC: u64 = u64::from_le_bytes(*b"AINFALLO");
/// Tag plus the stored length, both little-endian `u64`.
const ALLOC_HEADER: usize = 16;

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
    "active_infinity_free",
    "active_infinity_validate",
    "active_infinity_validate_canonical",
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
    while length < MAX_NAME_BYTES {
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
    static SLOT: std::sync::OnceLock<CString> = std::sync::OnceLock::new();
    version_pointer(&SLOT, active_infinity::VERSION)
}

/// Shim version as a static NUL-terminated string.
#[no_mangle]
pub extern "C" fn active_infinity_ffi_version() -> *const c_char {
    static SLOT: std::sync::OnceLock<CString> = std::sync::OnceLock::new();
    version_pointer(&SLOT, env!("CARGO_PKG_VERSION"))
}

fn version_pointer(slot: &'static std::sync::OnceLock<CString>, text: &str) -> *const c_char {
    slot.get_or_init(|| CString::new(text).expect("a version string has no NUL"))
        .as_ptr()
}

/// Stable error code from the last failing call on this thread.
#[no_mangle]
pub extern "C" fn active_infinity_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| slot.borrow().as_ptr())
}

/// Allocate `len` zeroed bytes in the module's linear memory.
///
/// WASM hosts have no other way to hand a buffer to the module. Release it with
/// [`active_infinity_free`] using the same length.
#[no_mangle]
pub extern "C" fn active_infinity_alloc(len: usize) -> *mut u8 {
    match catch_unwind(|| alloc_tagged(len)) {
        Ok(pointer) => pointer,
        Err(_) => {
            set_error("infinity/panic");
            ptr::null_mut()
        }
    }
}

fn alloc_tagged(len: usize) -> *mut u8 {
    if len > MAX_ALLOC_BYTES {
        set_error("infinity/limit");
        return ptr::null_mut();
    }
    let Some(total) = len.checked_add(ALLOC_HEADER) else {
        set_error("infinity/limit");
        return ptr::null_mut();
    };
    let mut buffer: Vec<u8> = Vec::new();
    if buffer.try_reserve_exact(total).is_err() {
        set_error("infinity/limit");
        return ptr::null_mut();
    }
    buffer.resize(total, 0);
    buffer[..8].copy_from_slice(&ALLOC_MAGIC.to_le_bytes());
    buffer[8..16].copy_from_slice(&(len as u64).to_le_bytes());
    let pointer = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    // SAFETY: the allocation has at least `ALLOC_HEADER` bytes.
    unsafe { pointer.add(ALLOC_HEADER) }
}

/// Release a buffer from [`active_infinity_alloc`].
///
/// # Safety
/// `ptr` must come from `active_infinity_alloc(len)` and must not be used after.
/// The same `len` must be passed. A foreign pointer, a different length or a
/// double free is undefined behaviour in the C ABI; the tag makes a wrong
/// length a no-op (the buffer is leaked rather than corrupting the heap) but
/// cannot make a double free safe.
#[no_mangle]
pub unsafe extern "C" fn active_infinity_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: the caller contract says `ptr - ALLOC_HEADER` is the start of an
    // allocation made by `alloc_tagged`.
    let base = unsafe { ptr.sub(ALLOC_HEADER) };
    let header = unsafe { slice::from_raw_parts(base, ALLOC_HEADER) };
    let magic = u64::from_le_bytes(header[..8].try_into().expect("8 bytes"));
    let stored = u64::from_le_bytes(header[8..16].try_into().expect("8 bytes"));
    if magic != ALLOC_MAGIC || stored != len as u64 {
        // Not the pairing the contract requires. Freeing would corrupt the
        // heap; refusing to free leaks one buffer, which is the safe failure.
        return;
    }
    // Clear the tag so a later `free` of the same pointer fails the check
    // instead of reconstructing the Vec a second time.
    unsafe { ptr::write_bytes(base, 0, ALLOC_HEADER) };
    let total = len + ALLOC_HEADER;
    // SAFETY: the header proves this is the allocation `alloc_tagged` made.
    drop(unsafe { Vec::from_raw_parts(base, total, total) });
}

/// Validate an AINF image. Returns 0 for a structurally valid image.
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
/// `active_infinity_validate` checks structure and the stored hash; this also
/// re-encodes and refuses a structurally valid image that is not canonical.
/// Dedup and signature checks need this answer.
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

/// Compute the Blake3 content hash of a valid image into `out32`.
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
/// producer: the output is byte-identical to what the reference encoder emits.
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
        match decode(bytes).and_then(|module| encode(&module)) {
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
        // SAFETY: forwarded caller contract.
        let Some(bytes) = (unsafe { input(source, source_len) }) else {
            set_error("infinity/null-input");
            return INVALID;
        };
        if bytes.len() > MAX_SOURCE_BYTES {
            set_error("infinity/limit");
            return INVALID;
        }
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
