//! ABI tests: the C surface must reproduce the reference bytes and codes.

use std::ffi::CString;

use active_infinity_ffi::{
    active_infinity_abi_version, active_infinity_content_hash, active_infinity_from_active,
    active_infinity_last_error, active_infinity_redacted_json, active_infinity_reencode,
    active_infinity_validate, active_infinity_validate_canonical, EXPORTS, MAX_ALLOC_BYTES,
    MAX_NAME_BYTES, MAX_SOURCE_BYTES,
};

fn vector(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors/valid")
        .join(name);
    std::fs::read(path).expect("vector")
}

fn last_error() -> String {
    // SAFETY: the pointer is a valid NUL-terminated string for this thread.
    unsafe { std::ffi::CStr::from_ptr(active_infinity_last_error()) }
        .to_string_lossy()
        .into_owned()
}

#[test]
fn abi_version_is_stable() {
    assert_eq!(active_infinity_abi_version(), 1);
}

#[test]
fn the_header_declares_every_export() {
    let header = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("include/active_infinity.h"),
    )
    .expect("header");
    for symbol in EXPORTS {
        assert!(header.contains(symbol), "header must declare {symbol}");
    }
    assert!(header.contains("ACTIVE_INFINITY_ABI_VERSION 1u"));
}

#[test]
fn validate_hash_and_reencode_match_the_reference() {
    for name in ["empty.ainf", "full.ainf", "extensions.ainf"] {
        let bytes = vector(name);
        // SAFETY: the vectors are readable buffers.
        let status = unsafe { active_infinity_validate(bytes.as_ptr(), bytes.len()) };
        assert_eq!(status, 0, "{name}: {}", last_error());

        let mut hash = [0u8; 32];
        // SAFETY: hash is 32 writable bytes.
        let status =
            unsafe { active_infinity_content_hash(bytes.as_ptr(), bytes.len(), hash.as_mut_ptr()) };
        assert_eq!(status, 0, "{name}: {}", last_error());
        assert_eq!(
            hash,
            active_infinity::content_hash(&bytes).expect("reference hash")
        );

        let mut out = vec![0u8; bytes.len()];
        let mut out_len = out.len();
        // SAFETY: out/out_len follow the calling convention.
        let status = unsafe {
            active_infinity_reencode(bytes.as_ptr(), bytes.len(), out.as_mut_ptr(), &mut out_len)
        };
        assert_eq!(status, 0, "{name}: {}", last_error());
        out.truncate(out_len);
        assert_eq!(out, bytes, "{name}: canonical bytes are unchanged");
    }
}

#[test]
fn a_small_buffer_reports_the_required_size() {
    let bytes = vector("full.ainf");
    let mut out_len = 0usize;
    // SAFETY: a null output with a zero capacity is the documented size query.
    let status = unsafe {
        active_infinity_reencode(
            bytes.as_ptr(),
            bytes.len(),
            std::ptr::null_mut(),
            &mut out_len,
        )
    };
    assert_eq!(status, -2);
    assert_eq!(out_len, bytes.len());
    assert_eq!(last_error(), "infinity/buffer-too-small");
}

#[test]
fn malformed_input_is_refused_with_a_stable_code() {
    let junk = [0xffu8; 64];
    // SAFETY: junk is readable.
    let status = unsafe { active_infinity_validate(junk.as_ptr(), junk.len()) };
    assert_eq!(status, -1);
    let code = last_error();
    assert!(code.starts_with("infinity/"), "{code}");
}

#[test]
fn null_input_is_refused_without_dereferencing() {
    // SAFETY: a null pointer with a zero length is explicitly allowed.
    let status = unsafe { active_infinity_validate(std::ptr::null(), 0) };
    assert_eq!(status, -1);

    // SAFETY: a null pointer with a non-zero length must be refused, not read.
    let status = unsafe { active_infinity_validate(std::ptr::null(), 16) };
    assert_eq!(status, -1);
    assert_eq!(last_error(), "infinity/null-input");
}

#[test]
fn alloc_free_cycles_do_not_corrupt_a_hash() {
    use active_infinity_ffi::{active_infinity_alloc, active_infinity_free};

    let bytes = vector("empty.ainf");
    let expected = active_infinity::content_hash(&bytes).expect("reference hash");
    for _ in 0..8 {
        // A small scratch allocation and a body-sized one, freed each round.
        let scratch = active_infinity_alloc(4);
        // SAFETY: the allocation is 4 bytes.
        unsafe { std::ptr::write_bytes(scratch, 0xAA, 4) };
        // SAFETY: same allocation and length.
        unsafe { active_infinity_free(scratch, 4) };

        let input = active_infinity_alloc(bytes.len());
        // SAFETY: the allocation is bytes.len() bytes.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), input, bytes.len()) };
        // SAFETY: same allocation and length.
        unsafe { active_infinity_free(input, bytes.len()) };

        let input = active_infinity_alloc(bytes.len());
        // SAFETY: the allocation is bytes.len() bytes.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), input, bytes.len()) };
        let out = active_infinity_alloc(32);
        // SAFETY: buffers follow the contract.
        let status = unsafe { active_infinity_content_hash(input, bytes.len(), out) };
        assert_eq!(status, 0, "{}", last_error());
        let mut hash = [0u8; 32];
        // SAFETY: both buffers are live and correctly sized.
        unsafe { std::ptr::copy_nonoverlapping(out, hash.as_mut_ptr(), 32) };
        // SAFETY: same allocations and lengths.
        unsafe {
            active_infinity_free(out, 32);
            active_infinity_free(input, bytes.len());
        }
        assert_eq!(hash, expected, "allocator reuse corrupted the hash");
    }
}

#[test]
fn active_source_compiles_to_a_valid_image() {
    let source = b"port = 8080\nname = \"abi\"\n";
    let name = CString::new("abi.active").expect("name");
    let mut out = vec![0u8; 64 * 1024];
    let mut out_len = out.len();
    // SAFETY: buffers and the NUL-terminated name follow the contract.
    let status = unsafe {
        active_infinity_from_active(
            source.as_ptr(),
            source.len(),
            name.as_ptr(),
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    assert_eq!(status, 0, "{}", last_error());
    out.truncate(out_len);
    assert!(active_infinity::validate(&out).is_ok());
    assert_eq!(
        active_infinity::content_hash(&out).expect("hash"),
        active_infinity::content_hash(
            &active_infinity::encode(&active_infinity::decode(&out).expect("decode"))
                .expect("reencode")
        )
        .expect("hash2")
    );
}

#[test]
fn redacted_json_never_contains_a_secret_canary() {
    let bytes = vector("full.ainf");
    let mut out = vec![0u8; 1 << 20];
    let mut out_len = out.len();
    // SAFETY: buffers follow the contract.
    let status = unsafe {
        active_infinity_redacted_json(bytes.as_ptr(), bytes.len(), out.as_mut_ptr(), &mut out_len)
    };
    assert_eq!(status, 0, "{}", last_error());
    let json = String::from_utf8(out[..out_len].to_vec()).expect("utf8");
    // The literal that `full.ainf` carries must not survive a projection, and
    // the marker stands in its place.
    assert!(!json.contains("vector-secret"), "{json}");
    assert!(json.contains("***SECRET***"), "{json}");
}

#[test]
fn the_header_and_the_export_list_agree_in_both_directions() {
    let header = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("include/active_infinity.h"),
    )
    .expect("header");
    let mut declared: Vec<String> = Vec::new();
    for line in header.lines() {
        if !line.contains('(') {
            continue;
        }
        for symbol in EXPORTS {
            if line.contains(symbol) {
                declared.push((*symbol).to_string());
            }
        }
    }
    declared.sort();
    declared.dedup();
    let mut expected: Vec<String> = EXPORTS.iter().map(|name| (*name).to_string()).collect();
    expected.sort();
    assert_eq!(
        declared, expected,
        "the header and EXPORTS must be identical"
    );
}

#[test]
fn version_reports_the_codec_and_the_shim() {
    let codec = unsafe { std::ffi::CStr::from_ptr(active_infinity_ffi::active_infinity_version()) };
    assert_eq!(codec.to_str().expect("utf8"), active_infinity::VERSION);
    let shim =
        unsafe { std::ffi::CStr::from_ptr(active_infinity_ffi::active_infinity_ffi_version()) };
    assert_eq!(shim.to_str().expect("utf8"), env!("CARGO_PKG_VERSION"));
}

#[test]
fn alloc_refuses_an_impossible_request() {
    use active_infinity_ffi::active_infinity_alloc;

    // A failed allocation returns null and leaves the thread's code alone: a
    // binding may allocate between a failed call and its read of the code.
    // SAFETY: the pointer is a 4-byte readable literal.
    assert_eq!(unsafe { active_infinity_validate(b"junk".as_ptr(), 4) }, -1);
    let before = last_error();
    let pointer = active_infinity_alloc(MAX_ALLOC_BYTES + 1);
    assert!(pointer.is_null(), "an oversized allocation returns null");
    assert_eq!(last_error(), before, "alloc must not change last_error");
}

#[test]
fn free_checks_the_length_it_is_given() {
    use active_infinity_ffi::{active_infinity_alloc, active_infinity_free};

    let pointer = active_infinity_alloc(16);
    assert!(!pointer.is_null());
    // SAFETY: the allocation is 16 bytes; the wrong length must be a no-op.
    unsafe { active_infinity_free(pointer, 17) };
    // SAFETY: same pointer and the length it was allocated with.
    unsafe { active_infinity_free(pointer, 16) };
}

#[test]
fn a_misaligned_out_len_is_refused() {
    let bytes = vector("empty.ainf");
    let mut raw = [0u8; 2 * std::mem::size_of::<usize>()];
    // SAFETY: the offset keeps the pointer inside `raw`; the shim must refuse it
    // before reading or writing through it.
    let misaligned = unsafe { raw.as_mut_ptr().add(1) as *mut usize };
    let status = unsafe {
        active_infinity_reencode(
            bytes.as_ptr(),
            bytes.len(),
            std::ptr::null_mut(),
            misaligned,
        )
    };
    assert_eq!(status, -1);
    assert_eq!(last_error(), "infinity/out-len-misaligned");
}

#[test]
fn success_reports_ok_after_a_failure() {
    let junk = [0xffu8; 8];
    // SAFETY: junk is readable.
    let status = unsafe { active_infinity_validate(junk.as_ptr(), junk.len()) };
    assert_eq!(status, -1);
    assert_ne!(last_error(), "infinity/ok");

    // The output path is the one that used to keep the stale failure.
    let good = vector("empty.ainf");
    let mut out = vec![0u8; good.len()];
    let mut out_len = out.len();
    // SAFETY: buffers follow the calling convention.
    let status = unsafe {
        active_infinity_reencode(good.as_ptr(), good.len(), out.as_mut_ptr(), &mut out_len)
    };
    assert_eq!(status, 0, "{}", last_error());
    assert_eq!(last_error(), "infinity/ok");
}

#[test]
fn validate_canonical_is_stricter_than_validate() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors/invalid/not_canonical.ainf");
    let bytes = std::fs::read(path).expect("vector");
    // SAFETY: the vector is readable.
    let structural = unsafe { active_infinity_validate(bytes.as_ptr(), bytes.len()) };
    assert_eq!(structural, 0, "{}", last_error());
    // SAFETY: the vector is readable.
    let canonical = unsafe { active_infinity_validate_canonical(bytes.as_ptr(), bytes.len()) };
    assert_eq!(canonical, -1);
    assert_eq!(last_error(), "infinity/not-canonical");
}

#[test]
fn an_unterminated_name_is_refused_without_an_unbounded_scan() {
    let source = b"port = 1\n";
    let name = vec![b'a'; MAX_NAME_BYTES + 1];
    let mut out = vec![0u8; 4096];
    let mut out_len = out.len();
    // SAFETY: both buffers are live for the call.
    let status = unsafe {
        active_infinity_from_active(
            source.as_ptr(),
            source.len(),
            name.as_ptr().cast(),
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    assert_eq!(status, -1);
    assert_eq!(last_error(), "infinity/name-too-long");
}

#[test]
fn an_oversized_source_is_refused_before_parsing() {
    let source = vec![b' '; MAX_SOURCE_BYTES + 1];
    let name = CString::new("big.active").expect("name");
    let mut out = vec![0u8; 64];
    let mut out_len = out.len();
    // SAFETY: the source buffer is live and exactly as long as `source_len`.
    let status = unsafe {
        active_infinity_from_active(
            source.as_ptr(),
            source.len(),
            name.as_ptr(),
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    assert_eq!(status, -1);
    assert_eq!(last_error(), "infinity/limit");
}

/// A caller can plant the tag at an address it chooses. The registry, not the
/// tag, decides what may be freed, so a foreign pointer is a no-op.
#[test]
fn a_foreign_pointer_with_a_planted_tag_is_not_freed() {
    use active_infinity_ffi::active_infinity_free;

    let mut buffer = vec![0u8; 64];
    buffer[..8].copy_from_slice(b"AINFALLO");
    buffer[8..16].copy_from_slice(&16u64.to_le_bytes());
    let planted = unsafe { buffer.as_mut_ptr().add(16) };
    // SAFETY: the pointer is inside `buffer`; the shim must not free it.
    unsafe { active_infinity_free(planted, 16) };
    // The buffer is still ours and unchanged where the tag was written.
    assert_eq!(&buffer[..8], b"AINFALLO");
    assert_eq!(buffer[16], 0);
}

/// A zero-length allocation still owns a header; freeing it with the same
/// length must release it instead of returning early.
#[test]
fn a_zero_length_allocation_round_trips() {
    use active_infinity_ffi::{active_infinity_alloc, active_infinity_free};

    let pointer = active_infinity_alloc(0);
    assert!(!pointer.is_null());
    // SAFETY: the pointer and its length come from the allocation above.
    unsafe { active_infinity_free(pointer, 0) };
}

/// The registry removes the address on the first free, so the second call is a
/// no-op rather than a double free.
#[test]
fn a_double_free_is_a_no_op() {
    use active_infinity_ffi::{active_infinity_alloc, active_infinity_free};

    let pointer = active_infinity_alloc(32);
    assert!(!pointer.is_null());
    // SAFETY: the first call frees the allocation; the second must be ignored.
    unsafe {
        active_infinity_free(pointer, 32);
        active_infinity_free(pointer, 32);
    }
}

/// A name of exactly the limit is inside the contract; one byte more is not.
#[test]
fn a_name_of_the_full_limit_is_accepted() {
    let source = b"port = 1\n";
    let mut name = vec![b'a'; MAX_NAME_BYTES];
    name.push(0);
    let mut out = vec![0u8; 64 * 1024];
    let mut out_len = out.len();
    // SAFETY: the name is NUL-terminated and both buffers are live.
    let status = unsafe {
        active_infinity_from_active(
            source.as_ptr(),
            source.len(),
            name.as_ptr().cast(),
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    assert_ne!(
        last_error(),
        "infinity/name-too-long",
        "a name of exactly {MAX_NAME_BYTES} bytes is inside the limit (status {status})"
    );
}

/// A one-byte-over name is refused by the bounded scan, not read past.
#[test]
fn a_name_over_the_limit_is_refused() {
    let source = b"port = 1\n";
    let mut name = vec![b'a'; MAX_NAME_BYTES + 1];
    name.push(0);
    let mut out = vec![0u8; 4096];
    let mut out_len = out.len();
    // SAFETY: the name is NUL-terminated; the scan must stop at the cap.
    let status = unsafe {
        active_infinity_from_active(
            source.as_ptr(),
            source.len(),
            name.as_ptr().cast(),
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    assert_eq!(status, -1);
    assert_eq!(last_error(), "infinity/name-too-long");
}

/// A length beyond `isize::MAX` must be refused before a slice is built from it.
#[test]
fn a_hostile_length_is_refused_before_the_slice() {
    let bytes = vector("empty.ainf");
    // SAFETY: the pointer is valid; the length is hostile and must be refused
    // without touching the buffer.
    let status = unsafe { active_infinity_validate(bytes.as_ptr(), usize::MAX) };
    assert_eq!(status, -1);
    assert_eq!(last_error(), "infinity/null-input");
}

/// The FFI hash is the byte identity: it equals the stored header hash and the
/// reference `content_hash`, for a canonical image and for a non-canonical one
/// whose bytes are still valid. Every language in the matrix hashes the same
/// bytes to the same value.
#[test]
fn content_hash_matches_the_reference_for_any_valid_image() {
    use active_infinity_ffi::active_infinity_content_hash;

    for name in ["full.ainf", "non_canonical.ainf"] {
        let bytes = vector(name);
        let mut hash = [0u8; 32];
        // SAFETY: the buffer is readable and `hash` is 32 writable bytes.
        let status =
            unsafe { active_infinity_content_hash(bytes.as_ptr(), bytes.len(), hash.as_mut_ptr()) };
        assert_eq!(status, 0, "{name}: {}", last_error());
        assert_eq!(
            hash,
            active_infinity::content_hash(&bytes).expect("reference")
        );
    }
}

/// `alloc` and `free` are primitives: a binding may call them between a failed
/// call and its read of `last_error`, so they must not clobber the code.
#[test]
fn alloc_and_free_do_not_change_the_last_error() {
    use active_infinity_ffi::{active_infinity_alloc, active_infinity_free};

    // SAFETY: the pointer is a 4-byte readable literal.
    assert_eq!(unsafe { active_infinity_validate(b"junk".as_ptr(), 4) }, -1);
    assert_eq!(last_error(), "infinity/magic");
    let pointer = active_infinity_alloc(8);
    assert!(!pointer.is_null());
    assert_eq!(last_error(), "infinity/magic");
    // SAFETY: the pointer and length come from the allocation above.
    unsafe { active_infinity_free(pointer, 8) };
    assert_eq!(last_error(), "infinity/magic");
    // A status-bearing call still reports its own result.
    let bytes = vector("full.ainf");
    let mut out = vec![0u8; 64];
    // SAFETY: buffers follow the contract.
    let status = unsafe {
        active_infinity_ffi::active_infinity_content_hash(
            bytes.as_ptr(),
            bytes.len(),
            out.as_mut_ptr(),
        )
    };
    assert_eq!(status, 0);
    assert_eq!(last_error(), "infinity/ok");
}

/// `validate_canonical` accepts every canonical vector, so the comparison with
/// `validate` is meaningful in both directions.
#[test]
fn validate_canonical_accepts_every_canonical_vector() {
    use active_infinity_ffi::active_infinity_validate_canonical;

    for name in ["empty.ainf", "full.ainf", "extensions.ainf", "simple.ainf"] {
        let bytes = vector(name);
        // SAFETY: the vector is a readable buffer.
        let status = unsafe { active_infinity_validate_canonical(bytes.as_ptr(), bytes.len()) };
        assert_eq!(status, 0, "{name}: {}", last_error());
    }
}
