//! ABI tests: the C surface must reproduce the reference bytes and codes.

use std::ffi::CString;

use active_infinity_ffi::{
    active_infinity_abi_version, active_infinity_alloc, active_infinity_alloc_gen,
    active_infinity_content_hash, active_infinity_decode_with_limits, active_infinity_free,
    active_infinity_free_gen, active_infinity_from_active, active_infinity_last_error,
    active_infinity_limits_default, active_infinity_redacted_json, active_infinity_reencode,
    active_infinity_validate, active_infinity_validate_canonical,
    active_infinity_validate_with_limits, ActiveInfinityLimits, EXPORTS, MAX_ALLOC_BYTES,
    MAX_NAME_BYTES, MAX_SOURCE_BYTES,
};

fn vector(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors/valid")
        .join(name);
    std::fs::read(path).expect("vector")
}

fn invalid_vector(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors/invalid")
        .join(name);
    std::fs::read(path).expect("invalid vector")
}

/// A limits struct filled by the library itself (INF-FFI-02): no test
/// hardcodes the 24 defaults, so a default change cannot desync the test.
fn default_limits() -> ActiveInfinityLimits {
    // SAFETY: the export writes every field of the struct.
    let mut limits = std::mem::MaybeUninit::<ActiveInfinityLimits>::uninit();
    let status = unsafe { active_infinity_limits_default(limits.as_mut_ptr()) };
    assert_eq!(status, 0, "{}", last_error());
    unsafe { limits.assume_init() }
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
fn reencode_repairs_a_non_canonical_image() {
    // NF-INF02-01: `reencode` is the repair path. `validate` and
    // `content_hash` prove the canonical form (INF-02), so they refuse the
    // valid non-canonical vector with `infinity/not-canonical`; `reencode`
    // decodes it leniently, re-encodes, and strict-validates the output.
    // The vector is a non-canonical encoding of the same module as
    // `simple.ainf`, so the repaired bytes are exactly `simple.ainf`.
    let bytes = vector("non_canonical.ainf");
    // SAFETY: the vector is readable.
    let status = unsafe { active_infinity_validate(bytes.as_ptr(), bytes.len()) };
    assert_eq!(status, -1);
    assert_eq!(last_error(), "infinity/not-canonical");
    let mut hash = [0u8; 32];
    // SAFETY: the buffer is readable and `hash` is 32 writable bytes.
    let status =
        unsafe { active_infinity_content_hash(bytes.as_ptr(), bytes.len(), hash.as_mut_ptr()) };
    assert_eq!(status, -1);
    assert_eq!(last_error(), "infinity/not-canonical");

    let mut out = vec![0u8; bytes.len()];
    let mut out_len = out.len();
    // SAFETY: out/out_len follow the calling convention.
    let status = unsafe {
        active_infinity_reencode(bytes.as_ptr(), bytes.len(), out.as_mut_ptr(), &mut out_len)
    };
    assert_eq!(status, 0, "{}", last_error());
    out.truncate(out_len);
    let simple = vector("simple.ainf");
    assert_eq!(out, simple, "the repair must be the canonical encoding");
    assert_ne!(out, bytes, "the repair must differ from the input");
    // SAFETY: the repaired bytes are readable.
    let status = unsafe { active_infinity_validate(out.as_ptr(), out.len()) };
    assert_eq!(status, 0, "{}", last_error());
    let mut repaired_hash = [0u8; 32];
    // SAFETY: the buffer is readable and `repaired_hash` is 32 writable bytes.
    let status = unsafe {
        active_infinity_content_hash(out.as_ptr(), out.len(), repaired_hash.as_mut_ptr())
    };
    assert_eq!(status, 0, "{}", last_error());
    assert_eq!(
        repaired_hash,
        active_infinity::content_hash(&simple).expect("reference hash")
    );
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
fn validate_and_validate_canonical_both_refuse_non_canonical() {
    // INF-02: `validate()` now proves canonicality by default, so it no
    // longer accepts a structurally valid but non-canonical image where
    // `validate_canonical()` refused it; both entry points refuse the
    // vector with `infinity/not-canonical`, and both accept a canonical one.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors/invalid/not_canonical.ainf");
    let bytes = std::fs::read(path).expect("vector");
    // SAFETY: the vector is readable.
    let plain = unsafe { active_infinity_validate(bytes.as_ptr(), bytes.len()) };
    assert_eq!(plain, -1);
    assert_eq!(last_error(), "infinity/not-canonical");
    // SAFETY: the vector is readable.
    let canonical = unsafe { active_infinity_validate_canonical(bytes.as_ptr(), bytes.len()) };
    assert_eq!(canonical, -1);
    assert_eq!(last_error(), "infinity/not-canonical");
    // SAFETY: the canonical vector is readable.
    let good = vector("empty.ainf");
    let plain = unsafe { active_infinity_validate(good.as_ptr(), good.len()) };
    assert_eq!(plain, 0, "{}", last_error());
    let canonical = unsafe { active_infinity_validate_canonical(good.as_ptr(), good.len()) };
    assert_eq!(canonical, 0, "{}", last_error());
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
/// reference `content_hash` for a canonical image. Every language in the matrix
/// hashes the same bytes to the same value. A non-canonical image is refused
/// by both (INF-02): the hash is the identity of canonical bytes, not of any
/// structurally valid encoding.
#[test]
fn content_hash_matches_the_reference_for_any_valid_image() {
    use active_infinity_ffi::active_infinity_content_hash;

    let name = "full.ainf";
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
    // The non-canonical vector is refused, not hashed: the FFI and the
    // reference agree on the refusal as well as on the value.
    let bytes = vector("non_canonical.ainf");
    let mut hash = [0u8; 32];
    // SAFETY: the buffer is readable and `hash` is 32 writable bytes.
    let status =
        unsafe { active_infinity_content_hash(bytes.as_ptr(), bytes.len(), hash.as_mut_ptr()) };
    assert_eq!(status, -1);
    assert_eq!(last_error(), "infinity/not-canonical");
    let error = active_infinity::content_hash(&bytes).expect_err("reference refuses");
    assert_eq!(error.code(), "infinity/not-canonical");
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

/// `limits_default` fills every field with the library defaults (INF-FFI-02).
/// The spot checks pin the values the conformance story depends on: the
/// 1 GiB total budget and the 4096 depth ceiling.
#[test]
fn limits_default_reports_the_library_defaults() {
    let limits = default_limits();
    assert_eq!(limits.max_nodes, 1 << 22);
    assert_eq!(limits.max_total_bytes, 1 << 30);
    assert_eq!(limits.max_decoded_bytes, 256 << 20);
    assert_eq!(limits.max_depth, 4096);
    assert_eq!(limits.max_secret_bytes, 16 << 20);
    // A null pointer is refused, not dereferenced.
    let status = unsafe { active_infinity_limits_default(std::ptr::null_mut()) };
    assert_eq!(status, -1);
    assert_eq!(last_error(), "infinity/null-output");
}

/// The manifest's limit vectors are hostile only under a narrowed budget
/// (INF-FFI-02): both are ACCEPTED under the defaults, and refused with
/// their declared codes once the budget is tightened. This is the
/// fail-before the audit could not run through any binding — the FFI had
/// no limits parameter at all.
#[test]
fn validate_with_limits_refuses_the_limit_vectors() {
    for (name, field, value, code) in [
        ("limit.ainf", "max_nodes", 1u32, "infinity/limit"),
        ("too_deep.ainf", "max_depth", 8u32, "infinity/depth"),
    ] {
        let bytes = invalid_vector(name);
        // Under the defaults the vector is accepted: the budget, not the
        // bytes, is what makes it hostile.
        // SAFETY: the vector is a readable buffer; null means defaults.
        let status = unsafe {
            active_infinity_validate_with_limits(bytes.as_ptr(), bytes.len(), std::ptr::null())
        };
        assert_eq!(status, 0, "{name} under defaults: {}", last_error());
        // Under the manifest's narrowed budget it is refused with exactly
        // the code the manifest declares.
        let mut limits = default_limits();
        match field {
            "max_nodes" => limits.max_nodes = value,
            "max_depth" => limits.max_depth = value,
            _ => unreachable!("{field}"),
        }
        // SAFETY: the vector is readable and `limits` is a valid struct.
        let status =
            unsafe { active_infinity_validate_with_limits(bytes.as_ptr(), bytes.len(), &limits) };
        assert_eq!(status, -1, "{name}");
        assert_eq!(last_error(), code, "{name}");
    }
}

/// The same two vectors through the decode path (INF-FFI-02): the refusal
/// codes match `validate_with_limits`, and a canonical image re-encodes
/// to its own bytes under the defaults.
#[test]
fn decode_with_limits_refuses_the_limit_vectors() {
    for (name, field, value, code) in [
        ("limit.ainf", "max_nodes", 1u32, "infinity/limit"),
        ("too_deep.ainf", "max_depth", 8u32, "infinity/depth"),
    ] {
        let bytes = invalid_vector(name);
        let mut limits = default_limits();
        match field {
            "max_nodes" => limits.max_nodes = value,
            "max_depth" => limits.max_depth = value,
            _ => unreachable!("{field}"),
        }
        let mut out = vec![0u8; 4096];
        let mut out_len = out.len();
        // SAFETY: buffers follow the contract.
        let status = unsafe {
            active_infinity_decode_with_limits(
                bytes.as_ptr(),
                bytes.len(),
                &limits,
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        assert_eq!(status, -1, "{name}");
        assert_eq!(last_error(), code, "{name}");
    }
    // A canonical image decodes and re-encodes to its own bytes.
    let bytes = vector("full.ainf");
    let mut out = vec![0u8; bytes.len()];
    let mut out_len = out.len();
    // SAFETY: buffers follow the contract; null means defaults.
    let status = unsafe {
        active_infinity_decode_with_limits(
            bytes.as_ptr(),
            bytes.len(),
            std::ptr::null(),
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    assert_eq!(status, 0, "{}", last_error());
    assert_eq!(out_len, bytes.len());
    assert_eq!(&out[..out_len], &bytes[..]);
}

/// A zero ceiling is an argument error, not a limit the reader discovers
/// later: `Limits::check` rejects it before any decoding happens.
#[test]
fn a_zero_ceiling_is_refused_as_an_invalid_argument() {
    let bytes = vector("full.ainf");
    let mut limits = default_limits();
    limits.max_nodes = 0;
    // SAFETY: the vector is readable and `limits` is a valid struct.
    let status =
        unsafe { active_infinity_validate_with_limits(bytes.as_ptr(), bytes.len(), &limits) };
    assert_eq!(status, -1);
    assert_eq!(last_error(), "infinity/invalid-argument");
}

/// Under the defaults, `validate_with_limits` agrees with
/// `validate_canonical` in both directions: it accepts a canonical image
/// and refuses a non-canonical one with the same code.
#[test]
fn validate_with_limits_matches_validate_canonical_under_defaults() {
    let good = vector("full.ainf");
    // SAFETY: the vector is readable; null means defaults.
    let status = unsafe {
        active_infinity_validate_with_limits(good.as_ptr(), good.len(), std::ptr::null())
    };
    assert_eq!(status, 0, "{}", last_error());
    let bad = invalid_vector("not_canonical.ainf");
    // SAFETY: the vector is readable; null means defaults.
    let status =
        unsafe { active_infinity_validate_with_limits(bad.as_ptr(), bad.len(), std::ptr::null()) };
    assert_eq!(status, -1);
    assert_eq!(last_error(), "infinity/not-canonical");
}

/// INF-FFI-01: a stale free after address reuse is refused and the live
/// buffer survives. This is the W5 C harness (`w5_ffi01.c`) as a Rust test:
/// alloc p1, free it, alloc p2 (the allocator reuses the address), then free
/// the stale handle (p1, old generation) and prove p2 is untouched.
#[test]
fn free_gen_refuses_a_stale_free_after_address_reuse() {
    let mut reused = false;
    for _ in 0..200 {
        let mut gen1 = 0u64;
        // SAFETY: gen1 is a writable u64.
        let p1 = unsafe { active_infinity_alloc_gen(64, &mut gen1) };
        assert!(!p1.is_null(), "alloc_gen must succeed");
        assert_ne!(gen1, 0, "generation 0 is never handed out");
        // SAFETY: p1 is a live 64-byte allocation with generation gen1.
        assert_eq!(unsafe { active_infinity_free_gen(p1, 64, gen1) }, 0);
        let mut gen2 = 0u64;
        // SAFETY: gen2 is a writable u64.
        let p2 = unsafe { active_infinity_alloc_gen(64, &mut gen2) };
        assert!(!p2.is_null(), "alloc_gen must succeed");
        if p2 != p1 {
            // The allocator did not reuse the address this round; free p2
            // and retry. (Same-size alloc/free cycles reuse the address
            // with overwhelming likelihood in both the system and WASM
            // allocators. 200 attempts keeps the test stable when other
            // tests allocate concurrently in the same process.)
            // SAFETY: p2 is a live 64-byte allocation with generation gen2.
            assert_eq!(unsafe { active_infinity_free_gen(p2, 64, gen2) }, 0);
            continue;
        }
        reused = true;
        assert_ne!(gen2, gen1, "a reused address carries a newer generation");
        // SAFETY: p2 is a live 64-byte allocation.
        unsafe { std::ptr::write_bytes(p2, 0xB2, 64) };
        // The stale free: p1's generation names an allocation that no longer
        // exists. It must be refused, and the live buffer must survive. The
        // return-code assert runs first, so p2 is only read while it is
        // provably still live (no use-after-free in the test itself).
        // SAFETY: p1 is the same address as p2 with the stale generation.
        assert_eq!(unsafe { active_infinity_free_gen(p1, 64, gen1) }, -1);
        // SAFETY: p2 is still the live allocation (the stale free refused).
        assert_eq!(
            unsafe { *p2 },
            0xB2,
            "the stale free must not touch the live buffer"
        );
        let mut gen3 = 0u64;
        // SAFETY: gen3 is a writable u64.
        let p3 = unsafe { active_infinity_alloc_gen(64, &mut gen3) };
        assert!(!p3.is_null(), "alloc_gen must succeed");
        assert_ne!(p3, p2, "the live buffer was not freed by the stale free");
        // SAFETY: p2 and p3 are live allocations with their generations.
        assert_eq!(unsafe { active_infinity_free_gen(p2, 64, gen2) }, 0);
        assert_eq!(unsafe { active_infinity_free_gen(p3, 64, gen3) }, 0);
        break;
    }
    assert!(
        reused,
        "the allocator never reused the freed address in 200 attempts"
    );
}

/// INF-FFI-01: an immediate double free through the generational path is
/// refused.
#[test]
fn free_gen_refuses_an_immediate_double_free() {
    let mut generation = 0u64;
    // SAFETY: generation is a writable u64.
    let pointer = unsafe { active_infinity_alloc_gen(64, &mut generation) };
    assert!(!pointer.is_null());
    // SAFETY: pointer is a live 64-byte allocation with this generation.
    assert_eq!(
        unsafe { active_infinity_free_gen(pointer, 64, generation) },
        0
    );
    // SAFETY: pointer was already freed with this generation.
    assert_eq!(
        unsafe { active_infinity_free_gen(pointer, 64, generation) },
        -1
    );
}

/// INF-FFI-01: a generational free with the wrong length is refused and the
/// buffer stays live (a later free with the right length still succeeds).
#[test]
fn free_gen_refuses_a_wrong_length_and_keeps_the_buffer_live() {
    let mut generation = 0u64;
    // SAFETY: generation is a writable u64.
    let pointer = unsafe { active_infinity_alloc_gen(64, &mut generation) };
    assert!(!pointer.is_null());
    // SAFETY: pointer is a live 64-byte allocation; 63 is the wrong length.
    assert_eq!(
        unsafe { active_infinity_free_gen(pointer, 63, generation) },
        -1
    );
    // The refusal must not untrack the buffer: the legitimate free works.
    // SAFETY: pointer is still the live 64-byte allocation.
    assert_eq!(
        unsafe { active_infinity_free_gen(pointer, 64, generation) },
        0
    );
}

/// INF-FFI-01: the legacy free validates the header BEFORE removing the
/// address from the registry, so a wrong-length free no longer untracks
/// the live buffer. Proof: after a wrong-length free and then a legitimate
/// free, the address is reclaimed and a later same-size allocation reuses
/// it (under the old order the buffer leaked untracked and its address
/// could never come back).
#[test]
fn legacy_free_with_a_wrong_length_keeps_the_buffer_live() {
    let pointer = active_infinity_alloc(64);
    assert!(!pointer.is_null());
    // SAFETY: pointer is a live 64-byte allocation; 63 is the wrong length.
    unsafe { active_infinity_free(pointer, 63) };
    // SAFETY: pointer is still the live 64-byte allocation.
    unsafe { active_infinity_free(pointer, 64) };
    let mut reused = false;
    for _ in 0..200 {
        let again = active_infinity_alloc(64);
        assert!(!again.is_null());
        if again == pointer {
            reused = true;
        }
        // SAFETY: again is a live 64-byte allocation.
        unsafe { active_infinity_free(again, 64) };
        if reused {
            break;
        }
    }
    assert!(reused, "the freed address was never handed out again");
}

/// INF-FFI-01: `alloc_gen` refuses a null generation out-pointer.
#[test]
fn alloc_gen_refuses_a_null_generation_out() {
    // SAFETY: a null out-pointer is the refused case.
    let pointer = unsafe { active_infinity_alloc_gen(64, std::ptr::null_mut()) };
    assert!(
        pointer.is_null(),
        "a null generation out-pointer is refused"
    );
}
