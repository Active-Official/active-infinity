#![no_main]
//! The C ABI is the attacker-facing boundary for every binding: hostile
//! alloc/free sequences, hostile pointers and lengths, and hostile limit
//! tables must all fail closed with a code — never a panic, never a
//! use-after-free. The stale-free oracle is the INF-FFI-01 regression
//! property (a refused `free_gen` must leave the live buffer freeable),
//! and every pure function is cross-checked against the Rust API, so the
//! shim cannot drift from the codec (INF-POLY-05).
//!
//! Safety: every pointer handed to the ABI is null, points into the fuzz
//! input (alive for the whole iteration), into a live allocation tracked
//! in `slots`, or into a target-owned output buffer. A freed pointer is
//! never passed again.

use libfuzzer_sys::fuzz_target;

use active_infinity::{decode_with, encode, validate, validate_canonical, DecodeOpts, Limits};
use active_infinity_ffi::{
    active_infinity_abi_version, active_infinity_alloc, active_infinity_alloc_gen,
    active_infinity_content_hash, active_infinity_decode_with_limits, active_infinity_ffi_version,
    active_infinity_free, active_infinity_free_gen, active_infinity_from_active,
    active_infinity_last_error, active_infinity_limits_default, active_infinity_redacted_json,
    active_infinity_reencode, active_infinity_validate, active_infinity_validate_canonical,
    active_infinity_validate_with_limits, active_infinity_version, ActiveInfinityLimits,
    ABI_VERSION,
};
use std::ffi::CStr;

/// One live allocation tracked by the interpreter.
struct Slot {
    ptr: *mut u8,
    len: usize,
    generation: Option<u64>,
}

/// The error code the last ABI call left behind; always an `infinity/*` code.
fn last_error() -> String {
    unsafe {
        let ptr = active_infinity_last_error();
        assert!(!ptr.is_null(), "last_error is never null");
        CStr::from_ptr(ptr)
            .to_str()
            .expect("last_error is UTF-8")
            .to_string()
    }
}

/// The FFI limits table as the Rust `Limits` the codec checks.
fn to_rust_limits(ffi: &ActiveInfinityLimits) -> Limits {
    Limits {
        max_nodes: ffi.max_nodes,
        max_edges: ffi.max_edges,
        max_children: ffi.max_children,
        max_fields: ffi.max_fields,
        max_parts: ffi.max_parts,
        max_strings: ffi.max_strings,
        max_string_bytes: ffi.max_string_bytes,
        max_blobs: ffi.max_blobs,
        max_blob_bytes: ffi.max_blob_bytes,
        max_annotations: ffi.max_annotations,
        max_units: ffi.max_units,
        max_types: ffi.max_types,
        max_aux: ffi.max_aux,
        max_numbers: ffi.max_numbers,
        max_secrets: ffi.max_secrets,
        max_secret_bytes: ffi.max_secret_bytes,
        max_extensions: ffi.max_extensions,
        max_prov_bytes: ffi.max_prov_bytes,
        max_prov_entries: ffi.max_prov_entries,
        max_hashes: ffi.max_hashes,
        max_bindings: ffi.max_bindings,
        max_total_bytes: ffi.max_total_bytes,
        max_decoded_bytes: ffi.max_decoded_bytes,
        max_depth: ffi.max_depth,
    }
}

/// What a `write_output` ABI call returned, against a fixed 1 MiB buffer.
/// `TooSmall` is an honest size report, not a failure: the library produced
/// output larger than the buffer, and the reported size is the oracle.
enum Output {
    Ok(Vec<u8>),
    Refused(String),
    TooSmall(usize),
}

/// Call a `write_output` ABI function once, with a fixed 1 MiB buffer.
fn call_output(mut call: impl FnMut(*mut u8, *mut usize) -> i32, buffer: &mut Vec<u8>) -> Output {
    let mut capacity = buffer.len();
    let code = call(buffer.as_mut_ptr(), &mut capacity);
    match code {
        0 => {
            assert!(
                capacity <= buffer.len(),
                "a successful call reports within the buffer"
            );
            Output::Ok(buffer[..capacity].to_vec())
        }
        -2 => Output::TooSmall(capacity),
        _ => Output::Refused(last_error()),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 65_536 {
        return;
    }
    // Version surface: the ABI version is pinned, and the version strings
    // agree with the Rust API.
    assert_eq!(active_infinity_abi_version(), ABI_VERSION);
    unsafe {
        let version = CStr::from_ptr(active_infinity_version())
            .to_str()
            .expect("version is UTF-8");
        assert_eq!(
            version,
            active_infinity::VERSION,
            "the ABI reports the codec"
        );
        let shim = CStr::from_ptr(active_infinity_ffi_version())
            .to_str()
            .expect("ffi version is UTF-8");
        assert!(
            !shim.is_empty() && shim.contains('.'),
            "the shim reports a version"
        );
    }

    let mut limits = ActiveInfinityLimits {
        max_nodes: 0,
        max_edges: 0,
        max_children: 0,
        max_fields: 0,
        max_parts: 0,
        max_strings: 0,
        max_string_bytes: 0,
        max_blobs: 0,
        max_blob_bytes: 0,
        max_annotations: 0,
        max_units: 0,
        max_types: 0,
        max_aux: 0,
        max_numbers: 0,
        max_secrets: 0,
        max_secret_bytes: 0,
        max_extensions: 0,
        max_prov_bytes: 0,
        max_prov_entries: 0,
        max_hashes: 0,
        max_bindings: 0,
        max_total_bytes: 0,
        max_decoded_bytes: 0,
        max_depth: 0,
    };
    assert_eq!(
        unsafe { active_infinity_limits_default(&mut limits) },
        0,
        "the defaults fill"
    );
    assert!(limits.max_nodes > 0, "a default ceiling is non-zero");
    assert!(
        unsafe { active_infinity_limits_default(std::ptr::null_mut()) } == -1
            && last_error() == "infinity/null-output",
        "a null limits pointer is refused"
    );

    // Null-input legs: a null pointer with a length is refused, and an
    // empty input is an empty image (which validation then refuses).
    assert!(
        unsafe { active_infinity_validate(std::ptr::null(), 5) } == -1
            && last_error() == "infinity/null-input",
        "a null image pointer is refused"
    );

    // One scratch buffer for every `write_output` call below.
    let mut out_buffer = vec![0u8; 1 << 20];
    let mut slots: Vec<Slot> = Vec::new();
    let mut cursor = 0usize;
    let mut ops = 0usize;
    // A slice of the fuzz input, located by two u16 operands (offset,
    // length), so a slice can cover a whole image.
    fn take_slice<'a>(data: &'a [u8], cursor: &mut usize) -> &'a [u8] {
        if *cursor + 4 > data.len() {
            return &[];
        }
        let at = u16::from_le_bytes([data[*cursor], data[*cursor + 1]]) as usize % data.len();
        let len = u16::from_le_bytes([data[*cursor + 2], data[*cursor + 3]]) as usize;
        *cursor += 4;
        let end = (at + len).min(data.len());
        &data[at..end]
    }
    // One operand byte, or 0 past the end.
    let take_u8 = |data: &[u8], cursor: &mut usize| -> u8 {
        if *cursor >= data.len() {
            0
        } else {
            let value = data[*cursor];
            *cursor += 1;
            value
        }
    };
    while cursor < data.len() && ops < 48 {
        ops += 1;
        let op = take_u8(data, &mut cursor);
        match op % 14 {
            // 0: legacy alloc — tracked so it is freed exactly once.
            0 => {
                if slots.len() < 8 {
                    let len = (take_u8(data, &mut cursor) as usize) * 16;
                    let ptr = active_infinity_alloc(len);
                    if !ptr.is_null() {
                        slots.push(Slot {
                            ptr,
                            len,
                            generation: None,
                        });
                    }
                }
            }
            // 1: generational alloc.
            1 => {
                if slots.len() < 8 {
                    let len = (take_u8(data, &mut cursor) as usize) * 16;
                    let mut generation: u64 = 0;
                    let ptr = unsafe { active_infinity_alloc_gen(len, &mut generation) };
                    if !ptr.is_null() {
                        slots.push(Slot {
                            ptr,
                            len,
                            generation: Some(generation),
                        });
                    }
                }
            }
            // 2: legacy free of a live slot.
            2 => {
                if !slots.is_empty() {
                    let index = (take_u8(data, &mut cursor) as usize) % slots.len();
                    let slot = slots.remove(index);
                    unsafe { active_infinity_free(slot.ptr, slot.len) };
                }
            }
            // 3: generational free — the INF-FFI-01 oracle. A wrong
            // generation refuses (-1), leaves `last_error` untouched, AND
            // leaves the buffer live, which the correct free right after
            // proves. (A legacy slot has no generation to get wrong.)
            3 => {
                if !slots.is_empty() {
                    let index = (take_u8(data, &mut cursor) as usize) % slots.len();
                    let wrong_gen = take_u8(data, &mut cursor) as u64;
                    let slot = &slots[index];
                    let Some(generation) = slot.generation else {
                        continue;
                    };
                    let tried = generation.wrapping_add(wrong_gen.max(1));
                    let before = last_error();
                    let code = unsafe { active_infinity_free_gen(slot.ptr, slot.len, tried) };
                    assert_eq!(code, -1, "a stale generation refuses");
                    assert_eq!(
                        last_error(),
                        before,
                        "a refused free leaves last_error untouched"
                    );
                    let code = unsafe { active_infinity_free_gen(slot.ptr, slot.len, generation) };
                    assert_eq!(code, 0, "the live buffer still frees with its generation");
                    slots.remove(index);
                }
            }
            // 4: validate, cross-checked against the Rust API.
            4 => {
                let bytes = take_slice(data, &mut cursor);
                let code = unsafe { active_infinity_validate(bytes.as_ptr(), bytes.len()) };
                match validate(bytes) {
                    Ok(_) => assert_eq!(code, 0, "the ABI accepts what Rust accepts"),
                    Err(error) => {
                        assert_eq!(code, -1, "the ABI refuses what Rust refuses");
                        assert_eq!(last_error(), error.code(), "the ABI reports the Rust code");
                    }
                }
            }
            // 5: validate_canonical, cross-checked the same way.
            5 => {
                let bytes = take_slice(data, &mut cursor);
                let code =
                    unsafe { active_infinity_validate_canonical(bytes.as_ptr(), bytes.len()) };
                match validate_canonical(bytes, Limits::default()) {
                    Ok(_) => assert_eq!(code, 0, "canonical accepts what Rust accepts"),
                    Err(error) => {
                        assert_eq!(code, -1, "canonical refuses what Rust refuses");
                        assert_eq!(
                            last_error(),
                            error.code(),
                            "canonical reports the Rust code"
                        );
                    }
                }
            }
            // 6: validate under hostile limits, cross-checked.
            6 => {
                let bytes = take_slice(data, &mut cursor);
                mutate_limits(&mut limits, take_u8(data, &mut cursor));
                let code = unsafe {
                    active_infinity_validate_with_limits(bytes.as_ptr(), bytes.len(), &limits)
                };
                match validate_canonical(bytes, to_rust_limits(&limits)) {
                    Ok(_) => assert_eq!(code, 0, "limited validation accepts what Rust accepts"),
                    Err(error) => {
                        assert_eq!(code, -1, "limited validation refuses what Rust refuses");
                        assert_eq!(
                            last_error(),
                            error.code(),
                            "limited validation reports Rust"
                        );
                    }
                }
            }
            // 7: decode under hostile limits, cross-checked byte for byte.
            7 => {
                let bytes = take_slice(data, &mut cursor);
                mutate_limits(&mut limits, take_u8(data, &mut cursor));
                let rust_limits = to_rust_limits(&limits);
                let rust = decode_with(
                    bytes,
                    DecodeOpts {
                        limits: rust_limits,
                        verify_canonical: false,
                        ..DecodeOpts::default()
                    },
                )
                .and_then(|module| encode(&module))
                .and_then(|canonical| {
                    validate_canonical(&canonical, rust_limits).map(|_| canonical)
                });
                let limits_ptr = &limits as *const ActiveInfinityLimits;
                let ffi = call_output(
                    |out, out_len| unsafe {
                        active_infinity_decode_with_limits(
                            bytes.as_ptr(),
                            bytes.len(),
                            limits_ptr,
                            out,
                            out_len,
                        )
                    },
                    &mut out_buffer,
                );
                match (rust, ffi) {
                    (Ok(expected), Output::Ok(got)) => {
                        assert_eq!(got, expected, "decode_with_limits matches Rust");
                    }
                    (Err(error), Output::Refused(code)) => {
                        assert_eq!(code, error.code(), "decode refusal matches Rust");
                    }
                    (Ok(_), Output::Refused(code)) => {
                        panic!("the ABI refused a decode Rust accepts: {code}")
                    }
                    (Err(error), Output::Ok(_)) => {
                        panic!("the ABI accepted a decode Rust refuses: {}", error.code())
                    }
                    (Ok(_), Output::TooSmall(needed)) => {
                        assert!(
                            needed > out_buffer.len(),
                            "an oversized decode honestly reports its size"
                        );
                    }
                    (Err(_), Output::TooSmall(_)) => {
                        panic!("a refused decode reported an output size")
                    }
                }
            }
            // 8: content_hash, cross-checked byte for byte.
            8 => {
                let bytes = take_slice(data, &mut cursor);
                let mut out = [0u8; 32];
                let code = unsafe {
                    active_infinity_content_hash(bytes.as_ptr(), bytes.len(), out.as_mut_ptr())
                };
                match active_infinity::content_hash(bytes) {
                    Ok(expected) => {
                        assert_eq!(code, 0, "hash accepts what Rust accepts");
                        assert_eq!(out, expected, "the ABI hash matches Rust");
                    }
                    Err(error) => {
                        assert_eq!(code, -1, "hash refuses what Rust refuses");
                        assert_eq!(last_error(), error.code(), "hash reports the Rust code");
                    }
                }
            }
            // 9: reencode, cross-checked byte for byte.
            9 => {
                let bytes = take_slice(data, &mut cursor);
                let rust = decode_with(
                    bytes,
                    DecodeOpts {
                        verify_canonical: false,
                        ..DecodeOpts::default()
                    },
                )
                .and_then(|module| encode(&module))
                .and_then(|canonical| validate(&canonical).map(|_| canonical));
                let ffi = call_output(
                    |out, out_len| unsafe {
                        active_infinity_reencode(bytes.as_ptr(), bytes.len(), out, out_len)
                    },
                    &mut out_buffer,
                );
                match (rust, ffi) {
                    (Ok(expected), Output::Ok(got)) => {
                        assert_eq!(got, expected, "reencode matches Rust");
                    }
                    (Err(error), Output::Refused(code)) => {
                        assert_eq!(code, error.code(), "reencode refusal matches Rust");
                    }
                    (Ok(_), Output::Refused(code)) => {
                        panic!("the ABI refused a reencode Rust accepts: {code}")
                    }
                    (Err(error), Output::Ok(_)) => {
                        panic!("the ABI accepted a reencode Rust refuses: {}", error.code())
                    }
                    (Ok(_), Output::TooSmall(needed)) => {
                        assert!(
                            needed > out_buffer.len(),
                            "an oversized reencode honestly reports its size"
                        );
                    }
                    (Err(_), Output::TooSmall(_)) => {
                        panic!("a refused reencode reported an output size")
                    }
                }
            }
            // 10: redacted_json, cross-checked against the Rust projection.
            10 => {
                let bytes = take_slice(data, &mut cursor);
                let rust = active_infinity::decode(bytes)
                    .and_then(|module| active_infinity::interop::to_redacted_json(&module));
                let ffi = call_output(
                    |out, out_len| unsafe {
                        active_infinity_redacted_json(bytes.as_ptr(), bytes.len(), out, out_len)
                    },
                    &mut out_buffer,
                );
                match (rust, ffi) {
                    (Ok(expected), Output::Ok(got)) => {
                        assert_eq!(
                            String::from_utf8(got).expect("redacted JSON is UTF-8"),
                            expected,
                            "redacted_json matches Rust"
                        );
                    }
                    (Err(error), Output::Refused(code)) => {
                        assert_eq!(code, error.code(), "redacted refusal matches Rust");
                    }
                    (Ok(_), Output::Refused(code)) => {
                        panic!("the ABI refused a redaction Rust accepts: {code}")
                    }
                    (Err(error), Output::Ok(_)) => {
                        panic!(
                            "the ABI accepted a redaction Rust refuses: {}",
                            error.code()
                        )
                    }
                    (Ok(_), Output::TooSmall(needed)) => {
                        assert!(
                            needed > out_buffer.len(),
                            "an oversized redaction honestly reports its size"
                        );
                    }
                    (Err(_), Output::TooSmall(_)) => {
                        panic!("a refused redaction reported an output size")
                    }
                }
            }
            // 11: from_active, cross-checked against the Rust compile.
            11 => {
                let source = take_slice(data, &mut cursor);
                let name_len = (take_u8(data, &mut cursor) as usize).min(64);
                // The effective name ends at the first NUL (the ABI scans
                // the same way); rebuild it as exactly one NUL-terminated
                // string so `from_bytes_with_nul_unchecked` is sound.
                let raw = &source[..name_len.min(source.len())];
                let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
                let name_bytes = &raw[..end];
                let mut name_buf = name_bytes.to_vec();
                name_buf.push(0);
                let c_name = unsafe { CStr::from_bytes_with_nul_unchecked(&name_buf) };
                let name_str = std::str::from_utf8(name_bytes).ok();
                let rust = match (std::str::from_utf8(source), name_str) {
                    (Ok(text), Some(name)) => {
                        active_infinity::interop::from_active_source(text, name)
                            .and_then(|module| encode(&module))
                    }
                    _ => {
                        // Non-UTF-8 input cannot reach the Rust call; the
                        // ABI must refuse it with a codec code.
                        let mut probe_len: usize = 0;
                        let code = unsafe {
                            active_infinity_from_active(
                                source.as_ptr(),
                                source.len(),
                                c_name.as_ptr(),
                                std::ptr::null_mut(),
                                &mut probe_len,
                            )
                        };
                        assert_eq!(code, -1, "non-UTF-8 source refuses");
                        assert!(
                            last_error().starts_with("infinity/"),
                            "non-UTF-8 refusal carries a codec code"
                        );
                        continue;
                    }
                };
                let ffi = call_output(
                    |out, out_len| unsafe {
                        active_infinity_from_active(
                            source.as_ptr(),
                            source.len(),
                            c_name.as_ptr(),
                            out,
                            out_len,
                        )
                    },
                    &mut out_buffer,
                );
                match (rust, ffi) {
                    (Ok(expected), Output::Ok(got)) => {
                        assert_eq!(got, expected, "from_active matches Rust");
                    }
                    (Err(error), Output::Refused(code)) => {
                        assert_eq!(code, error.code(), "from_active refusal matches Rust");
                    }
                    (Ok(_), Output::Refused(code)) => {
                        panic!("the ABI refused a compile Rust accepts: {code}")
                    }
                    (Err(error), Output::Ok(_)) => {
                        panic!("the ABI accepted a compile Rust refuses: {}", error.code())
                    }
                    (Ok(_), Output::TooSmall(needed)) => {
                        assert!(
                            needed > out_buffer.len(),
                            "an oversized compile honestly reports its size"
                        );
                    }
                    (Err(_), Output::TooSmall(_)) => {
                        panic!("a refused compile reported an output size")
                    }
                }
            }
            // 12: null limits mean the defaults.
            12 => {
                let bytes = take_slice(data, &mut cursor);
                let code = unsafe {
                    active_infinity_validate_with_limits(
                        bytes.as_ptr(),
                        bytes.len(),
                        std::ptr::null(),
                    )
                };
                match validate_canonical(bytes, Limits::default()) {
                    Ok(_) => assert_eq!(code, 0, "null limits accept what the defaults accept"),
                    Err(error) => {
                        assert_eq!(code, -1, "null limits refuse what the defaults refuse");
                        assert_eq!(
                            last_error(),
                            error.code(),
                            "null limits report the Rust code"
                        );
                    }
                }
            }
            // 13: a null hash output is refused before the image is even
            // read — the caller's contract is checked first (null input,
            // then null output, then the image), so the code is
            // `infinity/null-output` whenever the output is null,
            // whatever the image.
            _ => {
                let bytes = take_slice(data, &mut cursor);
                let code = unsafe {
                    active_infinity_content_hash(bytes.as_ptr(), bytes.len(), std::ptr::null_mut())
                };
                assert_eq!(code, -1, "a null hash output refuses");
                assert_eq!(
                    last_error(),
                    "infinity/null-output",
                    "null-output code wins"
                );
            }
        }
        // Every call leaves a codec code behind.
        assert!(
            last_error().starts_with("infinity/"),
            "last_error always carries a codec code"
        );
    }
    // Every live buffer frees cleanly at the end of the iteration, so no
    // allocation leaks into the next one.
    for slot in slots {
        match slot.generation {
            Some(generation) => {
                assert_eq!(
                    unsafe { active_infinity_free_gen(slot.ptr, slot.len, generation) },
                    0,
                    "a live generational buffer frees at the end"
                );
            }
            None => unsafe { active_infinity_free(slot.ptr, slot.len) },
        }
    }
});

/// Mutate one ceiling of the limits table from a fuzz byte: the field is
/// picked by the low bits, the value by the high bits (0, 1, 8, or 1024),
/// so the table walks the default, tightened, and refused (zero) shapes.
fn mutate_limits(limits: &mut ActiveInfinityLimits, selector: u8) {
    let value = match selector >> 5 {
        0 => 0,
        1 => 1,
        2 => 8,
        _ => 1024,
    };
    match selector % 24 {
        0 => limits.max_nodes = value,
        1 => limits.max_edges = value,
        2 => limits.max_children = value,
        3 => limits.max_fields = value,
        4 => limits.max_parts = value,
        5 => limits.max_strings = value,
        6 => limits.max_string_bytes = value,
        7 => limits.max_blobs = value,
        8 => limits.max_blob_bytes = value,
        9 => limits.max_annotations = value,
        10 => limits.max_units = value,
        11 => limits.max_types = value,
        12 => limits.max_aux = value,
        13 => limits.max_numbers = value,
        14 => limits.max_secrets = value,
        15 => limits.max_secret_bytes = value,
        16 => limits.max_extensions = value,
        17 => limits.max_prov_bytes = value,
        18 => limits.max_prov_entries = value,
        19 => limits.max_hashes = value,
        20 => limits.max_bindings = value,
        21 => limits.max_total_bytes = u64::from(value),
        22 => limits.max_decoded_bytes = u64::from(value),
        _ => limits.max_depth = value,
    }
}
