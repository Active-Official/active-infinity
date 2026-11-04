//! F-01 (DeepSeek fix pack): the binding checks run through the public entry.
//!
//! The pack's claim was that `check_bindings` is never called. It is: the
//! `Validated::new` path calls `check_reachability`, whose first statement is
//! `check_bindings`. These tests prove each rejection fires through
//! `validate_with`, so the call graph cannot be broken silently.

use active_infinity::layout::{DecodeOpts, Section};
use active_infinity::{encode, validate_with, InfinityModule, Inode};

/// Two bindings, sorted (`a`, `b`), both naming the root node.
fn bindings_image() -> Vec<u8> {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(1));
    module.set_root(Some(root));
    module.bind("a", root);
    module.bind("b", root);
    encode(&module).expect("encode")
}

/// Where the bindings section's data starts: the count, then a reserved word,
/// then one 8-byte row per binding (name ref, node id).
fn bindings_base(bytes: &[u8]) -> usize {
    let header = active_infinity::layout::Header::parse(bytes).expect("header");
    header.span(Section::Bindings).offset as usize
}

fn opts() -> DecodeOpts {
    DecodeOpts {
        // The tests patch bytes, so the stored hash no longer matches; the
        // binding checks run before canonical re-encoding is compared.
        verify_hash: false,
        verify_canonical: false,
        ..DecodeOpts::default()
    }
}

#[test]
fn a_duplicate_binding_name_is_refused_through_validate() {
    let mut bytes = bindings_image();
    let base = bindings_base(&bytes);
    // Row 1 starts at base + 8. Point its name at row 0's string.
    let first = u32::from_le_bytes([
        bytes[base + 8],
        bytes[base + 9],
        bytes[base + 10],
        bytes[base + 11],
    ]);
    bytes[base + 16..base + 20].copy_from_slice(&first.to_le_bytes());
    let error = validate_with(&bytes, opts()).expect_err("the same name twice");
    assert_eq!(error.code(), "infinity/duplicate-binding", "{error:?}");
}

#[test]
fn an_unsorted_binding_table_is_refused_through_validate() {
    let mut bytes = bindings_image();
    let base = bindings_base(&bytes);
    // Swap the two names: the table becomes descending.
    let first = u32::from_le_bytes([
        bytes[base + 8],
        bytes[base + 9],
        bytes[base + 10],
        bytes[base + 11],
    ]);
    let second = u32::from_le_bytes([
        bytes[base + 16],
        bytes[base + 17],
        bytes[base + 18],
        bytes[base + 19],
    ]);
    bytes[base + 8..base + 12].copy_from_slice(&second.to_le_bytes());
    bytes[base + 16..base + 20].copy_from_slice(&first.to_le_bytes());
    let error = validate_with(&bytes, opts()).expect_err("names are not ascending");
    assert_eq!(error.code(), "infinity/duplicate-binding", "{error:?}");
}

#[test]
fn the_bindings_reserved_word_must_be_zero() {
    let mut bytes = bindings_image();
    let base = bindings_base(&bytes);
    // The section starts with its count, then the reserved word.
    bytes[base + 4..base + 8].copy_from_slice(&7u32.to_le_bytes());
    let error = validate_with(&bytes, opts()).expect_err("a non-zero reserved word");
    assert_eq!(error.code(), "infinity/reserved", "{error:?}");
}

#[test]
fn an_empty_bindings_section_is_refused() {
    // The bindings span count lives in the header; zeroing it must not produce a
    // module that validates with no bindings.
    let mut bytes = bindings_image();
    // The header's span table carries the section count; zeroing it must not
    // produce a module without bindings.
    let count_at = 64 + Section::Bindings as usize * 8 + 4;
    bytes[count_at..count_at + 4].copy_from_slice(&0u32.to_le_bytes());
    assert!(
        validate_with(&bytes, opts()).is_err(),
        "a module with no bindings must not validate"
    );
}
