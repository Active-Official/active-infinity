#![no_main]

//! Canonical round-trip and hash stability under mutation.
//!
//! Invariants under test:
//!
//! 1. A validated image decodes, and its re-encoding is a canonical fixpoint.
//! 2. Two independent encodes of the same logical module are byte-identical and
//!    have the same hash.
//! 3. A one-bit change outside the hash field either fails validation or changes
//!    the content hash; the old hash never verifies the new bytes.
//! 4. Construction order does not affect canonical identity.
//!
//! Run with `cargo +nightly fuzz run fuzz_canonical_roundtrip -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_infinity::{
    decode, encode, hash_image, validate, validate_canonical, InfinityModule, Inode, Limits,
};

#[path = "common.rs"]
mod common;

fn reverse_build(order: &[u8]) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut ids = Vec::new();
    for _ in 0..4 {
        ids.push(module.push(Inode::Int(1)));
    }
    // Build the table in an order chosen by the input. Canonical identity must
    // not depend on it.
    let mut fields: Vec<(String, active_infinity::NodeId)> = vec![
        ("a".into(), ids[0]),
        ("b".into(), ids[1]),
        ("c".into(), ids[2]),
        ("d".into(), ids[3]),
    ];
    if order.first().copied().unwrap_or(0) % 2 == 1 {
        fields.reverse();
    }
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));
    module
}

fuzz_target!(|data: &[u8]| {
    if let Ok(module) = decode(data) {
        let first = encode(&module).expect("a decoded module encodes");
        let second = encode(&module).expect("a decoded module encodes twice");
        assert_eq!(first, second, "encode is not deterministic");
        assert_eq!(
            hash_image(&first).expect("hash"),
            hash_image(&second).expect("hash"),
            "the hash is not stable"
        );
        assert!(
            validate_canonical(&first, Limits::default()).is_ok(),
            "encoder output must pass the canonical proof"
        );
        let again = decode(&first).expect("canonical bytes decode");
        assert_eq!(
            encode(&again).expect("re-encode"),
            first,
            "canonical form is not a fixpoint"
        );
    }

    // Independent encodes of the same logical module agree.
    let one = encode(&reverse_build(data)).expect("build encodes");
    let mut reordered = data.to_vec();
    reordered.push(1);
    let two = encode(&reverse_build(&reordered)).expect("build encodes");
    assert_eq!(one, two, "construction order changed canonical bytes");

    // A one-bit change outside the hash field: fail closed or change the hash.
    let mut mutated = one.clone();
    if !data.is_empty() && mutated.len() > 64 {
        let span = mutated.len() - 64;
        let at = 64 + (data[0] as usize % span.max(1));
        mutated[at] ^= 1 << (data.get(1).copied().unwrap_or(0) % 8);
        let old = active_infinity::layout::Header::parse(&one)
            .expect("header")
            .content_hash;
        if common::rehash(&mut mutated) {
            match validate(&mutated) {
                Ok(_) => {
                    let new = active_infinity::layout::Header::parse(&mutated)
                        .expect("header")
                        .content_hash;
                    assert_ne!(old, new, "a changed payload kept the content hash");
                }
                Err(error) => {
                    assert!(
                        error.code().starts_with("infinity/"),
                        "unexpected error code {}",
                        error.code()
                    );
                }
            }
        }
    }
});
