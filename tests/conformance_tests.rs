//! Conformance vectors: checked-in images with declared expectations.
//!
//! The vector set is part of the wire contract. `index.txt` files are the
//! expected values; if the codec or the canonical form changes, regenerating
//! the vectors produces a reviewable diff (`cargo run --example
//! generate_vectors`).
//!
//! Valid vectors prove: validation succeeds, the stored content hash matches
//! the index, decoding re-encodes byte-identically, and the zero-copy view
//! agrees with the decoded module.
//!
//! Invalid vectors prove: each declared failure class is rejected with its
//! documented code and no panic, using only the bytes in the repository.

use std::fs;
use std::path::{Path, PathBuf};

use active_infinity::{decode, encode, validate, InfinityView, Limits};

fn vectors_dir(kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(kind)
}

fn parse_index(kind: &str) -> Vec<Vec<String>> {
    let path = vectors_dir(kind).join("index.txt");
    let text = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "cannot read {}: {error} (run `cargo run --example generate_vectors`)",
            path.display()
        )
    });
    text.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| {
            line.split_whitespace()
                .map(|part| part.to_string())
                .collect()
        })
        .collect()
}

#[test]
fn valid_vectors_validate_and_reencode_identically() {
    let entries = parse_index("valid");
    assert!(!entries.is_empty(), "the vector set must not be empty");
    for entry in entries {
        let name = &entry[0];
        let expected_size: u64 = entry[1].parse().expect("size");
        let expected_hash = &entry[2];
        let expected_nodes: u32 = entry[3].parse().expect("nodes");
        let path = vectors_dir("valid").join(format!("{name}.ainf"));
        let bytes = fs::read(&path).expect("vector file");

        let meta = validate(&bytes).unwrap_or_else(|error| {
            panic!("{name} must validate, got {error:?}");
        });
        assert_eq!(meta.total_size, expected_size, "{name} size");
        assert_eq!(
            active_infinity::ir::hash_hex(&meta.content_hash),
            *expected_hash,
            "{name} content hash"
        );
        assert_eq!(meta.nodes, expected_nodes, "{name} node count");

        let module = decode(&bytes).unwrap_or_else(|error| {
            panic!("{name} must decode, got {error:?}");
        });
        assert_eq!(encode(&module).unwrap(), bytes, "{name} re-encode");

        let view = InfinityView::new(&bytes, Limits::default()).expect("view");
        assert_eq!(view.node_count(), meta.nodes, "{name} view nodes");
        assert_eq!(view.content_hash(), meta.content_hash, "{name} view hash");
    }
}

#[test]
fn invalid_vectors_are_rejected_with_their_declared_code() {
    let entries = parse_index("invalid");
    assert!(
        entries.len() >= 10,
        "the invalid set must cover the classes"
    );
    for entry in entries {
        let name = &entry[0];
        let expected = &entry[1];
        let path = vectors_dir("invalid").join(format!("{name}.ainf"));
        let bytes = fs::read(&path).expect("vector file");
        let outcome = std::panic::catch_unwind(|| validate(&bytes));
        let error = match outcome {
            Ok(Ok(_)) => panic!("{name} must be rejected but validated"),
            Ok(Err(error)) => error,
            Err(_) => panic!("{name} made the validator panic"),
        };
        if expected.ends_with('/') {
            assert!(
                error.code().starts_with(expected.as_str()),
                "{name}: expected a code with prefix {expected}, got {}",
                error.code()
            );
        } else {
            assert_eq!(
                error.code(),
                expected.as_str(),
                "{name}: unexpected failure class ({error:?})"
            );
        }
    }
}

#[test]
fn every_declared_invalid_class_is_documented_in_the_spec() {
    let spec =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/spec/layout.md"))
            .expect("layout spec");
    for entry in parse_index("invalid") {
        let code = &entry[1];
        let code = code.trim_end_matches('/');
        assert!(
            spec.contains(code),
            "spec must document the failure class {code}"
        );
    }
}
