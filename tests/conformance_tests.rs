//! Conformance vectors: checked-in bytes with declared expectations.
//!
//! The vector set is part of the wire contract, so it is checked in rather than
//! generated during the test run. `index.txt` files hold the expectations; if
//! the codec or the canonical form changes, regenerating produces a reviewable
//! diff (`cargo run --example generate_vectors`).
//!
//! Coverage is bidirectional, which is the point of a conformance suite:
//!
//! - every checked-in vector must behave as its index line declares;
//! - every failure class declared in `docs/spec/layout.md` must have a vector,
//!   or an entry in [`NON_IMAGE_CLASSES`] saying why no byte image can express
//!   it. A new code cannot land without a vector or an explicit waiver.
//!
//! Valid vectors prove: validation succeeds, the stored content hash matches the
//! index, decoding re-encodes byte-identically, and the zero-copy view agrees
//! with the decoded module. Invalid vectors prove each failure class is
//! rejected with its documented code and no panic, using only the bytes in the
//! repository. Stream vectors run through the shipped `StreamDecoder`, so the
//! frame layer is covered with the same discipline as whole images.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use active_infinity::{
    decode, encode, validate_canonical, validate_with, DecodeOpts, InfinityView, Limits,
    StreamDecoder,
};

/// Failure classes that no input image can trigger, with the reason.
///
/// Everything else must have a vector. Keeping this list explicit means a new
/// error code fails the suite until its author either ships a vector or writes
/// down why the code is unreachable from bytes.
const NON_IMAGE_CLASSES: &[(&str, &str)] = &[
    (
        "infinity/invalid-argument",
        "caller-supplied argument (offset, depth, tag) outside its range",
    ),
    (
        "infinity/encode",
        "encoder-side refusal; the bytes it would have produced do not exist",
    ),
    (
        "infinity/encode-dangling",
        "encoder-side refusal; the bytes it would have produced do not exist",
    ),
    (
        "infinity/too-large",
        "requires an image above the 4 GiB address space",
    ),
];

struct Entry {
    name: String,
    expected: String,
    /// Positional values after the expected one (size, hash, counts, ...).
    extra: Vec<String>,
    options: Vec<(String, String)>,
}

impl Entry {
    fn option(&self, key: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    /// `limits=max_nodes:1,max_depth:8` → a `Limits` value.
    fn limits(&self) -> Limits {
        let mut limits = Limits::default();
        let Some(spec) = self.option("limits") else {
            return limits;
        };
        for pair in spec.split(',') {
            let (key, value) = pair
                .split_once(':')
                .unwrap_or_else(|| panic!("{}: malformed limits `{pair}`", self.name));
            let value: u64 = value
                .parse()
                .unwrap_or_else(|_| panic!("{}: limit `{key}` is not an integer", self.name));
            match key {
                "max_nodes" => limits.max_nodes = value as u32,
                "max_edges" => limits.max_edges = value as u32,
                "max_children" => limits.max_children = value as u32,
                "max_fields" => limits.max_fields = value as u32,
                "max_parts" => limits.max_parts = value as u32,
                "max_strings" => limits.max_strings = value as u32,
                "max_string_bytes" => limits.max_string_bytes = value as u32,
                "max_blobs" => limits.max_blobs = value as u32,
                "max_blob_bytes" => limits.max_blob_bytes = value as u32,
                "max_annotations" => limits.max_annotations = value as u32,
                "max_units" => limits.max_units = value as u32,
                "max_types" => limits.max_types = value as u32,
                "max_aux" => limits.max_aux = value as u32,
                "max_numbers" => limits.max_numbers = value as u32,
                "max_secrets" => limits.max_secrets = value as u32,
                "max_secret_bytes" => limits.max_secret_bytes = value as u32,
                "max_extensions" => limits.max_extensions = value as u32,
                "max_prov_entries" => limits.max_prov_entries = value as u32,
                "max_total_bytes" => limits.max_total_bytes = value,
                "max_depth" => limits.max_depth = value as u32,
                other => panic!("{}: unknown limit `{other}`", self.name),
            }
        }
        limits
    }

    fn decode_opts(&self) -> DecodeOpts {
        DecodeOpts {
            limits: self.limits(),
            ..DecodeOpts::default()
        }
    }

    /// A valid vector is canonical unless it says otherwise.
    fn is_canonical(&self) -> bool {
        self.option("canonical") != Some("no")
    }

    /// Positional values, starting with the size for valid vectors.
    fn numbers(&self) -> Vec<&str> {
        let mut numbers = vec![self.expected.as_str()];
        numbers.extend(self.extra.iter().map(String::as_str));
        numbers
    }
}

fn vectors_dir(kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(kind)
}

fn parse_index(kind: &str) -> Vec<Entry> {
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
            let mut parts = line.split_whitespace();
            let name = parts
                .next()
                .unwrap_or_else(|| panic!("{kind}: empty index line"))
                .to_string();
            let mut expected = String::new();
            let mut extra = Vec::new();
            let mut options = Vec::new();
            for (index, token) in parts.enumerate() {
                match token.split_once('=') {
                    Some((key, value)) => options.push((key.to_string(), value.to_string())),
                    None if index == 0 => expected = token.to_string(),
                    None => extra.push(token.to_string()),
                }
            }
            Entry {
                name,
                expected,
                extra,
                options,
            }
        })
        .collect()
}

fn read_vector(kind: &str, name: &str) -> Vec<u8> {
    let path = vectors_dir(kind).join(format!("{name}.ainf"));
    fs::read(&path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// Run `f`, turning a panic into a test failure that names the vector.
fn without_panic<T>(name: &str, f: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(_) => panic!("{name} made the codec panic"),
    }
}

#[test]
fn valid_vectors_validate_and_reencode_identically() {
    let entries = parse_index("valid");
    assert!(!entries.is_empty(), "the vector set must not be empty");
    for entry in entries {
        let name = entry.name.as_str();
        let numbers = entry.numbers();
        assert_eq!(numbers.len(), 5, "{name}: size, hash and three counts");
        let expected_size: u64 = numbers[0].parse().expect("size");
        let expected_hash = numbers[1];
        let expected_nodes: u32 = numbers[2].parse().expect("nodes");
        let expected_strings: u32 = numbers[3].parse().expect("strings");
        let expected_blobs: u32 = numbers[4].parse().expect("blobs");
        let bytes = read_vector("valid", name);
        let limits = entry.limits();

        let meta = without_panic(name, || validate_with(&bytes, entry.decode_opts()))
            .unwrap_or_else(|error| panic!("{name} must validate, got {error:?}"));
        assert_eq!(meta.total_size, expected_size, "{name} size");
        assert_eq!(
            active_infinity::ir::hash_hex(&meta.content_hash),
            expected_hash,
            "{name} content hash"
        );
        assert_eq!(meta.nodes, expected_nodes, "{name} node count");
        assert_eq!(meta.strings, expected_strings, "{name} string count");
        assert_eq!(meta.blobs, expected_blobs, "{name} blob count");

        let module =
            decode(&bytes).unwrap_or_else(|error| panic!("{name} must decode, got {error:?}"));

        let view = InfinityView::new(&bytes, limits).expect("view");
        assert_eq!(view.node_count(), meta.nodes, "{name} view nodes");
        assert_eq!(view.content_hash(), meta.content_hash, "{name} view hash");

        if entry.is_canonical() {
            assert_eq!(encode(&module).unwrap(), bytes, "{name} re-encode");
            validate_canonical(&bytes, limits)
                .unwrap_or_else(|error| panic!("{name} must be canonical, got {error:?}"));
        } else {
            // The encoder drops the unreferenced string, so the image changes —
            // and the image it produces must itself be canonical and stable.
            let canonical = encode(&module).expect("re-encode");
            assert_ne!(canonical, bytes, "{name} must not already be canonical");
            let error = validate_canonical(&bytes, limits)
                .expect_err("a non-canonical image must fail canonical verification");
            assert_eq!(error.code(), "infinity/not-canonical", "{name}");
            validate_canonical(&canonical, limits).unwrap_or_else(|error| {
                panic!("{name}: the re-encoded image must be canonical, got {error:?}")
            });
            let again = decode(&canonical).expect("decode the canonical image");
            assert_eq!(
                encode(&again).unwrap(),
                canonical,
                "{name} canonical fixpoint"
            );
        }
    }
}

#[test]
fn invalid_vectors_are_rejected_with_their_declared_code() {
    let entries = parse_index("invalid");
    assert!(
        entries.len() >= 33,
        "the invalid set must cover every byte-reachable validation class"
    );
    for entry in entries {
        let name = entry.name.as_str();
        let expected = entry.expected.as_str();
        let bytes = read_vector("invalid", name);
        let limits = entry.limits();
        let canonical_verification = entry.option("verify") == Some("canonical");
        let outcome = without_panic(name, || {
            if canonical_verification {
                validate_canonical(&bytes, limits)
            } else {
                validate_with(&bytes, entry.decode_opts())
            }
        });
        let error = match outcome {
            Ok(_) => panic!("{name} must be rejected but validated"),
            Err(error) => error,
        };
        assert_eq!(
            error.code(),
            expected,
            "{name}: unexpected failure class ({error:?})"
        );
        // Every rejection must be value-free: no payload bytes in the message.
        let message = error.to_string();
        assert!(
            !message.contains("vector-secret"),
            "{name}: the error message leaked payload"
        );
    }
}

#[test]
fn stream_vectors_are_rejected_with_their_declared_code() {
    let entries = parse_index("invalid_stream");
    assert!(
        entries.len() >= 9,
        "the stream set must cover every frame-layer class"
    );
    for entry in entries {
        let name = entry.name.as_str();
        let bytes = read_vector("invalid_stream", name);
        let outcome = without_panic(name, || {
            let mut decoder = StreamDecoder::new();
            decoder.push_bytes(&bytes)?;
            decoder.finish().map(|_| ())
        });
        let error = match outcome {
            Ok(()) => panic!("{name} must be rejected but the decoder accepted it"),
            Err(error) => error,
        };
        assert_eq!(
            error.code(),
            entry.expected,
            "{name}: unexpected failure class ({error:?})"
        );
    }
}

/// Every code in the spec's error table needs a vector or a documented reason.
#[test]
fn every_declared_failure_code_has_a_vector() {
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for kind in ["invalid", "invalid_stream"] {
        for entry in parse_index(kind) {
            covered.insert(entry.expected.trim_end_matches('/').to_string());
        }
    }
    let waived: BTreeSet<&str> = NON_IMAGE_CLASSES.iter().map(|(code, _)| *code).collect();

    let mut missing = Vec::new();
    for code in spec_error_codes() {
        if !covered.contains(&code) && !waived.contains(code.as_str()) {
            missing.push(code);
        }
    }
    assert!(
        missing.is_empty(),
        "docs/spec/layout.md declares codes with no conformance vector: {missing:?}"
    );

    // Keep the waiver list honest: every entry must still be a real code, and
    // must not shadow a vector that actually exists.
    let spec: BTreeSet<String> = spec_error_codes().into_iter().collect();
    for (code, reason) in NON_IMAGE_CLASSES {
        assert!(
            spec.contains(*code),
            "{code} is waived but no longer declared in the spec"
        );
        assert!(
            !covered.contains(*code),
            "{code} is waived but has a vector; drop the waiver"
        );
        assert!(!reason.is_empty(), "{code} needs a reason");
    }
}

/// Every checked-in image must be listed, and every listed image must exist.
#[test]
fn the_index_and_the_vector_files_agree() {
    for kind in ["valid", "invalid", "invalid_stream"] {
        let listed: BTreeSet<String> = parse_index(kind).into_iter().map(|e| e.name).collect();
        let mut on_disk = BTreeSet::new();
        for item in fs::read_dir(vectors_dir(kind)).expect("vector directory") {
            let path = item.expect("directory entry").path();
            if path.extension().and_then(|e| e.to_str()) == Some("ainf") {
                on_disk.insert(
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .expect("utf-8 stem")
                        .to_string(),
                );
            }
        }
        assert_eq!(
            listed, on_disk,
            "{kind}: index.txt and the checked-in images disagree"
        );
    }
}

#[test]
fn every_declared_invalid_class_is_documented_in_the_spec() {
    let spec = read_spec();
    for kind in ["invalid", "invalid_stream"] {
        for entry in parse_index(kind) {
            let code = entry.expected.trim_end_matches('/');
            assert!(
                spec.contains(code),
                "spec must document the failure class {code} ({})",
                entry.name
            );
        }
    }
}

fn read_spec() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/spec/layout.md"))
        .expect("layout spec")
}

/// The `infinity/...` codes from the spec's error table (§9).
fn spec_error_codes() -> Vec<String> {
    let text = read_spec();
    let start = text
        .find("## 9. Error codes")
        .expect("the spec must keep its error-code section");
    let section = &text[start..];
    let end = section[1..]
        .find("\n## ")
        .map(|index| index + 1)
        .unwrap_or(section.len());
    let section = &section[..end];

    let mut codes = Vec::new();
    let mut current = String::new();
    let mut in_code = false;
    for ch in section.chars() {
        if ch == '`' {
            if in_code && current.starts_with("infinity/") {
                codes.push(current.clone());
            }
            current.clear();
            in_code = !in_code;
        } else if in_code {
            current.push(ch);
        }
    }
    codes.sort();
    codes.dedup();
    assert!(
        codes.len() >= 35,
        "the error table should declare the full code set, found {}",
        codes.len()
    );
    codes
}
