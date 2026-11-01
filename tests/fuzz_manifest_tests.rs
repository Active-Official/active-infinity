//! The fuzz lanes must describe the same target set.
//!
//! A target that exists in `fuzz/Cargo.toml` but is missing from the Docker
//! script, a workflow or the docs is a lane that silently stopped fuzzing
//! (I-16). This test is the reverse gate for that drift.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path.as_ref())
        .unwrap_or_else(|error| panic!("{}: {error}", path.as_ref().display()))
}

/// `[[bin]]` names declared by the fuzz crate.
fn cargo_targets() -> BTreeSet<String> {
    let manifest = read(root().join("fuzz/Cargo.toml"));
    let mut names = BTreeSet::new();
    let mut in_bin = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line == "[[bin]]" {
            in_bin = true;
            continue;
        }
        if line.starts_with('[') && line != "[[bin]]" {
            in_bin = false;
            continue;
        }
        if in_bin {
            if let Some(value) = line.strip_prefix("name = ") {
                names.insert(value.trim_matches('"').to_string());
            }
        }
    }
    names
}

/// The `TARGETS` list in the Docker driver.
fn script_targets() -> BTreeSet<String> {
    let script = read(root().join("scripts/fuzz_docker.py"));
    let start = script
        .find("TARGETS = [")
        .expect("the script must declare TARGETS");
    let end = start + script[start..].find(']').expect("TARGETS must close");
    let mut names = BTreeSet::new();
    for line in script[start..end].lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('"') {
            if let Some(value) = rest.split('"').next() {
                if value.starts_with("fuzz_") {
                    names.insert(value.to_string());
                }
            }
        }
    }
    names
}

#[test]
fn the_cargo_docker_and_workflow_lanes_list_the_same_targets() {
    let cargo = cargo_targets();
    assert!(!cargo.is_empty(), "fuzz/Cargo.toml has no [[bin]] targets");
    assert_eq!(
        cargo,
        script_targets(),
        "scripts/fuzz_docker.py TARGETS must match fuzz/Cargo.toml"
    );

    for workflow in ["ci.yml", "fuzz-nightly.yml"] {
        let text = read(root().join(".github/workflows").join(workflow));
        for target in &cargo {
            assert!(text.contains(target), "{workflow} does not run {target}");
        }
    }

    // One canonical nightly lane: `nightly.yml` keeps the coverage job only.
    let nightly = read(root().join(".github/workflows/nightly.yml"));
    assert!(
        !nightly.contains("cargo fuzz run"),
        "nightly.yml duplicates the fuzz lane; fuzz-nightly.yml is canonical"
    );

    for document in ["fuzz/README.md", "docs/hardening/CORPUS.md"] {
        let text = read(root().join(document));
        for target in &cargo {
            assert!(text.contains(target), "{document} omits {target}");
        }
    }

    // Every target must have a committed seed: an empty corpus is a lane that
    // starts from nothing on each run.
    for target in &cargo {
        let corpus = root().join("fuzz/corpus").join(target);
        let seeds = fs::read_dir(&corpus)
            .map(|entries| entries.filter_map(Result::ok).count())
            .unwrap_or(0);
        assert!(seeds > 0, "{target} has no committed seeds");
    }
}

/// The positive seeds must still parse; a seed that only reaches the refusal
/// branch leaves the success oracle unexercised.
#[cfg(all(feature = "signatures", feature = "json"))]
#[test]
fn the_positive_seeds_parse() {
    let envelope = fs::read(root().join("fuzz/corpus/fuzz_signed_image/valid-envelope"))
        .expect("envelope seed");
    assert!(
        active_infinity::SignedImage::from_bytes(&envelope).is_ok(),
        "the envelope seed must verify"
    );
    let proof = fs::read_to_string(root().join("fuzz/corpus/fuzz_proof_sidecar/valid-proof.json"))
        .expect("proof seed");
    assert!(
        active_infinity::Proof::from_json(&proof).is_ok(),
        "the proof seed must parse"
    );
    let schema = fs::read(root().join("fuzz/corpus/fuzz_schema/schema.ainf")).expect("schema seed");
    assert!(
        active_infinity::Schema::from_bytes(&schema).is_ok(),
        "the schema seed must parse"
    );
}
