//! Documentation gate.
//!
//! The layout spec is normative: these tests fail the build when the prose and
//! the implementation disagree about the facts that matter to a peer
//! implementer (magic, header size, section order, error codes, roadmap).
//! Cheap to run, and it keeps `docs/spec/layout.md` honest as the format
//! evolves.

use std::fs;
use std::path::Path;

fn repo_path(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

#[test]
fn layout_spec_documents_every_section_in_order() {
    let spec = fs::read_to_string(repo_path("docs/spec/layout.md")).expect("layout spec exists");
    let mut cursor = 0usize;
    for section in active_infinity::Section::ALL {
        let needle = section.name();
        let position = spec[cursor..]
            .find(needle)
            .unwrap_or_else(|| panic!("layout spec must mention section {needle} after {cursor}"));
        cursor += position + needle.len();
    }
}

#[test]
fn layout_spec_states_the_implemented_constants() {
    let spec = fs::read_to_string(repo_path("docs/spec/layout.md")).expect("layout spec exists");
    assert!(
        spec.contains(&format!(
            "header size is {} bytes",
            active_infinity::HEADER_SIZE
        )),
        "spec must state the fixed header size"
    );
    assert!(
        spec.contains("magic is `AINF`"),
        "spec must state the magic"
    );
    assert!(
        spec.contains(&format!(
            "format version is {}",
            active_infinity::FORMAT_MAJOR
        )),
        "spec must state the major version"
    );
    assert!(
        spec.contains("content hash is Blake3-256"),
        "spec must state the hash algorithm"
    );
    assert!(
        spec.contains("0xFFFF"),
        "spec must state the named-unit discriminant"
    );
}

#[test]
fn every_error_code_is_documented() {
    let spec = fs::read_to_string(repo_path("docs/spec/layout.md")).expect("layout spec exists");
    for code in [
        "infinity/magic",
        "infinity/version-major",
        "infinity/version-minor",
        "infinity/header-truncated",
        "infinity/header-size",
        "infinity/flags",
        "infinity/reserved",
        "infinity/offset",
        "infinity/truncated",
        "infinity/trailing-bytes",
        "infinity/count",
        "infinity/padding",
        "infinity/hash-mismatch",
        "infinity/dialect",
        "infinity/not-canonical",
        "infinity/string-ref",
        "infinity/node-ref",
        "infinity/utf8",
        "infinity/unknown-unit",
        "infinity/unit-ref",
        "infinity/edge",
        "infinity/cycle",
        "infinity/limit",
        "infinity/stream-magic",
        "infinity/stream-hash",
    ] {
        assert!(spec.contains(code), "layout spec must document code {code}");
    }
}

#[test]
fn readme_states_the_guarantees() {
    let readme = fs::read_to_string(repo_path("README.md")).expect("README exists");
    for phrase in ["canonical", "Blake3", "zero-copy", "secret", "streaming"] {
        assert!(
            readme.to_lowercase().contains(&phrase.to_lowercase()),
            "README must mention {phrase}"
        );
    }
}

#[test]
fn adr_index_lists_every_adr_file() {
    let dir = repo_path("docs/adr");
    let index = fs::read_to_string(dir.join("README.md")).expect("ADR index exists");
    for entry in fs::read_dir(&dir).expect("adr dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if name == "README.md" {
            continue;
        }
        assert!(index.contains(name), "ADR index must list {name}");
    }
}

#[test]
fn hardening_documents_exist_and_state_their_rules() {
    for doc in [
        "REVIEW-SCOPE.md",
        "RELEASE.md",
        "COMPATIBILITY.md",
        "MIGRATION.md",
        "COMPARISON.md",
        "LOGGING.md",
        "CORPUS.md",
        "RESEARCH-LOG.md",
        "STATUS.md",
        "invariant-map.toml",
    ] {
        let path = repo_path(&format!("docs/hardening/{doc}"));
        assert!(path.exists(), "missing hardening document {doc}");
    }

    let logging = fs::read_to_string(repo_path("docs/hardening/LOGGING.md")).expect("logging");
    assert!(logging.contains("raw 16-byte capability id"));
    assert!(logging.contains("***SECRET***"));
    assert!(logging.contains("correlation"));

    let release = fs::read_to_string(repo_path("docs/hardening/RELEASE.md")).expect("release");
    assert!(release.contains("Active-Official"));
    assert!(release.contains("RatioArtificiosa"));
    assert!(release.contains("cargo yank"));

    let compatibility =
        fs::read_to_string(repo_path("docs/hardening/COMPATIBILITY.md")).expect("compatibility");
    assert!(compatibility.contains("Unknown flags"));
    assert!(compatibility.contains("Deprecation window"));
}

#[test]
fn security_spec_lists_every_invariant() {
    let spec = fs::read_to_string(repo_path("docs/spec/security.md")).expect("security spec");
    for number in 1..=12 {
        let needle = format!("| I-{number} |");
        assert!(
            spec.contains(&needle),
            "security spec must list invariant I-{number}"
        );
    }
}

#[test]
fn review_program_is_documented_and_has_a_record() {
    let scope = fs::read_to_string(repo_path("docs/hardening/REVIEW-SCOPE.md")).expect("scope");
    for phrase in [
        "## Scope",
        "## Method",
        "## Severity",
        "## Mandatory review triggers",
        "## Cadence",
        "delta review",
        "release candidate",
    ] {
        assert!(scope.contains(phrase), "review scope must contain {phrase}");
    }
    let record = fs::read_to_string(repo_path("REVIEWS.md")).expect("review record");
    assert!(
        record.contains("## Round"),
        "review record must list rounds"
    );
    assert!(
        record.to_lowercase().contains("no new findings"),
        "review record must state convergence"
    );
    assert!(record.contains("| Finding |"), "review record must triage");
}

#[test]
fn performance_baselines_are_checked_in() {
    let perf = fs::read_to_string(repo_path("docs/spec/performance.md")).expect("performance");
    for shape in [
        "wide-64",
        "wide-256",
        "wide-1024",
        "deep-32",
        "deep-128",
        "deep-512",
    ] {
        assert!(
            perf.contains(shape),
            "performance matrix must include {shape}"
        );
    }
    assert!(perf.contains("Regression policy"));
    assert!(perf.contains("Hostile-input DoS budget"));
    let bench = fs::read_to_string(repo_path("benches/codec.rs")).expect("benchmark");
    assert!(bench.contains("deep_module"), "benchmark must cover depth");
    assert!(bench.contains("wide_module"), "benchmark must cover width");
}

#[test]
fn release_and_supply_chain_process_is_operational() {
    let release = fs::read_to_string(repo_path("docs/hardening/RELEASE.md")).expect("release");
    for phrase in [
        "SBOM",
        "signed",
        "reproducib",
        "cargo yank",
        "crates.io",
        "Active-Official",
        "RatioArtificiosa",
        "allowed_signers",
    ] {
        assert!(
            release.contains(phrase),
            "release guide must contain {phrase}"
        );
    }
}

#[test]
fn migration_comparison_and_compatibility_are_documented() {
    let migration =
        fs::read_to_string(repo_path("docs/hardening/MIGRATION.md")).expect("migration");
    assert!(migration.contains("JSON") && migration.contains("YAML"));
    let comparison =
        fs::read_to_string(repo_path("docs/hardening/COMPARISON.md")).expect("comparison");
    assert!(comparison.contains("Cap'n Proto"));
    assert!(comparison.contains("FlatBuffers"));
    assert!(comparison.contains("gRPC"));
    let compatibility =
        fs::read_to_string(repo_path("docs/hardening/COMPATIBILITY.md")).expect("compatibility");
    for phrase in ["Unknown flags", "Deprecation window", "AINF"] {
        assert!(
            compatibility.contains(phrase),
            "compatibility must contain {phrase}"
        );
    }
}

#[test]
fn status_publishes_residual_risks_and_the_sign_off_block() {
    let status = fs::read_to_string(repo_path("docs/hardening/STATUS.md")).expect("status");
    for phrase in [
        "Residual risks",
        "Maturity sign-off",
        "H0 inventory complete",
        "H9 continuous assurance active",
        "Sign-off",
    ] {
        assert!(status.contains(phrase), "STATUS must contain {phrase}");
    }
}

#[test]
fn security_policy_states_the_evidence_levels() {
    let security = fs::read_to_string(repo_path("SECURITY.md")).expect("security policy");
    for level in ["**Tested**", "**Fuzzed**", "**Reviewed**", "**Proven**"] {
        assert!(security.contains(level), "SECURITY.md must state {level}");
    }
    assert!(security.contains("not") && security.contains("formally"));
}
