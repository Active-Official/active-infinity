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
