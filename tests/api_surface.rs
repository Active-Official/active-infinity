//! Public-surface policy: secrets are structural, never readable through the API.
//!
//! A function that returns secret plaintext (or a `pub use` of one) turns
//! structural secrets into an unlock API. These checks fail the build if such an
//! accessor is reintroduced. The list is deliberately explicit: a new
//! secret-returning helper has to be added here, which makes the decision
//! visible in review. `SECRET_MARKER` is the one public secret constant, and it
//! carries no secret material.

use std::path::Path;

/// Public items that would hand out secret bytes or text.
const FORBIDDEN: &[&str] = &[
    "pub fn secret_texts",
    "pub fn secret_bytes",
    "pub fn secret_literals",
    "pub fn secret_values",
];

#[test]
fn the_crate_exposes_no_plaintext_secret_accessor() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sources = [
        "src/interop.rs",
        "src/canonical.rs",
        "src/ir.rs",
        "src/lib.rs",
        "src/protobuf.rs",
        "src/view.rs",
    ];
    let mut offenders = Vec::new();
    for relative in sources {
        let path = root.join(relative);
        let text = std::fs::read_to_string(&path).expect("source file");
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if FORBIDDEN
                .iter()
                .any(|forbidden| trimmed.starts_with(forbidden))
            {
                offenders.push(format!("{}:{}: {}", relative, index + 1, trimmed));
            }
            // A `pub use` that re-exports one of them is the same leak with a
            // different spelling.
            if trimmed.starts_with("pub use") {
                for forbidden in FORBIDDEN {
                    let name = forbidden.trim_start_matches("pub fn ");
                    if trimmed.contains(name) {
                        offenders.push(format!("{}:{}: {}", relative, index + 1, trimmed));
                    }
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the crate must not expose secret plaintext; found:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_redaction_marker_is_the_only_public_secret_constant() {
    // Pins the exception the check above relies on: the marker is a literal
    // `***SECRET***`, not secret material.
    assert_eq!(active_infinity::interop::SECRET_MARKER, "***SECRET***");
}
