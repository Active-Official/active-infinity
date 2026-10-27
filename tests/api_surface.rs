//! Public-surface policy: secrets are structural, never readable through the API.
//!
//! A function that returns secret plaintext (or a `pub use` of one) turns
//! structural secrets into an unlock API. These checks fail the build when such
//! an accessor reappears, by three rules:
//!
//! 1. a named blacklist of every accessor this crate ever exported;
//! 2. a shape rule: any public function whose name mentions secrets and whose
//!    return type is a raw byte/text container (`String`, `Vec<String>`,
//!    `Vec<u8>`, `&[u8]`, `Vec<Vec<u8>>`) is a leak unless it is allowlisted with
//!    a reason. `secret_tainted_paths` is allowlisted: it returns redacted
//!    labels, not secret material;
//! 3. the scan walks every file under `src/`, follows declarations whose return
//!    type is on its own line, and strips every modifier
//!    (`const`/`async`/`unsafe`, in any order) before reading the name.
//!
//! The return type is read only after the last `->`, so an array length like
//! `[u8; 32]` in the parameter list cannot confuse the scan, and the body is cut
//! off before the check, so a one-line body cannot hide the type either.
//!
//! `SECRET_MARKER` is the one public secret constant, and it carries no secret.
//! A deliberately obfuscated accessor (an unrelated name returning `Vec<u8>`)
//! can still evade a text check; ADR-0010 makes that a reviewed decision, and the
//! allowlist below is the audit surface.

use std::path::{Path, PathBuf};

/// Public items that would hand out secret bytes or text.
const FORBIDDEN: &[&str] = &[
    "secret_texts",
    "secret_bytes",
    "secret_literals",
    "secret_values",
    "secret",
];

/// Functions whose name mentions secrets but whose return is not secret material.
const ALLOWED: &[(&str, &str)] = &[(
    "secret_tainted_paths",
    "returns redacted dotted labels of the tainted cone, never secret bytes",
)];

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory).expect("src directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Join a declaration that spans lines, including a return type that starts on
/// its own line, keeping the line number where it started.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut buffer = String::new();
    let mut start = 0usize;
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if buffer.is_empty() {
            start = index + 1;
        } else {
            buffer.push(' ');
        }
        buffer.push_str(trimmed);

        let balanced = buffer.matches('(').count() == buffer.matches(')').count();
        let next_continues = lines.get(index + 1).is_some_and(|next| {
            let next = next.trim();
            next.starts_with("->") || next.starts_with("where")
        });
        if balanced && !next_continues {
            out.push((start, std::mem::take(&mut buffer)));
        }
    }
    if !buffer.is_empty() {
        out.push((start, buffer));
    }
    out
}

/// The name of a public function, stripping `const`/`async`/`unsafe` in any order.
fn public_fn_name(line: &str) -> Option<&str> {
    let mut rest = line.strip_prefix("pub ")?;
    loop {
        let stripped = ["const ", "async ", "unsafe "]
            .iter()
            .find_map(|modifier| rest.strip_prefix(modifier));
        match stripped {
            Some(next) => rest = next,
            None => break,
        }
    }
    let rest = rest.strip_prefix("fn ")?;
    Some(rest.split('(').next().unwrap_or("").trim())
}

/// Whether the declaration's return type is raw text or bytes.
///
/// Only the text after the last `->` can be a return type, so array lengths and
/// generic parameters in the argument list cannot interfere.
fn returns_raw_text(line: &str) -> bool {
    let Some(arrow) = line.rfind("->") else {
        return false;
    };
    let tail = &line[arrow + 2..];
    // Stop at the body (or an unexpected block close); a trait declaration ends
    // with `;` and keeps its type in the tail.
    let signature = tail.split('{').next().unwrap_or(tail);
    let signature = signature.split('}').next().unwrap_or(signature);
    signature.contains("String") || signature.contains("u8")
}

#[test]
fn the_crate_exposes_no_plaintext_secret_accessor() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    for path in rust_sources(&root) {
        let relative = path
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(&path)
            .display()
            .to_string();
        let text = std::fs::read_to_string(&path).expect("source file");
        for (line_number, line) in logical_lines(&text) {
            if line.starts_with("//") {
                continue;
            }
            if let Some(name) = public_fn_name(&line) {
                if FORBIDDEN.contains(&name) {
                    offenders.push(format!("{relative}:{line_number}: {line}"));
                    continue;
                }
                if name.contains("secret") {
                    let allowed = ALLOWED.iter().any(|(allowed, _)| *allowed == name);
                    if !allowed && returns_raw_text(&line) {
                        offenders.push(format!("{relative}:{line_number}: {line}"));
                    }
                }
            }
            if line.starts_with("pub use") {
                for forbidden in FORBIDDEN {
                    if line
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .any(|token| token == *forbidden)
                    {
                        offenders.push(format!("{relative}:{line_number}: {line}"));
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

#[test]
fn the_allowlist_entries_still_exist_and_are_argued() {
    // A stale allowlist entry would silently widen the policy.
    let interop =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/interop.rs"))
            .expect("source file");
    for (name, reason) in ALLOWED {
        assert!(
            interop.contains(&format!("pub fn {name}")),
            "{name} is allowlisted but no longer exists; remove the entry"
        );
        assert!(
            reason.len() > 20,
            "{name} needs a real justification for the allowlist"
        );
    }
}
