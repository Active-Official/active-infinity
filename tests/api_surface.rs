//! Public-surface policy: secrets are structural, never readable through the API.
//!
//! The authoritative check is `scripts/api_surface.py`, which reads the rustdoc
//! JSON and therefore sees the resolved public API: free functions, inherent and
//! trait methods, and re-exports. CI runs it in the `api-surface` job. This file
//! is the **fast tripwire** that runs with `cargo test` and no nightly toolchain:
//! it catches the realistic textual forms and documents the policy, but a
//! determined author can spell around a text scan. ADR-0010 records that split.
//!
//! The tripwire rules:
//! 1. a blacklist of every accessor this crate ever exported, including a public
//!    `use` (aliased or glob) that names one;
//! 2. a shape rule: any public function whose name mentions secrets and whose
//!    return type is raw text or bytes (`String`, `str`, `char`, `u8` and their
//!    containers) is a leak unless allowlisted with a reason.
//!
//! `SECRET_MARKER` is the one public secret constant, and it carries no secret.

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
/// its own line or after a trailing `->`.
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
        let next = lines.get(index + 1).map(|line| line.trim());
        let continues = next.is_some_and(|next| {
            buffer.ends_with("->") || next.starts_with("->") || next.starts_with("where")
        });
        if balanced && !continues {
            out.push((start, std::mem::take(&mut buffer)));
        }
    }
    if !buffer.is_empty() {
        out.push((start, buffer));
    }
    out
}

/// Strip `#[...]` attributes and leading comments, then return the declaration.
fn declaration(line: &str) -> &str {
    let mut rest = line.trim_start();
    loop {
        if rest.starts_with("#[") {
            match rest.find(']') {
                Some(close) => rest = rest[close + 1..].trim_start(),
                None => return rest,
            }
        } else if rest.starts_with("///") || rest.starts_with("//") {
            return "";
        } else {
            return rest;
        }
    }
}

/// The name of a public function, stripping modifiers in any order.
fn public_fn_name(line: &str) -> Option<&str> {
    let mut rest = line.strip_prefix("pub ")?;
    loop {
        let stripped = ["const ", "async ", "unsafe "]
            .iter()
            .find_map(|modifier| rest.strip_prefix(modifier))
            .or_else(|| {
                if rest.starts_with("extern ") {
                    // `extern "C"` / `extern "system"`: drop the ABI string too.
                    let after = rest.trim_start_matches("extern ");
                    let after = match after.strip_prefix('"') {
                        Some(rest) => rest.split_once('"').map(|(_, rest)| rest).unwrap_or(after),
                        None => after,
                    };
                    Some(after.trim_start())
                } else {
                    None
                }
            });
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
/// The body is cut before the arrow is located, so a `->` in the body cannot
/// move the window, and only the text after the last `->` is examined, so array
/// lengths in parameters cannot interfere either.
fn returns_raw_text(line: &str) -> bool {
    let signature = line.split('{').next().unwrap_or(line);
    let signature = signature.split(" where ").next().unwrap_or(signature);
    let Some(arrow) = signature.rfind("->") else {
        return false;
    };
    let tail = &signature[arrow + 2..];
    tail.contains("String")
        || tail.contains("Vec<String>")
        || tail.contains("str")
        || tail.contains("char")
        || tail.contains("u8")
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
        for (line_number, raw) in logical_lines(&text) {
            let line = declaration(&raw);
            if line.is_empty() {
                continue;
            }
            if let Some(name) = public_fn_name(line) {
                if FORBIDDEN.contains(&name) {
                    offenders.push(format!("{relative}:{line_number}: {line}"));
                    continue;
                }
                if name.contains("secret") {
                    let allowed = ALLOWED.iter().any(|(allowed, _)| *allowed == name);
                    if !allowed && returns_raw_text(line) {
                        offenders.push(format!("{relative}:{line_number}: {line}"));
                    }
                }
            }
            if line.starts_with("pub use") {
                if line.contains("::*") {
                    offenders.push(format!(
                        "{relative}:{line_number}: glob re-export cannot be audited: {line}"
                    ));
                }
                // `pub use innocent as secret_x` hides the target behind a new
                // name; a text scan cannot resolve it, so it fails closed.
                if let Some((_, alias)) = line.split_once(" as ") {
                    if alias.trim().trim_end_matches(';').contains("secret") {
                        offenders.push(format!(
                            "{relative}:{line_number}: aliased re-export with a secret \
                             name cannot be audited: {line}"
                        ));
                    }
                }
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
    // Pins the exception the checks rely on: the marker is a literal
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

#[test]
fn the_allowlisted_label_helper_never_returns_secret_material() {
    // The allowlist is only honest if the function it names really returns
    // redacted labels. Build a module whose binding name contains a copy of the
    // secret and check the reported labels.
    use active_infinity::{AnnotationKind, InfinityModule, Inode, SecretBytes};

    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from("hunter2-secret")));
    let leaf = module.push(Inode::Int(7));
    let root = module.push(Inode::Table {
        fields: vec![("s".into(), secret), ("n".into(), leaf)],
    });
    module.set_root(Some(root));
    module.bind("binding hunter2-secret", leaf);
    module.annotate(leaf, AnnotationKind::Intent("note".into()));

    let paths = active_infinity::interop::secret_tainted_paths(&module);
    assert!(!paths.is_empty(), "the tainted cone must be reported");
    for label in &paths {
        assert!(
            !label.contains("hunter2-secret"),
            "the allowlisted helper leaked a secret copy: {label}"
        );
    }
}
