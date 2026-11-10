//! Regression tests for INF-INTEROP-07: `resolve_path` splits on `'.'` with
//! no unescaping; non-strict `provenance_json` returns `Null` on budget
//! exhaustion.
//!
//! The audit (`AUDIT-REPORT.md`, at 6aad041) found two things in
//! `src/interop.rs`:
//!
//! 1. `resolve_path` splits the path on `'.'` with no unescaping, so a field
//!    name containing a literal `.` -- which `merge.rs` escapes as `\.` in
//!    conflict paths (`escape_field`, `src/merge.rs:830`) -- can never be
//!    resolved. CONFIRMED by W4 (code read).
//! 2. `provenance_json` returns `Value::Null` when the redaction budget is
//!    spent, indistinguishable from "no provenance".
//!
//! Part 1 reproduces exactly as audited. Part 2 does NOT reproduce as
//! stated, at 6aad041 or at HEAD 6d9120b: `provenance_json_with` ends the
//! entry list on a spent budget (`break`, `src/interop.rs`) and only returns
//! `None` on a redacted-key collision, which the non-strict call disables
//! (`strict_collisions = false`). The `None => Value::Null` arm in
//! `provenance_json` is therefore unreachable today -- budget exhaustion
//! truncates the entry list and saturates values to the marker, it never
//! yields `Null`. The tests below pin the true behaviour instead of the
//! audited one, and the rustdoc now states it. What IS real, and is
//! documented by the fix:
//!
//! - `provenance_json` is lossy on budget exhaustion (silent entry-list
//!   truncation + value saturation), with no marker that anything was
//!   dropped. See the rustdoc; it cross-references the canonical loss table
//!   in `to_redacted_json` rather than duplicating it.
//! - `provenance_json_for` returns `None` for two different reasons -- the
//!   module carries no provenance, or the projection was refused (a
//!   redacted-key collision) -- which the return value alone cannot tell
//!   apart. `provenance_json` never returns `Null` for either reason: a
//!   collision keeps the first entry there.
//!
//! Design decisions (full evidence in `records/F2-INF/INF-INTEROP-07.md`):
//!
//! - The escaping convention is `merge.rs::escape_field`, the single
//!   canonical escaper: `\` becomes `\\`, `.` becomes `\.`, a leading `<`
//!   becomes `\<`. `resolve_path` implements its exact inverse. The merge
//!   round-trip tests below prove the inverse against the real escaper, not
//!   against a copy of it.
//! - Unescaping is lenient: a `\` before any other character, and a
//!   dangling trailing `\`, stay literal. That keeps every path that
//!   contains no escape sequence resolving exactly as before; the only
//!   behaviour change is for spellings the documented convention already
//!   assigns to an escaped field name.
//! - The binding fallback is now driven by the parsed segment count (one
//!   segment), not by the raw text containing `'.'`, so a binding whose
//!   name contains a literal `.` resolves via its escaped spelling.
//! - `value_paths` does NOT escape (it joins raw keys with `.`), so its
//!   output is not round-trippable through `resolve_path` for dotted field
//!   names. That is a separate pre-existing gap, out of scope here: changing
//!   `value_paths` would change every `impact` / `why` / `node_label`
//!   string. It is recorded as a new finding in the fix record, not fixed.

use active_infinity::interop::resolve_path;
use active_infinity::{
    merge, ConflictKind, InfinityModule, Inode, Merge, NodeId, ProvEntry, ProvValue, Provenance,
    SecretBytes,
};

#[cfg(feature = "json")]
use active_infinity::interop::{provenance_json, provenance_json_for, SECRET_MARKER};

/// Root table with the given `(name, value)` int fields; returns the module
/// and the leaf ids in field order.
fn int_table(fields: &[(&str, i64)]) -> (InfinityModule, Vec<NodeId>) {
    let mut module = InfinityModule::new();
    let mut nodes = Vec::new();
    for (name, value) in fields {
        let id = module.push(Inode::Int(*value));
        nodes.push(((*name).to_string(), id));
    }
    let ids: Vec<NodeId> = nodes.iter().map(|(_, id)| *id).collect();
    let root = module.push(Inode::Table { fields: nodes });
    module.set_root(Some(root));
    (module, ids)
}

/// Root `{"srv": {"a.b": value}}`; returns the module and the leaf id.
fn nested_dotted(value: i64) -> (InfinityModule, NodeId) {
    let mut module = InfinityModule::new();
    let leaf = module.push(Inode::Int(value));
    let inner = module.push(Inode::Table {
        fields: vec![("a.b".to_string(), leaf)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("srv".to_string(), inner)],
    });
    module.set_root(Some(root));
    (module, leaf)
}

fn conflicts(result: Merge) -> Vec<active_infinity::Conflict> {
    match result {
        Merge::Clean(_) => panic!("expected conflicts"),
        Merge::Conflicts(conflicts) => conflicts,
    }
}

/// A field name containing a literal `.` resolves via the escaped path, and
/// the unescaped spelling is two segments that match nothing here.
#[test]
fn a_field_name_with_a_literal_dot_resolves_via_the_escaped_path() {
    let (module, leaves) = int_table(&[("a.b", 7)]);
    assert_eq!(resolve_path(&module, "a\\.b"), Some(leaves[0]));
    assert_eq!(resolve_path(&module, "a.b"), None);
    assert!(matches!(module.get(leaves[0]), Some(Inode::Int(7))));
}

/// The merge escaper and the resolver are inverses: a real merge conflict on
/// a dotted field names it `a\.b`, and that exact string resolves in the
/// base module.
#[test]
fn a_merge_conflict_path_round_trips_through_resolve_path() {
    let (base, base_leaves) = int_table(&[("a.b", 1)]);
    let (left, _) = int_table(&[("a.b", 2)]);
    let (right, _) = int_table(&[("a.b", 3)]);
    let found = conflicts(merge(&base, &left, &right).expect("merge"));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].field, "a\\.b");
    assert_eq!(found[0].kind, ConflictKind::ModifyModify);
    assert_eq!(
        resolve_path(&base, &found[0].field),
        Some(base_leaves[0]),
        "the conflict path must resolve in the module it names"
    );
}

/// Same round-trip one level down: the conflict path is `srv.a\.b`.
#[test]
fn a_nested_merge_conflict_path_round_trips_through_resolve_path() {
    let (base, base_leaf) = nested_dotted(1);
    let (left, _) = nested_dotted(2);
    let (right, _) = nested_dotted(3);
    let found = conflicts(merge(&base, &left, &right).expect("merge"));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].field, "srv.a\\.b");
    assert_eq!(found[0].kind, ConflictKind::ModifyModify);
    assert_eq!(
        resolve_path(&base, &found[0].field),
        Some(base_leaf),
        "the nested conflict path must resolve in the module it names"
    );
}

/// A field name containing a literal `\` resolves via its escaped spelling
/// (`\\`), and the raw spelling keeps working: a backslash before any other
/// character is literal, so no existing path changes meaning.
#[test]
fn a_field_name_with_a_literal_backslash_resolves() {
    let (module, leaves) = int_table(&[("a\\b", 1)]);
    assert_eq!(resolve_path(&module, "a\\\\b"), Some(leaves[0]));
    assert_eq!(resolve_path(&module, "a\\b"), Some(leaves[0]));
}

/// A `\` before a `.` is not misread: the name `a\.b` (backslash, then dot)
/// escapes to `a\\\.b` and resolves to exactly that field -- never to a
/// field named `a.b`, and never as two segments.
#[test]
fn a_backslash_before_a_dot_is_not_misread() {
    let (module, leaves) = int_table(&[("a\\.b", 1)]);
    assert_eq!(resolve_path(&module, "a\\\\\\.b"), Some(leaves[0]));
    let (other, _) = int_table(&[("a.b", 2)]);
    assert_eq!(resolve_path(&other, "a\\\\\\.b"), None);
}

/// A dangling trailing `\` is a literal backslash, not an error: a field
/// named `a\` resolves via the path `a\`, exactly as it did before the fix.
#[test]
fn a_dangling_trailing_backslash_is_a_literal_backslash() {
    let (module, leaves) = int_table(&[("a\\", 1)]);
    assert_eq!(resolve_path(&module, "a\\"), Some(leaves[0]));
    assert_eq!(resolve_path(&module, "zz\\"), None);
}

/// Empty segments resolve only when empty-named fields exist: `.` names the
/// nested empty field, `""` names the root's empty field, and on an ordinary
/// module `.`, `""` and `a..b` are all `None`.
#[test]
fn empty_segments_resolve_only_when_empty_fields_exist() {
    let mut module = InfinityModule::new();
    let leaf = module.push(Inode::Int(1));
    let inner = module.push(Inode::Table {
        fields: vec![(String::new(), leaf)],
    });
    let root = module.push(Inode::Table {
        fields: vec![(String::new(), inner)],
    });
    module.set_root(Some(root));
    assert_eq!(resolve_path(&module, "."), Some(leaf));
    assert_eq!(resolve_path(&module, ""), Some(inner));

    let (plain, _) = int_table(&[("a", 1)]);
    assert_eq!(resolve_path(&plain, "."), None);
    assert_eq!(resolve_path(&plain, ""), None);
    assert_eq!(resolve_path(&plain, "a..b"), None);
}

/// A binding whose name contains a literal `.` resolves via its escaped
/// spelling: the binding fallback is driven by the parsed segment count, not
/// by whether the raw text contains a dot.
#[test]
fn a_binding_whose_name_contains_a_dot_resolves_via_the_escaped_path() {
    let mut module = InfinityModule::new();
    let leaf = module.push(Inode::Int(9));
    module.set_root(Some(leaf));
    module.bind("a.b", leaf);
    assert_eq!(resolve_path(&module, "a\\.b"), Some(leaf));
    // The unescaped spelling is two segments, so it is not a binding lookup.
    assert_eq!(resolve_path(&module, "a.b"), None);
}

/// `merge.rs` escapes a leading `<` (`\<`) because `<bindings>` and friends
/// are merge markers, not fields; the resolver reverses that rule too. A
/// field that literally starts with `\<` escapes to `\\<` and still resolves.
#[test]
fn a_leading_angle_bracket_field_resolves_via_the_escaped_path() {
    let (module, leaves) = int_table(&[("<x", 1), ("\\<x", 2)]);
    assert_eq!(resolve_path(&module, "\\<x"), Some(leaves[0]));
    assert_eq!(resolve_path(&module, "\\\\<x"), Some(leaves[1]));
}

/// Plain paths are unchanged: dotted table descent, single-segment bindings,
/// and `None` for anything missing.
#[test]
fn plain_paths_are_unchanged() {
    let mut module = InfinityModule::new();
    let port = module.push(Inode::Int(8080));
    let server = module.push(Inode::Table {
        fields: vec![("port".to_string(), port)],
    });
    // The root contains the server table; it does not *is* it -- `server.port`
    // descends root -> `server` -> `port`, as in `integration_tests`.
    let root = module.push(Inode::Table {
        fields: vec![("server".to_string(), server)],
    });
    module.set_root(Some(root));
    module.bind("cfg", server);
    assert_eq!(resolve_path(&module, "server.port"), Some(port));
    assert_eq!(resolve_path(&module, "server"), Some(server));
    // The server table is also named through its binding.
    assert_eq!(resolve_path(&module, "cfg"), Some(server));
    assert_eq!(resolve_path(&module, "server.missing"), None);
    assert_eq!(resolve_path(&module, "missing"), None);
}

/// A secret-bearing module with `count` secrets and a root `Int(0)`.
/// (Same shape as `marathon_export_budget_tests.rs`.)
#[cfg(feature = "json")]
fn many_secrets(count: usize) -> InfinityModule {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(0));
    module.set_root(Some(root));
    for index in 0..count {
        module.push(Inode::Secret(SecretBytes::from(format!(
            "SECRET{index:05}"
        ))));
    }
    module
}

/// A module whose provenance has a redacted-key collision: the keys
/// `hunter2` (a secret literal) and `***SECRET***` redact to one key.
/// (Same fixture as `marathon_export_budget_tests.rs`.)
#[cfg(feature = "json")]
fn collision_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from("hunter2")));
    module.set_root(Some(secret));
    module.set_provenance(Some(Provenance {
        entries: vec![
            ProvEntry {
                key: "hunter2".into(),
                value: ProvValue::Text("first".into()),
            },
            ProvEntry {
                key: "***SECRET***".into(),
                value: ProvValue::Text("second".into()),
            },
        ],
        ..Provenance::default()
    }));
    module
}

/// Budget exhaustion truncates, it never yields `Null`: the 4096-byte entry
/// value spends the shared 64 MiB budget against 3000 secrets, so its value
/// saturates to the marker and the entry list ends there -- but the result
/// is still an object. The strict entry point truncates identically:
/// exhaustion is not a refusal, only a collision is.
#[cfg(feature = "json")]
#[test]
fn provenance_json_never_returns_null_on_budget_exhaustion() {
    let mut module = many_secrets(3000);
    module.set_provenance(Some(Provenance {
        entries: vec![
            ProvEntry {
                key: "first".into(),
                value: ProvValue::Text("z".repeat(4096)),
            },
            ProvEntry {
                key: "second".into(),
                value: ProvValue::Int(2),
            },
            ProvEntry {
                key: "third".into(),
                value: ProvValue::Int(3),
            },
        ],
        ..Provenance::default()
    }));
    let secrets: Vec<String> = (0..3000).map(|index| format!("SECRET{index:05}")).collect();
    let prov = module.provenance().expect("provenance");
    let json = provenance_json(prov, &secrets);
    assert!(
        json.is_object(),
        "budget exhaustion must truncate, never Null: {json}"
    );
    let entries = json["entries"].as_object().expect("entries object");
    assert_eq!(
        entries.len(),
        1,
        "later entries are dropped once the budget is spent: {json}"
    );
    assert_eq!(
        entries["first"],
        serde_json::Value::from(SECRET_MARKER),
        "the value that spends the budget saturates to the marker: {json}"
    );
    assert!(!entries.contains_key("second"));
    assert!(!entries.contains_key("third"));
    assert_eq!(
        provenance_json_for(&module).as_ref(),
        Some(&json),
        "the strict entry point truncates identically on exhaustion"
    );
}

/// A redacted-key collision keeps the first entry in the lenient projection
/// -- never `Null` -- while the strict entry point refuses the same input.
/// That refusal, not budget exhaustion, is where the two entry points differ.
#[cfg(feature = "json")]
#[test]
fn provenance_json_keeps_the_first_entry_on_a_redacted_key_collision() {
    let module = collision_module();
    let json = provenance_json(
        module.provenance().expect("provenance"),
        &["hunter2".to_string()],
    );
    assert!(
        json.is_object(),
        "a collision keeps the first entry, never Null: {json}"
    );
    assert_eq!(
        json["entries"]["***SECRET***"],
        serde_json::Value::from("second"),
        "the first entry in raw-key order wins, as in `provenance_lines`: {json}"
    );
    assert!(
        provenance_json_for(&module).is_none(),
        "the strict entry point must refuse the collision"
    );
}

/// `provenance_json_for` returns `None` for two different reasons -- the
/// module carries no provenance, or the projection was refused -- and the
/// return value alone cannot tell them apart. The discriminator is
/// `module.provenance()`: `None` there means absence, `Some` means refusal.
#[cfg(feature = "json")]
#[test]
fn provenance_json_for_conflates_no_provenance_with_a_refused_projection() {
    let bare = InfinityModule::new();
    assert!(provenance_json_for(&bare).is_none());
    assert!(bare.provenance().is_none());

    let module = collision_module();
    assert!(
        provenance_json_for(&module).is_none(),
        "the same None, for a different reason"
    );
    assert!(
        module.provenance().is_some(),
        "the None here is a refusal, not an absence"
    );
}
