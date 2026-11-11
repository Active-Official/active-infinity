//! Regression tests for INF-MERGE-01: the three-way merge is root-field
//! granular only — two sides editing disjoint leaves of the same nested
//! table conflict (`Conflicts([server ModifyModify])`) instead of merging,
//! even though neither side touched the other's leaf.
//!
//! The audit probe is `probe_merge_nested_disjoint_edits` (round-1 report
//! §B.8): base `{server:{port:1,host:"a"}}`, left `port=2`, right
//! `host="b"` → `Conflicts([server ModifyModify])` at HEAD. The fix makes
//! `decide` recursive: a both-changed table field is settled per nested
//! field (reusing `decide` + `import_subtree`), falling back to the
//! whole-field conflict only when a nested field itself conflicts, when
//! the shapes differ, or when the `MAX_CONFLICT_DEPTH` recursion bound is
//! reached.
//!
//! Fail-before / pass-after, per test, at HEAD `1186776` (INF-L13):
//!
//! * Tests 1–7, 13, 14 expect a clean merge and FAIL at HEAD (the merge
//!   returns `Conflicts`); they pass after the fix. Test 1 is the audit
//!   probe verbatim, plus the value assertions the probe does not make.
//! * Tests 8–12 expect a conflict and PASS at HEAD as well as after the
//!   fix — they pin the fallback: a nested field both sides changed
//!   differently still conflicts, reported at its dotted leaf path, and
//!   a shape change or a secret still conflicts at the parent.
//! * Test 15 pins the recursion bound: a disjoint edit deeper than
//!   `MAX_CONFLICT_DEPTH` (64) still conflicts, fail-closed, and the
//!   merge terminates — it returns `Conflicts`, it does not hang or
//!   recurse without bound. It passes at HEAD as well as after the fix
//!   (the bound and the reporting cap are unchanged by the fix); what it
//!   pins is that the new recursion respects the same bound.

use active_infinity::{
    content_hash, decode, encode, merge, ConflictKind, InfinityModule, Inode, Merge,
};

/// A tiny nested-module spec, so tests read as the modules they build.
enum Spec<'a> {
    Int(i64),
    Str(&'a str),
    Bool(bool),
    Table(Vec<(&'a str, Spec<'a>)>),
}

fn push_spec(module: &mut InfinityModule, spec: &Spec<'_>) -> active_infinity::NodeId {
    match spec {
        Spec::Int(value) => module.push(Inode::Int(*value)),
        Spec::Str(text) => module.push(Inode::Str((*text).into())),
        Spec::Bool(flag) => module.push(Inode::Bool(*flag)),
        Spec::Table(fields) => {
            let inner: Vec<(String, active_infinity::NodeId)> = fields
                .iter()
                .map(|(name, child)| ((*name).to_string(), push_spec(module, child)))
                .collect();
            module.push(Inode::Table { fields: inner })
        }
    }
}

/// A module whose root is a table built from `spec`.
fn build(spec: &[(&str, Spec<'_>)]) -> InfinityModule {
    let mut module = InfinityModule::new();
    let fields: Vec<(String, active_infinity::NodeId)> = spec
        .iter()
        .map(|(name, child)| ((*name).to_string(), push_spec(&mut module, child)))
        .collect();
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));
    module
}

/// The audit probe's shape: `{server:{port, host}}`.
fn server(port: i64, host: &str) -> InfinityModule {
    build(&[(
        "server",
        Spec::Table(vec![("port", Spec::Int(port)), ("host", Spec::Str(host))]),
    )])
}

fn node_at(module: &InfinityModule, path: &[&str]) -> active_infinity::NodeId {
    assert!(!path.is_empty(), "a path names at least one field");
    let mut current = module.root().expect("root");
    for name in path {
        let Inode::Table { fields } = module.get(current).expect("node") else {
            panic!("{name}: its parent is not a table");
        };
        current = fields
            .iter()
            .find(|(field, _)| field == name)
            .unwrap_or_else(|| panic!("missing field {name}"))
            .1;
    }
    current
}

fn int_at(module: &InfinityModule, path: &[&str]) -> i64 {
    match module.get(node_at(module, path)) {
        Some(Inode::Int(value)) => *value,
        other => panic!("{} is not an int: {other:?}", path.join(".")),
    }
}

fn str_at(module: &InfinityModule, path: &[&str]) -> String {
    match module.get(node_at(module, path)) {
        Some(Inode::Str(value)) => value.clone(),
        other => panic!("{} is not a string: {other:?}", path.join(".")),
    }
}

fn bool_at(module: &InfinityModule, path: &[&str]) -> bool {
    match module.get(node_at(module, path)) {
        Some(Inode::Bool(value)) => *value,
        other => panic!("{} is not a bool: {other:?}", path.join(".")),
    }
}

fn has_path(module: &InfinityModule, path: &[&str]) -> bool {
    let mut current = match module.root() {
        Some(root) => root,
        None => return false,
    };
    for name in path {
        let Some(Inode::Table { fields }) = module.get(current) else {
            return false;
        };
        match fields.iter().find(|(field, _)| field == name) {
            Some((_, id)) => current = *id,
            None => return false,
        }
    }
    true
}

fn clean(result: Merge) -> InfinityModule {
    match result.into_module() {
        Some(module) => module,
        None => panic!("unexpected conflicts"),
    }
}

fn conflicts(result: Merge) -> Vec<active_infinity::Conflict> {
    match result {
        Merge::Conflicts(conflicts) => conflicts,
        Merge::Clean(_) => panic!("expected conflicts"),
    }
}

/// The merged module is canonical: encode, decode, re-encode, same hash.
fn assert_canonical(module: &InfinityModule) {
    let image = encode(module).expect("encode the merged module");
    let decoded = decode(&image).expect("decode the merged module");
    assert_eq!(
        content_hash(&image).expect("hash"),
        content_hash(&encode(&decoded).expect("re-encode")).expect("hash again"),
        "the merged module is canonical and stable"
    );
}

#[test]
fn disjoint_nested_edits_merge_clean() {
    // The audit probe verbatim: base {server:{port:1,host:"a"}}, left
    // port=2, right host="b". At HEAD this is Conflicts([server
    // ModifyModify]); after the fix it is Clean with both edits.
    let base = server(1, "a");
    let left = server(2, "a");
    let right = server(1, "b");
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(int_at(&merged, &["server", "port"]), 2);
    assert_eq!(str_at(&merged, &["server", "host"]), "b");
    // Root table + server table + Int + Str: nothing duplicated, nothing
    // dropped.
    assert_eq!(merged.node_count(), 4);
    assert_canonical(&merged);
}

#[test]
fn disjoint_nested_edits_merge_clean_two_levels_deep() {
    // The same disjoint edit one level deeper: config.server.port on the
    // left, config.server.host on the right.
    let mk = |port: i64, host: &str| {
        build(&[(
            "config",
            Spec::Table(vec![(
                "server",
                Spec::Table(vec![("port", Spec::Int(port)), ("host", Spec::Str(host))]),
            )]),
        )])
    };
    let merged = clean(merge(&mk(1, "a"), &mk(2, "a"), &mk(1, "b")).expect("merge"));
    assert_eq!(int_at(&merged, &["config", "server", "port"]), 2);
    assert_eq!(str_at(&merged, &["config", "server", "host"]), "b");
    assert_canonical(&merged);
}

#[test]
fn disjoint_edits_inside_a_nested_table_merge_clean() {
    // Recursion descends through a table-valued nested field:
    // server.tls.enabled on the left, server.tls.version on the right.
    let mk = |enabled: bool, version: i64| {
        build(&[(
            "server",
            Spec::Table(vec![
                ("port", Spec::Int(80)),
                (
                    "tls",
                    Spec::Table(vec![
                        ("enabled", Spec::Bool(enabled)),
                        ("version", Spec::Int(version)),
                    ]),
                ),
            ]),
        )])
    };
    let merged = clean(merge(&mk(true, 1), &mk(false, 1), &mk(true, 2)).expect("merge"));
    assert!(!bool_at(&merged, &["server", "tls", "enabled"]));
    assert_eq!(int_at(&merged, &["server", "tls", "version"]), 2);
    assert_eq!(int_at(&merged, &["server", "port"]), 80);
    assert_canonical(&merged);
}

#[test]
fn a_nested_add_on_one_side_merges_with_the_other_sides_edit() {
    // Left adds server.tls, right changes server.port: the nested add is
    // kept (the right side never touched tls) and the port change is
    // imported from the right.
    let base = build(&[("server", Spec::Table(vec![("port", Spec::Int(80))]))]);
    let left = build(&[(
        "server",
        Spec::Table(vec![("port", Spec::Int(80)), ("tls", Spec::Bool(true))]),
    )]);
    let right = build(&[("server", Spec::Table(vec![("port", Spec::Int(8080))]))]);
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(int_at(&merged, &["server", "port"]), 8080);
    assert!(bool_at(&merged, &["server", "tls"]));
    assert_canonical(&merged);
}

#[test]
fn a_nested_delete_on_one_side_merges_with_the_other_sides_edit() {
    // Left deletes server.tls, right changes server.port: the delete
    // stands (the right side left tls alone) and the port change lands.
    let base = build(&[(
        "server",
        Spec::Table(vec![("port", Spec::Int(80)), ("tls", Spec::Bool(true))]),
    )]);
    let left = build(&[("server", Spec::Table(vec![("port", Spec::Int(80))]))]);
    let right = build(&[(
        "server",
        Spec::Table(vec![("port", Spec::Int(8080)), ("tls", Spec::Bool(true))]),
    )]);
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(int_at(&merged, &["server", "port"]), 8080);
    assert!(!has_path(&merged, &["server", "tls"]), "tls stays deleted");
    assert_canonical(&merged);
}

#[test]
fn a_nested_field_replaced_by_a_table_on_one_side_merges() {
    // The right side replaces server.host (a string) with a whole table
    // {name, ip} while the left side changes server.port: the nested
    // TakeRight imports the table subtree.
    let base = server(1, "a");
    let left = server(2, "a");
    let right = build(&[(
        "server",
        Spec::Table(vec![
            ("port", Spec::Int(1)),
            (
                "host",
                Spec::Table(vec![
                    ("name", Spec::Str("edge")),
                    ("ip", Spec::Str("10.0.0.1")),
                ]),
            ),
        ]),
    )]);
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(int_at(&merged, &["server", "port"]), 2);
    assert_eq!(str_at(&merged, &["server", "host", "name"]), "edge");
    assert_eq!(str_at(&merged, &["server", "host", "ip"]), "10.0.0.1");
    assert_canonical(&merged);
}

#[test]
fn both_sides_add_disjoint_fields_of_a_new_table_merge_clean() {
    // The base has no server at all; each side adds it with a different
    // leaf. The same per-field mechanism settles the AddAdd case: the
    // added table is the union of the two disjoint additions.
    let base = build(&[("app", Spec::Int(1))]);
    let left = build(&[
        ("app", Spec::Int(1)),
        ("server", Spec::Table(vec![("port", Spec::Int(2))])),
    ]);
    let right = build(&[
        ("app", Spec::Int(1)),
        ("server", Spec::Table(vec![("host", Spec::Str("b"))])),
    ]);
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(int_at(&merged, &["server", "port"]), 2);
    assert_eq!(str_at(&merged, &["server", "host"]), "b");
    assert_eq!(int_at(&merged, &["app"]), 1);
    assert_canonical(&merged);
}

#[test]
fn nested_same_leaf_changed_differently_still_conflicts() {
    // Both sides changed the same nested leaf differently: the nested
    // merge fails at that leaf, and the report names it, not the table.
    let base = server(1, "a");
    let left = server(2, "a");
    let right = server(3, "a");
    let found = conflicts(merge(&base, &left, &right).expect("merge"));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].field, "server.port");
    assert_eq!(found[0].kind, ConflictKind::ModifyModify);
}

#[test]
fn nested_same_leaf_added_differently_still_conflicts() {
    // Both sides added the same nested leaf with different values.
    let base = build(&[("server", Spec::Table(vec![("port", Spec::Int(80))]))]);
    let left = build(&[(
        "server",
        Spec::Table(vec![("port", Spec::Int(80)), ("tls", Spec::Bool(true))]),
    )]);
    let right = build(&[(
        "server",
        Spec::Table(vec![("port", Spec::Int(80)), ("tls", Spec::Bool(false))]),
    )]);
    let found = conflicts(merge(&base, &left, &right).expect("merge"));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].field, "server.tls");
    assert_eq!(found[0].kind, ConflictKind::AddAdd);
}

#[test]
fn nested_delete_versus_modify_still_conflicts() {
    // Left deletes a nested leaf the right side modified.
    let base = build(&[(
        "server",
        Spec::Table(vec![("port", Spec::Int(80)), ("tls", Spec::Bool(true))]),
    )]);
    let left = build(&[("server", Spec::Table(vec![("port", Spec::Int(80))]))]);
    let right = build(&[(
        "server",
        Spec::Table(vec![("port", Spec::Int(80)), ("tls", Spec::Bool(false))]),
    )]);
    let found = conflicts(merge(&base, &left, &right).expect("merge"));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].field, "server.tls");
    assert_eq!(found[0].kind, ConflictKind::DeleteModify);
}

#[test]
fn nested_shape_change_still_conflicts_at_the_parent() {
    // The base says server is an integer while both sides turned it into
    // a table: the shape changed, so the recursion never descends and
    // the conflict belongs to server, not to server.port.
    let base = build(&[("server", Spec::Int(1))]);
    let left = server(8080, "a");
    let right = server(9090, "a");
    let found = conflicts(merge(&base, &left, &right).expect("merge"));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].field, "server");
    assert_eq!(found[0].kind, ConflictKind::ModifyModify);
}

#[test]
fn a_secret_inside_a_nested_table_still_conflicts_at_the_parent() {
    // A secret anywhere in either side's subtree is never walked into:
    // the merge conflicts at the table, and the outcome says nothing
    // about whether the secrets match.
    use active_infinity::SecretBytes;

    // The Spec builder cannot express a secret, so build these by hand.
    let mk = |value: &[u8]| {
        let mut module = InfinityModule::new();
        let secret = module.push(Inode::Secret(SecretBytes::new(value.to_vec())));
        let inner = module.push(Inode::Table {
            fields: vec![("token".to_string(), secret)],
        });
        let root = module.push(Inode::Table {
            fields: vec![("server".to_string(), inner)],
        });
        module.set_root(Some(root));
        module
    };
    let found = conflicts(merge(&mk(b"plain"), &mk(b"a"), &mk(b"b")).expect("merge"));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].field, "server");
    assert_eq!(found[0].kind, ConflictKind::ModifyModify);
}

#[test]
fn nested_merge_result_is_canonical_and_stable() {
    // Three nested leaves: each side touches a different one, the third
    // is untouched — all three survive, and the result is canonical.
    let mk = |port: i64, host: &str| {
        build(&[(
            "server",
            Spec::Table(vec![
                ("port", Spec::Int(port)),
                ("host", Spec::Str(host)),
                ("mode", Spec::Str("fast")),
            ]),
        )])
    };
    let merged = clean(merge(&mk(1, "a"), &mk(2, "a"), &mk(1, "b")).expect("merge"));
    assert_eq!(int_at(&merged, &["server", "port"]), 2);
    assert_eq!(str_at(&merged, &["server", "host"]), "b");
    assert_eq!(str_at(&merged, &["server", "mode"]), "fast");
    assert_canonical(&merged);
}

#[test]
fn three_nested_fields_each_side_touches_a_different_one() {
    // A wider disjoint edit: left changes port, right changes host, and
    // a second root field changes on the left at the same time, so the
    // nested merge and the root merge compose.
    let mk = |port: i64, host: &str, app: i64| {
        build(&[
            ("app", Spec::Int(app)),
            (
                "server",
                Spec::Table(vec![
                    ("port", Spec::Int(port)),
                    ("host", Spec::Str(host)),
                    ("mode", Spec::Str("fast")),
                ]),
            ),
        ])
    };
    let merged = clean(merge(&mk(1, "a", 1), &mk(2, "a", 9), &mk(1, "b", 1)).expect("merge"));
    assert_eq!(int_at(&merged, &["app"]), 9);
    assert_eq!(int_at(&merged, &["server", "port"]), 2);
    assert_eq!(str_at(&merged, &["server", "host"]), "b");
    assert_eq!(str_at(&merged, &["server", "mode"]), "fast");
    assert_canonical(&merged);
}

/// A chain of single-field tables `n0 -> n1 -> ... -> n69`, the deepest
/// holding two leaves `x` and `y`. The left side changes `x`, the right
/// side changes `y` — a disjoint edit 70 levels down, past the
/// `MAX_CONFLICT_DEPTH` (64) recursion bound.
fn deep_chain(x: i64, y: i64) -> InfinityModule {
    fn table(module: &mut InfinityModule, depth: usize, x: i64, y: i64) -> active_infinity::NodeId {
        if depth == 70 {
            let x_node = module.push(Inode::Int(x));
            let y_node = module.push(Inode::Int(y));
            return module.push(Inode::Table {
                fields: vec![("x".to_string(), x_node), ("y".to_string(), y_node)],
            });
        }
        let child = table(module, depth + 1, x, y);
        module.push(Inode::Table {
            fields: vec![(format!("n{depth}"), child)],
        })
    }
    let mut module = InfinityModule::new();
    let root = table(&mut module, 0, x, y);
    module.set_root(Some(root));
    module
}

#[test]
fn a_disjoint_edit_past_the_recursion_bound_still_conflicts() {
    // The recursion bound is the fail-closed edge of the fix: below it a
    // disjoint edit merges, past it the merge refuses rather than
    // recursing without bound. The report names the deepest path the
    // reporting walk reaches — n0 through n64, 65 segments — and the
    // merge terminates with exactly that one conflict.
    let found =
        conflicts(merge(&deep_chain(1, 1), &deep_chain(2, 1), &deep_chain(1, 2)).expect("merge"));
    assert_eq!(found.len(), 1, "{found:?}");
    let expected: Vec<String> = (0..=64).map(|i| format!("n{i}")).collect();
    assert_eq!(found[0].field, expected.join("."));
    assert_eq!(found[0].kind, ConflictKind::ModifyModify);
}
