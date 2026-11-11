//! Regression tests for INF-MERGE-03: a left annotation survives on a stale
//! node when TakeRight replaces its subject (annotation ghost).
//!
//! The merged module starts as `left.clone()`; a `TakeRight` decision
//! replaces the annotated node's field slot with an imported copy, but the
//! annotation still points at the old left node id, which stays in the
//! arena, and `import_subtree` copies nodes only, never annotations. At
//! final `encode()`, canonical ordering treats annotation subjects as
//! roots, so the stale pre-change subtree is retained alongside the new
//! value. The audit probe is `probe_merge_annotation_ghost` (round-1
//! report §B.8): `CLEAN, nodes=5, Int10_count=2, annotations=1` — two
//! `Int(10)` nodes, the stale annotated one and the imported one.
//!
//! The fix remaps annotations (and bindings — NF-MERGE01-01, the binding
//! twin of this finding, and R2-INF-MRG-02, the nested binding ghost)
//! whose subject was replaced by an import onto the corresponding imported
//! node, and drops the ones whose subject has no counterpart in the
//! imported subtree. The remap follows the same logical field: a node is
//! repointed only when the imported subtree holds the node at the same
//! structural position, and only when the old node does not survive
//! somewhere else in the merged module.
//!
//! Fail-before / pass-after, per test, at HEAD `0aa47ed` (INF-MERGE-02):
//!
//! * Tests 1–6, 9, 10, 12–14 expect a clean merge with the annotation or
//!   binding following the replaced node, and FAIL at HEAD (the stale node
//!   survives, or the binding still resolves to the stale value); they
//!   pass after the fix. Test 1 is the audit probe verbatim, plus the
//!   value assertions the probe does not make.
//! * Test 7 pins the drop side on a rename: the annotated node has no
//!   counterpart under its old name in the imported subtree, so the
//!   annotation is dropped rather than ghosted. It FAILS at HEAD (the
//!   annotation survives on the stale node).
//! * Test 8 pins the live-node guard: an annotation on a node that
//!   survives through another field is NOT repointed. It passes at HEAD
//!   as well as after the fix — what it pins is that the remap does not
//!   move metadata that still has a live home.
//! * Test 11 pins the sweep's no-op guard: a clean merge that replaces
//!   nothing drops nothing. It passes at HEAD as well as after the fix.
//! * Tests 12 and 13 pin the drop side on a delete: an annotation on a
//!   node the right side deleted has no home in the merged module, so it
//!   is dropped rather than ghosted. They FAIL at HEAD (the annotation
//!   survives on the stale node).
//! * Tests 15 and 16 pin the same drop side for *bindings*: a binding
//!   names its target as a root, so a binding left pointing at an
//!   orphaned node would ghost the stale value back just as an
//!   annotation does. They FAIL on the fix as first written (which
//!   repointed bindings but never dropped them) and pass once the
//!   post-pass drops orphaned binding targets.
//! * Test 17 pins the constraint-expression drop: a Constraint whose
//!   expression names a deleted node is dropped whole, even though its
//!   subject survives — the expression has no home in the merged
//!   module. It passes on the fix as first written (the annotation
//!   filter already dropped it); it FAILS at HEAD.

use active_infinity::{
    content_hash, decode, encode, merge, Annotation, AnnotationKind, InfinityModule, Inode, Merge,
    NodeId,
};

/// A tiny nested-module spec, so tests read as the modules they build.
enum Spec<'a> {
    Int(i64),
    Table(Vec<(&'a str, Spec<'a>)>),
}

fn push_spec(module: &mut InfinityModule, spec: &Spec<'_>) -> NodeId {
    match spec {
        Spec::Int(value) => module.push(Inode::Int(*value)),
        Spec::Table(fields) => {
            let inner: Vec<(String, NodeId)> = fields
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
    let fields: Vec<(String, NodeId)> = spec
        .iter()
        .map(|(name, child)| ((*name).to_string(), push_spec(&mut module, child)))
        .collect();
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));
    module
}

fn node_at(module: &InfinityModule, path: &[&str]) -> NodeId {
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

fn count_int(module: &InfinityModule, value: i64) -> usize {
    module
        .nodes()
        .iter()
        .filter(|node| matches!(node, Inode::Int(found) if *found == value))
        .count()
}

fn binding_target(module: &InfinityModule, name: &str) -> Option<NodeId> {
    module
        .bindings()
        .iter()
        .find(|(bound, _)| bound == name)
        .map(|(_, id)| *id)
}

fn intent_annotation<'a>(module: &'a InfinityModule, text: &str) -> Option<&'a Annotation> {
    module.annotations().iter().find(
        |annotation| matches!(&annotation.kind, AnnotationKind::Intent(found) if found == text),
    )
}

fn clean(result: Merge) -> InfinityModule {
    match result.into_module() {
        Some(module) => module,
        None => panic!("unexpected conflicts"),
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

/// Annotate the node at `path` in `module`.
fn annotate_at(module: &mut InfinityModule, path: &[&str], kind: AnnotationKind) {
    let id = node_at(module, path);
    module.annotate(id, kind);
}

/// Remove the field `name` from the table at `parent_path` (empty path
/// names the root table), leaving the field's nodes in the arena. This is
/// how a side "deletes a field but keeps the annotation/binding" on one of
/// its nodes: the nodes stay addressable, only the field is gone.
fn remove_field_at(module: &mut InfinityModule, parent_path: &[&str], name: &str) {
    let parent = if parent_path.is_empty() {
        module.root().expect("root")
    } else {
        node_at(module, parent_path)
    };
    let table = module.node_mut(parent).expect("parent table");
    let Inode::Table { fields } = table else {
        panic!("parent is not a table");
    };
    let before = fields.len();
    fields.retain(|(field, _)| field != name);
    assert_eq!(
        fields.len() + 1,
        before,
        "field {name} was present to delete"
    );
}

/// The audit probe's shape: `{f:{x:10, y}}`, both sides annotating `x`.
fn ghost_modules(y: i64) -> (InfinityModule, NodeId) {
    let module = build(&[(
        "f",
        Spec::Table(vec![("x", Spec::Int(10)), ("y", Spec::Int(y))]),
    )]);
    let x = node_at(&module, &["f", "x"]);
    (module, x)
}

#[test]
fn annotation_ghost_audit_probe() {
    // The audit probe verbatim: base `{f:{x:10,y:1}}`, left annotates `x`,
    // right changes `y` to 2 and annotates its own `x`. At HEAD this is
    // CLEAN with nodes=5, Int10_count=2, annotations=1 — the stale
    // annotated `Int(10)` survives next to the imported one.
    let (base, _) = ghost_modules(1);
    let (mut left, left_x) = ghost_modules(1);
    left.annotate(left_x, AnnotationKind::Intent("the ex".into()));
    let (mut right, right_x) = ghost_modules(2);
    right.annotate(right_x, AnnotationKind::Intent("the ex".into()));
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(int_at(&merged, &["f", "x"]), 10);
    assert_eq!(int_at(&merged, &["f", "y"]), 2);
    // Exactly one Int(10): the imported one. The stale annotated copy is
    // gone, and the annotation now names the imported node.
    assert_eq!(count_int(&merged, 10), 1);
    assert_eq!(merged.annotations().len(), 1);
    let annotation = intent_annotation(&merged, "the ex").expect("the annotation survives");
    assert_eq!(annotation.node, node_at(&merged, &["f", "x"]));
    // Root table + f table + Int(10) + Int(2): nothing duplicated.
    assert_eq!(merged.node_count(), 4);
    assert_canonical(&merged);
}

#[test]
fn annotation_on_an_agreed_field_itself_is_repointed() {
    // The annotation names the replaced cone's root itself: both sides
    // change `f` identically (left_eq_right, so TakeRight) and both
    // annotate the `f` table. At HEAD the annotation stays on the stale
    // left `f` table; after the fix it names the imported `f`.
    let mk = |y: i64| {
        build(&[(
            "f",
            Spec::Table(vec![("x", Spec::Int(10)), ("y", Spec::Int(y))]),
        )])
    };
    let base = mk(1);
    let mut left = mk(2);
    annotate_at(&mut left, &["f"], AnnotationKind::Intent("section".into()));
    let mut right = mk(2);
    annotate_at(&mut right, &["f"], AnnotationKind::Intent("section".into()));
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(int_at(&merged, &["f", "y"]), 2);
    assert_eq!(merged.annotations().len(), 1);
    let annotation = intent_annotation(&merged, "section").expect("the annotation survives");
    assert_eq!(annotation.node, node_at(&merged, &["f"]));
    assert_canonical(&merged);
}

#[test]
fn binding_twin_root_take_right() {
    // NF-MERGE01-01, the binding twin of INF-MERGE-03, probe verbatim:
    // base `{a:1}`, left `{a:1}` with binding `b` -> `a`'s node, right
    // `{a:2}`. The metadata plan keeps the left binding (the right side
    // never had it), so at HEAD the merge is clean with the field showing
    // `Int(2)` while the binding still resolves to the stale `Int(1)`.
    let mk = |value: i64| build(&[("a", Spec::Int(value))]);
    let base = mk(1);
    let mut left = mk(1);
    let target = node_at(&left, &["a"]);
    left.bind("b", target);
    let right = mk(2);
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(int_at(&merged, &["a"]), 2);
    let bound = binding_target(&merged, "b").expect("binding b survives");
    assert_eq!(merged.get(bound), Some(&Inode::Int(2)));
    // The binding names the same node the field does: one node, no stale
    // copy, and the stale Int(1) is gone entirely.
    assert_eq!(bound, node_at(&merged, &["a"]));
    assert_eq!(count_int(&merged, 1), 0);
    assert_eq!(merged.node_count(), 2);
    assert_canonical(&merged);
}

#[test]
fn binding_ghost_nested_take_right() {
    // R2-INF-MRG-02 probe shape: base/left `{f:{x:10, y:1}}`, binding `b`
    // -> `x`; right changes only `y` to 2. `decide(f)` is TakeRight (left
    // unchanged, right changed). At HEAD the field's `x` and the binding's
    // `x` are two different `Int(10)` nodes; after the fix they are one.
    let mk = |y: i64| {
        build(&[(
            "f",
            Spec::Table(vec![("x", Spec::Int(10)), ("y", Spec::Int(y))]),
        )])
    };
    let base = mk(1);
    let mut left = mk(1);
    left.bind("b", node_at(&left, &["f", "x"]));
    let mut right = mk(2);
    right.bind("b", node_at(&right, &["f", "x"]));
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(int_at(&merged, &["f", "y"]), 2);
    let bound = binding_target(&merged, "b").expect("binding b survives");
    assert_eq!(bound, node_at(&merged, &["f", "x"]));
    assert_eq!(count_int(&merged, 10), 1);
    assert_canonical(&merged);
}

#[test]
fn binding_ghost_deeply_nested_take_right() {
    // The binding ghost one level deeper, through a MergeNested
    // (INF-MERGE-01) decision: left changes `s.g`, right changes `s.f.y`,
    // so `s` merges per nested field and `f` is a nested TakeRight. The
    // binding on `s.f.x` must follow the nested import.
    let mk = |g: i64, y: i64| {
        build(&[(
            "s",
            Spec::Table(vec![
                (
                    "f",
                    Spec::Table(vec![("x", Spec::Int(10)), ("y", Spec::Int(y))]),
                ),
                ("g", Spec::Int(g)),
            ]),
        )])
    };
    let base = mk(1, 1);
    let mut left = mk(2, 1);
    left.bind("b", node_at(&left, &["s", "f", "x"]));
    let mut right = mk(1, 2);
    right.bind("b", node_at(&right, &["s", "f", "x"]));
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(int_at(&merged, &["s", "g"]), 2);
    assert_eq!(int_at(&merged, &["s", "f", "y"]), 2);
    let bound = binding_target(&merged, "b").expect("binding b survives");
    assert_eq!(bound, node_at(&merged, &["s", "f", "x"]));
    assert_eq!(count_int(&merged, 10), 1);
    assert_canonical(&merged);
}

#[test]
fn annotation_ghost_nested_take_right() {
    // The annotation ghost one level deeper (INF-MERGE-01 §6.1): a nested
    // TakeRight replaces a nested slot and never touches annotations, so
    // the same ghost appears below the root. Left changes `s.g`, right
    // changes `s.f.y`; both annotate `s.f.x`.
    let mk = |g: i64, y: i64| {
        build(&[(
            "s",
            Spec::Table(vec![
                (
                    "f",
                    Spec::Table(vec![("x", Spec::Int(10)), ("y", Spec::Int(y))]),
                ),
                ("g", Spec::Int(g)),
            ]),
        )])
    };
    let base = mk(1, 1);
    let mut left = mk(2, 1);
    annotate_at(
        &mut left,
        &["s", "f", "x"],
        AnnotationKind::Intent("the ex".into()),
    );
    let mut right = mk(1, 2);
    annotate_at(
        &mut right,
        &["s", "f", "x"],
        AnnotationKind::Intent("the ex".into()),
    );
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(int_at(&merged, &["s", "g"]), 2);
    assert_eq!(int_at(&merged, &["s", "f", "y"]), 2);
    assert_eq!(count_int(&merged, 10), 1);
    assert_eq!(merged.annotations().len(), 1);
    let annotation = intent_annotation(&merged, "the ex").expect("the annotation survives");
    assert_eq!(annotation.node, node_at(&merged, &["s", "f", "x"]));
    assert_canonical(&merged);
}

#[test]
fn annotation_on_a_renamed_node_is_dropped_not_ghosted() {
    // The drop side of the fix: the right side renames `x` to `z` and
    // changes `y`. The annotation keys still match (same Intent text on
    // the same `Int(10)` image), so the merge is clean, but the annotated
    // node has no counterpart under its old name in the imported subtree
    // — there is nothing to repoint at. The annotation is dropped rather
    // than left ghosting the stale node.
    let left = {
        let mut module = build(&[(
            "f",
            Spec::Table(vec![("x", Spec::Int(10)), ("y", Spec::Int(1))]),
        )]);
        annotate_at(
            &mut module,
            &["f", "x"],
            AnnotationKind::Intent("the ex".into()),
        );
        module
    };
    let base = build(&[(
        "f",
        Spec::Table(vec![("x", Spec::Int(10)), ("y", Spec::Int(1))]),
    )]);
    let right = {
        let mut module = build(&[(
            "f",
            Spec::Table(vec![("z", Spec::Int(10)), ("y", Spec::Int(2))]),
        )]);
        annotate_at(
            &mut module,
            &["f", "z"],
            AnnotationKind::Intent("the ex".into()),
        );
        module
    };
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(int_at(&merged, &["f", "z"]), 10);
    assert_eq!(int_at(&merged, &["f", "y"]), 2);
    assert_eq!(merged.annotations().len(), 0);
    // One Int(10) — the imported `z`. The stale left `x` is gone.
    assert_eq!(count_int(&merged, 10), 1);
    assert_canonical(&merged);
}

#[test]
fn annotation_on_a_node_shared_with_a_surviving_field_stays_put() {
    // The live-node guard: one `Int(10)` node is shared by `f.x` and
    // `g.v`. The right side changes `f.w`, so `f` is TakeRight and the
    // shared node is inside the replaced cone — but it also survives
    // through `g.v`, which no decision touches. The annotation stays on
    // the original node (the surviving home), it is not repointed at the
    // imported copy. This passes at HEAD as well as after the fix: what
    // it pins is that the remap never moves metadata that still lives.
    let mk = |w: i64| {
        let mut module = InfinityModule::new();
        let shared = module.push(Inode::Int(10));
        let w_node = module.push(Inode::Int(w));
        let f = module.push(Inode::Table {
            fields: vec![("x".to_string(), shared), ("w".to_string(), w_node)],
        });
        let g = module.push(Inode::Table {
            fields: vec![("v".to_string(), shared)],
        });
        let root = module.push(Inode::Table {
            fields: vec![("f".to_string(), f), ("g".to_string(), g)],
        });
        module.set_root(Some(root));
        module
    };
    let base = mk(1);
    let mut left = mk(1);
    let shared = node_at(&left, &["f", "x"]);
    assert_eq!(shared, node_at(&left, &["g", "v"]));
    left.annotate(shared, AnnotationKind::Intent("shared".into()));
    let mut right = mk(2);
    let shared_right = node_at(&right, &["f", "x"]);
    right.annotate(shared_right, AnnotationKind::Intent("shared".into()));
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(int_at(&merged, &["f", "w"]), 2);
    // Two Int(10) nodes is correct here, not a ghost: the merge broke the
    // sharing (R2-INF-MRG-06 territory — the double import itself is a
    // separate finding), so `f.x` and `g.v` are distinct live values.
    assert_eq!(count_int(&merged, 10), 2);
    assert_eq!(merged.annotations().len(), 1);
    let annotation = intent_annotation(&merged, "shared").expect("the annotation survives");
    assert_eq!(annotation.node, node_at(&merged, &["g", "v"]));
    assert_ne!(annotation.node, node_at(&merged, &["f", "x"]));
    assert_canonical(&merged);
}

#[test]
fn constraint_expression_on_a_replaced_node_is_repointed() {
    // A Constraint annotation's expression is a node too: the annotation
    // sits on the untouched field `g`, but its expression is `f.x`,
    // inside the replaced cone. The expression must follow the import
    // exactly like a subject does, while the subject stays put.
    let mk = |y: i64| {
        build(&[
            (
                "f",
                Spec::Table(vec![("x", Spec::Int(10)), ("y", Spec::Int(y))]),
            ),
            ("g", Spec::Int(5)),
        ])
    };
    let base = mk(1);
    let mut left = mk(1);
    let expr = node_at(&left, &["f", "x"]);
    let subject = node_at(&left, &["g"]);
    left.annotate(
        subject,
        AnnotationKind::Constraint {
            source: "x-nonzero".into(),
            expr,
        },
    );
    let mut right = mk(2);
    let expr_right = node_at(&right, &["f", "x"]);
    let subject_right = node_at(&right, &["g"]);
    right.annotate(
        subject_right,
        AnnotationKind::Constraint {
            source: "x-nonzero".into(),
            expr: expr_right,
        },
    );
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(int_at(&merged, &["f", "y"]), 2);
    assert_eq!(count_int(&merged, 10), 1);
    assert_eq!(merged.annotations().len(), 1);
    let annotation = merged
        .annotations()
        .iter()
        .find(|a| matches!(&a.kind, AnnotationKind::Constraint { .. }))
        .expect("the constraint survives");
    assert_eq!(annotation.node, node_at(&merged, &["g"]));
    match &annotation.kind {
        AnnotationKind::Constraint { expr, .. } => {
            assert_eq!(*expr, node_at(&merged, &["f", "x"]));
        }
        other => panic!("unexpected annotation kind: {other:?}"),
    }
    assert_canonical(&merged);
}

#[test]
fn metadata_binding_take_right_remaps_annotations_on_the_old_target() {
    // The same ghost through the metadata plan: the binding `b` names a
    // table `T` that is not a root field at all, and an annotation names
    // the unchanged leaf `x` inside `T`. The right side changes `T.y`,
    // so the plan TakeRights the binding; the import replaces `T`, and
    // the annotation must follow `x` into the imported copy. At HEAD the
    // annotation keeps the stale `x` alive next to the imported one.
    let mk = |y: i64| {
        let mut module = InfinityModule::new();
        let x = module.push(Inode::Int(10));
        let y_node = module.push(Inode::Int(y));
        let target = module.push(Inode::Table {
            fields: vec![("x".to_string(), x), ("y".to_string(), y_node)],
        });
        let g = module.push(Inode::Int(1));
        let root = module.push(Inode::Table {
            fields: vec![("g".to_string(), g)],
        });
        module.set_root(Some(root));
        module.bind("b", target);
        (module, x)
    };
    let (base, _) = mk(1);
    let (mut left, left_x) = mk(1);
    left.annotate(left_x, AnnotationKind::Intent("the ex".into()));
    let (mut right, right_x) = mk(2);
    right.annotate(right_x, AnnotationKind::Intent("the ex".into()));
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    let bound = binding_target(&merged, "b").expect("binding b survives");
    let target_x = match merged.get(bound) {
        Some(Inode::Table { fields }) => fields
            .iter()
            .find(|(name, _)| name == "x")
            .map(|(_, id)| *id)
            .expect("bound table has x"),
        other => panic!("binding b does not name a table: {other:?}"),
    };
    assert_eq!(merged.get(target_x), Some(&Inode::Int(10)));
    assert_eq!(count_int(&merged, 10), 1);
    assert_eq!(merged.annotations().len(), 1);
    let annotation = intent_annotation(&merged, "the ex").expect("the annotation survives");
    assert_eq!(annotation.node, target_x);
    assert_canonical(&merged);
}

#[test]
fn no_op_merge_keeps_binding_only_annotations() {
    // The sweep's no-op guard: a binding names a node that is not a field
    // anywhere, and an annotation names that node. All three sides are
    // identical, so the merge replaces nothing — and must drop nothing.
    // A reachability sweep seeded only from the root table would wrongly
    // drop this annotation; the fix drops only what a decision orphaned.
    let mk = || {
        let mut module = InfinityModule::new();
        let field = module.push(Inode::Int(1));
        let bound = module.push(Inode::Int(5));
        let root = module.push(Inode::Table {
            fields: vec![("f".to_string(), field)],
        });
        module.set_root(Some(root));
        module.bind("b", bound);
        module.annotate(bound, AnnotationKind::Intent("bound-note".into()));
        module
    };
    let base = mk();
    let left = mk();
    let right = mk();
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(merged.node_count(), 3);
    assert_eq!(merged.annotations().len(), 1);
    let bound = binding_target(&merged, "b").expect("binding b survives");
    assert_eq!(merged.get(bound), Some(&Inode::Int(5)));
    let annotation = intent_annotation(&merged, "bound-note").expect("the annotation survives");
    assert_eq!(annotation.node, bound);
    assert_canonical(&merged);
}

#[test]
fn annotation_on_a_field_deleted_by_the_right_is_dropped() {
    // The drop side through a nested Delete: both sides change `s`
    // disjointly, so `s` merges per nested field; the right side deletes
    // `f` while the left side changes `g`. The annotation on `f.x` has
    // no home in the merged module — `f` is gone by decision — so it is
    // dropped rather than ghosted. At HEAD it survives on the stale node.
    let mk = |g: i64| {
        build(&[(
            "s",
            Spec::Table(vec![
                ("f", Spec::Table(vec![("x", Spec::Int(10))])),
                ("g", Spec::Int(g)),
            ]),
        )])
    };
    let base = mk(1);
    let mut left = mk(2);
    annotate_at(
        &mut left,
        &["s", "f", "x"],
        AnnotationKind::Intent("the ex".into()),
    );
    let mut right = mk(1);
    annotate_at(
        &mut right,
        &["s", "f", "x"],
        AnnotationKind::Intent("the ex".into()),
    );
    remove_field_at(&mut right, &["s"], "f");
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert!(!has_path(&merged, &["s", "f"]));
    assert_eq!(int_at(&merged, &["s", "g"]), 2);
    assert_eq!(merged.annotations().len(), 0);
    assert_eq!(count_int(&merged, 10), 0);
    assert_canonical(&merged);
}

#[test]
fn root_field_deleted_by_the_right_drops_its_annotations() {
    // The same drop at the root: the left side keeps `f` (and its
    // annotation on `x`), the right side deletes `f`. The Delete
    // decision orphans the cone, and the annotation goes with it.
    let mk = || build(&[("f", Spec::Table(vec![("x", Spec::Int(10))]))]);
    let base = mk();
    let mut left = mk();
    annotate_at(
        &mut left,
        &["f", "x"],
        AnnotationKind::Intent("the ex".into()),
    );
    let mut right = mk();
    annotate_at(
        &mut right,
        &["f", "x"],
        AnnotationKind::Intent("the ex".into()),
    );
    remove_field_at(&mut right, &[], "f");
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert!(!has_path(&merged, &["f"]));
    assert_eq!(merged.annotations().len(), 0);
    assert_eq!(count_int(&merged, 10), 0);
    assert_canonical(&merged);
}

#[test]
fn take_right_where_both_sides_agree_remaps() {
    // Both sides change `f` identically, so `decide` prefers the right
    // node (TakeRight) even though nothing disagrees — the slot is still
    // replaced by an import, so the annotation on `x` must still follow.
    let mk = |y: i64| {
        build(&[(
            "f",
            Spec::Table(vec![("x", Spec::Int(10)), ("y", Spec::Int(y))]),
        )])
    };
    let base = mk(1);
    let mut left = mk(2);
    annotate_at(
        &mut left,
        &["f", "x"],
        AnnotationKind::Intent("the ex".into()),
    );
    let mut right = mk(2);
    annotate_at(
        &mut right,
        &["f", "x"],
        AnnotationKind::Intent("the ex".into()),
    );
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(int_at(&merged, &["f", "y"]), 2);
    assert_eq!(count_int(&merged, 10), 1);
    assert_eq!(merged.annotations().len(), 1);
    let annotation = intent_annotation(&merged, "the ex").expect("the annotation survives");
    assert_eq!(annotation.node, node_at(&merged, &["f", "x"]));
    assert_canonical(&merged);
}

#[test]
fn binding_on_a_field_deleted_by_the_right_is_dropped() {
    // The binding twin of test 13 (root Delete): the left side binds `b`
    // to `f.x` and the right side deletes `f`. The metadata plan keeps
    // the left binding (the right side never had it), and the Delete
    // decision orphans the whole `f` cone — but a binding target is a
    // root (`roots()` in `ir.rs`), so a binding left pointing at the
    // orphaned node would keep the stale `Int(10)` alive through the
    // final encode, exactly like the annotation ghost. The binding is
    // dropped instead: its target has no home in the merged module.
    let mk = || build(&[("f", Spec::Table(vec![("x", Spec::Int(10))]))]);
    let base = mk();
    let mut left = mk();
    left.bind("b", node_at(&left, &["f", "x"]));
    let mut right = mk();
    remove_field_at(&mut right, &[], "f");
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert!(!has_path(&merged, &["f"]));
    assert_eq!(binding_target(&merged, "b"), None);
    assert_eq!(count_int(&merged, 10), 0);
    // Only the (now empty) root table remains.
    assert_eq!(merged.node_count(), 1);
    assert_canonical(&merged);
}

#[test]
fn binding_on_a_renamed_node_is_dropped_not_ghosted() {
    // The binding twin of test 7 (TakeRight rename): the right side
    // renames `x` to `z` and changes `y`, so `f` is TakeRight and the
    // left `x` has no counterpart under its old name in the imported
    // subtree — there is nothing to repoint the binding at. The binding
    // is dropped rather than left ghosting the stale node.
    let base = build(&[(
        "f",
        Spec::Table(vec![("x", Spec::Int(10)), ("y", Spec::Int(1))]),
    )]);
    let mut left = build(&[(
        "f",
        Spec::Table(vec![("x", Spec::Int(10)), ("y", Spec::Int(1))]),
    )]);
    left.bind("b", node_at(&left, &["f", "x"]));
    let right = build(&[(
        "f",
        Spec::Table(vec![("z", Spec::Int(10)), ("y", Spec::Int(2))]),
    )]);
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert_eq!(int_at(&merged, &["f", "z"]), 10);
    assert_eq!(int_at(&merged, &["f", "y"]), 2);
    assert_eq!(binding_target(&merged, "b"), None);
    // One Int(10) — the imported `z`. The stale left `x` is gone.
    assert_eq!(count_int(&merged, 10), 1);
    assert_canonical(&merged);
}

#[test]
fn constraint_expression_on_a_deleted_node_drops_the_annotation() {
    // A Constraint annotation's expression is a node too, and a root
    // (`roots()` in `ir.rs`): the annotation sits on the untouched field
    // `g`, but its expression is `f.x`, and the right side deletes `f`.
    // The subject survives, but the expression has no home in the merged
    // module — keeping the annotation would ghost the stale `Int(10)`
    // back in through the expression. The annotation is dropped whole.
    let mk = || {
        build(&[
            ("f", Spec::Table(vec![("x", Spec::Int(10))])),
            ("g", Spec::Int(5)),
        ])
    };
    let base = mk();
    let mut left = mk();
    let expr = node_at(&left, &["f", "x"]);
    let subject = node_at(&left, &["g"]);
    left.annotate(
        subject,
        AnnotationKind::Constraint {
            source: "x-nonzero".into(),
            expr,
        },
    );
    let mut right = mk();
    let expr_right = node_at(&right, &["f", "x"]);
    let subject_right = node_at(&right, &["g"]);
    right.annotate(
        subject_right,
        AnnotationKind::Constraint {
            source: "x-nonzero".into(),
            expr: expr_right,
        },
    );
    remove_field_at(&mut right, &[], "f");
    let merged = clean(merge(&base, &left, &right).expect("merge"));
    assert!(!has_path(&merged, &["f"]));
    assert_eq!(int_at(&merged, &["g"]), 5);
    assert_eq!(merged.annotations().len(), 0);
    assert_eq!(count_int(&merged, 10), 0);
    assert_canonical(&merged);
}
