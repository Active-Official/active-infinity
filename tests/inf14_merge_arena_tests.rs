//! INF-14: `merge_fragment` grows the arena monotonically and drops
//! annotations/provenance (INF-STREAM-03).
//!
//! Fail-before probes (W4's `w4_inf14_arena_growth`, replicated exactly):
//! 100 `PutNode` deltas of an 11-node fragment grow `node_count` by 1100,
//! and an annotated/provenance-bearing fragment loses both after the merge.
//! After the fix the arena stays proportional to the live module (the
//! imported root copy and the replaced subtree are pruned per `PutNode`),
//! and the fragment's annotations (remapped, root-subject repointed at the
//! target) and provenance (adopted when the base has none) survive.

use active_infinity::stream::{apply_delta, DeltaOp};
use active_infinity::{
    encode, validate, AnnotationKind, InfinityModule, Inode, NodeId, Provenance,
};

/// W4's base: target `Int(0)` + `Table` root.
fn base() -> (InfinityModule, NodeId) {
    let mut base = InfinityModule::new();
    let target = base.push(Inode::Int(0));
    let root = base.push(Inode::Table {
        fields: vec![("t".into(), target)],
    });
    base.set_root(Some(root));
    (base, target)
}

/// W4's fragment: 10 `Int` nodes under an `Array` root (11 nodes).
/// When `annotated`, the fragment root carries an `Intent` annotation and
/// the fragment carries provenance (`producer: "frag"`).
fn fragment(annotated: bool) -> InfinityModule {
    let mut f = InfinityModule::new();
    let mut ids = Vec::new();
    for i in 0..10 {
        ids.push(f.push(Inode::Int(i)));
    }
    let r = f.push(Inode::Array { elements: ids });
    f.set_root(Some(r));
    if annotated {
        f.annotate(r, AnnotationKind::Intent("frag-note".into()));
        f.set_provenance(Some(Provenance {
            producer: Some("frag".into()),
            ..Default::default()
        }));
    }
    f
}

fn putnode(target: NodeId, fragment: InfinityModule) -> DeltaOp {
    DeltaOp::PutNode {
        target,
        fragment: Box::new(fragment),
    }
}

/// The audit's regression probe: 100 `PutNode` deltas replacing the same
/// target with a 10-node fragment; `node_count` grows by ~1000 before the
/// fix and stays ~constant after it.
#[test]
fn inf14_arena_stays_bounded_across_repeated_putnode() {
    let (base, target) = base();
    let start = base.node_count();
    assert_eq!(start, 2);
    let mut cur = base;
    for i in 0..100 {
        cur = apply_delta(&cur, &[putnode(target, fragment(false))]).expect("delta applies");
        // Steady state: the base's 2 nodes + the 10 live `Int` nodes of the
        // current fragment. The imported `Array` root copy is orphaned by
        // the content move into the target, and the previous generation's
        // `Int` nodes are orphaned with the old target content; both are
        // pruned by the `PutNode` (INF-14). Without the fix this grows by
        // 11 per iteration (1100 after 100).
        assert_eq!(cur.node_count(), 12, "after PutNode {i}");
        // No unreachable node survives the merge: plain `encode` (no
        // `drop_unreachable` opt-in) succeeds and the module is reachable.
        cur.check_reachable()
            .expect("no unreachable nodes after PutNode");
    }
    println!(
        "INF-14 arena: start={start} after 100 PutNode={} growth={}",
        cur.node_count(),
        cur.node_count() - start
    );
    assert_eq!(cur.node_count() - start, 10);
    // The grafted content is the current fragment: the target holds the
    // `Array` of `Int(0..10)`.
    assert!(matches!(
        cur.get(target),
        Some(Inode::Array { elements }) if elements.len() == 10
    ));
    let image = encode(&cur).expect("plain encode succeeds on a pruned module");
    validate(&image).expect("validate");
}

/// W4's metadata leg: the annotated fragment's annotation and provenance
/// survive the merge (before the fix both are 0 / `None`).
#[test]
fn inf14_fragment_annotations_and_provenance_survive_the_merge() {
    let (base, target) = base();
    let cur = apply_delta(&base, &[putnode(target, fragment(true))]).expect("delta applies");
    assert_eq!(
        cur.annotations().len(),
        1,
        "the fragment root's Intent survives, repointed at the target"
    );
    let annotation = &cur.annotations()[0];
    assert_eq!(annotation.node, target);
    assert!(
        matches!(&annotation.kind, AnnotationKind::Intent(text) if text == "frag-note"),
        "unexpected annotation kind: {:?}",
        annotation.kind
    );
    assert_eq!(
        cur.provenance().and_then(|p| p.producer.as_deref()),
        Some("frag"),
        "the fragment's provenance is adopted (the base had none)"
    );
    let image = encode(&cur).expect("encode");
    validate(&image).expect("validate");
}

/// The fragment root's annotation is repointed at the target, so repeating
/// the identical annotated delta does not grow the annotation list: the
/// repointed annotation is an exact duplicate of the one already there and
/// is skipped (canonical `prepare` dedupes exact annotations, so skipping
/// is canonical-form-preserving).
#[test]
fn inf14_repeated_identical_annotated_delta_does_not_grow_annotations() {
    let (base, target) = base();
    let mut cur = base;
    for i in 0..10 {
        cur = apply_delta(&cur, &[putnode(target, fragment(true))]).expect("delta applies");
        assert_eq!(cur.annotations().len(), 1, "after annotated PutNode {i}");
        assert_eq!(cur.node_count(), 12, "after annotated PutNode {i}");
        assert_eq!(
            cur.provenance().and_then(|p| p.producer.as_deref()),
            Some("frag"),
            "after annotated PutNode {i}"
        );
    }
}

/// Annotations on non-root fragment nodes survive with remapped subjects,
/// and a `Constraint` annotation's expression is remapped too.
#[test]
fn inf14_annotations_on_deep_fragment_nodes_survive_with_remapped_ids() {
    let (base, target) = base();
    let mut frag = InfinityModule::new();
    let leaf = frag.push(Inode::Int(7));
    let predicate = frag.push(Inode::Int(1));
    let root = frag.push(Inode::Array {
        elements: vec![leaf],
    });
    frag.set_root(Some(root));
    frag.annotate(leaf, AnnotationKind::Intent("leaf-note".into()));
    frag.annotate(
        root,
        AnnotationKind::Constraint {
            source: "nonzero".into(),
            expr: predicate,
        },
    );
    let cur = apply_delta(&base, &[putnode(target, frag)]).expect("delta applies");
    assert_eq!(cur.annotations().len(), 2);
    // The `Intent` subject is the imported leaf, now a child of the target.
    let leaf_annotation = cur
        .annotations()
        .iter()
        .find(|a| matches!(&a.kind, AnnotationKind::Intent(text) if text == "leaf-note"))
        .expect("leaf annotation carried");
    assert!(matches!(
        cur.get(target),
        Some(Inode::Array { elements }) if elements.contains(&leaf_annotation.node)
    ));
    // The `Constraint` subject is the target (repointed from the fragment
    // root) and its expression is the imported predicate node.
    let constraint = cur
        .annotations()
        .iter()
        .find(|a| matches!(&a.kind, AnnotationKind::Constraint { .. }))
        .expect("constraint annotation carried");
    assert_eq!(constraint.node, target);
    assert!(
        matches!(&constraint.kind, AnnotationKind::Constraint { expr, .. } if cur.get(*expr) == Some(&Inode::Int(1))),
        "constraint expression must be the imported predicate node"
    );
    // Live nodes: base 2 + leaf + predicate (the imported `Array` root copy
    // is pruned; leaf and predicate are kept as annotation roots).
    assert_eq!(cur.node_count(), 4);
    let image = encode(&cur).expect("encode");
    validate(&image).expect("validate");
}

/// A fragment node reachable only through a fragment binding is not
/// imported: `PutNode` does not graft bindings (pinned by the marathon
/// round-7 tests), so importing it would land an unreachable node.
#[test]
fn inf14_binding_only_fragment_nodes_are_not_imported() {
    let (base, target) = base();
    let mut frag = InfinityModule::new();
    let small = frag.push(Inode::Int(0));
    frag.set_root(Some(small));
    let value = frag.push(Inode::Int(1));
    let table = frag.push(Inode::Table {
        fields: (0..100).map(|i| (format!("f{i:03}"), value)).collect(),
    });
    frag.bind("big", table);
    let before = base.node_count();
    let cur = apply_delta(&base, &[putnode(target, frag)]).expect("delta applies");
    // Only the root cone (the `Int(0)` root, itself pruned after the content
    // move) is imported: the bound table's 2 nodes never land, and the
    // fragment's binding is not carried.
    assert_eq!(cur.node_count(), before);
    assert!(cur.bindings().is_empty());
    assert!(matches!(cur.get(target), Some(Inode::Int(0))));
}

/// Pruning drops the unannotated part of the replaced subtree, and keeps
/// exactly the nodes the annotation roots still reach: the annotated node
/// of the old subtree survives (annotations are roots by design — the
/// same shape as the INF-MERGE-03 annotation ghost, a separate finding),
/// the unannotated one does not.
#[test]
fn inf14_prune_drops_unannotated_replaced_nodes_and_keeps_annotated_ones() {
    let mut base = InfinityModule::new();
    let plain = base.push(Inode::Int(1));
    let noted = base.push(Inode::Int(2));
    let target = base.push(Inode::Array {
        elements: vec![plain, noted],
    });
    let root = base.push(Inode::Table {
        fields: vec![("t".into(), target)],
    });
    base.set_root(Some(root));
    base.annotate(noted, AnnotationKind::Intent("keep-me".into()));
    assert_eq!(base.node_count(), 4);
    let mut frag = InfinityModule::new();
    let r = frag.push(Inode::Int(99));
    frag.set_root(Some(r));
    let cur = apply_delta(&base, &[putnode(target, frag)]).expect("delta applies");
    // Target + table root + the annotation-kept node; the plain node is gone.
    // (Compaction renumbers, so the kept node's id is resolved by content,
    // not by its pre-merge id.)
    assert_eq!(cur.node_count(), 3);
    assert_eq!(cur.annotations().len(), 1);
    assert_eq!(
        cur.get(cur.annotations()[0].node),
        Some(&Inode::Int(2)),
        "the surviving annotation still points at the annotated node"
    );
    // Compaction renumbers, so the target's id is resolved by content, not
    // by its pre-merge id: the node holding Int(99) is the target, and the
    // root table still points at it.
    let new_target = cur
        .nodes()
        .iter()
        .position(|node| matches!(node, Inode::Int(99)))
        .map(|index| NodeId(index as u32))
        .expect("the target holds the fragment's content");
    assert!(matches!(
        cur.get(cur.root().expect("root")),
        Some(Inode::Table { fields }) if fields.iter().any(|(_, id)| *id == new_target)
    ));
    let image = encode(&cur).expect("encode");
    validate(&image).expect("validate");
}

/// A fragment without a root is refused with `infinity/stream-delta`
/// (marathon behaviour, unchanged) and the base is untouched: the root
/// check now runs before anything is pushed, so the merge is fail-atomic
/// even without the caller's clone-then-swap.
#[test]
fn inf14_rootless_fragment_is_refused_without_mutating_the_base() {
    let (base, target) = base();
    let mut frag = InfinityModule::new();
    let _leaf = frag.push(Inode::Int(7));
    let error = apply_delta(&base, &[putnode(target, frag)]).expect_err("rootless fragment");
    assert_eq!(error.code(), "infinity/stream-delta", "{error:?}");
    assert_eq!(base.node_count(), 2);
}

/// Provenance the base already has is never silently overwritten: an
/// identical fragment provenance is a no-op, a different one is refused
/// explicitly (`infinity/stream-delta`) instead of being dropped without
/// a signal.
#[test]
fn inf14_conflicting_fragment_provenance_is_refused_explicitly() {
    let (mut base, target) = base();
    base.set_provenance(Some(Provenance {
        producer: Some("base".into()),
        ..Default::default()
    }));
    let frag_with = |producer: &str| {
        let mut frag = InfinityModule::new();
        let r = frag.push(Inode::Int(5));
        frag.set_root(Some(r));
        frag.set_provenance(Some(Provenance {
            producer: Some(producer.into()),
            ..Default::default()
        }));
        frag
    };
    let same = apply_delta(&base, &[putnode(target, frag_with("base"))]).expect("same applies");
    assert_eq!(
        same.provenance().and_then(|p| p.producer.as_deref()),
        Some("base")
    );
    let error = apply_delta(&base, &[putnode(target, frag_with("other"))])
        .expect_err("conflicting provenance is refused, not dropped");
    assert_eq!(error.code(), "infinity/stream-delta", "{error:?}");
}
