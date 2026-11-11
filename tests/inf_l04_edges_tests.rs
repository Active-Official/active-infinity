//! INF-L04: `InfinityModule::edges()` must be the structural edge set —
//! exactly the wire edge table (`encode::derive_edges` /
//! `validate::check_edges`, node references only) — and must not carry the
//! annotation-expression edge. The full dependency set, annotation edges
//! included, lives in `edges_including_annotations()` /
//! `dependency_map_including_annotations()`.

use active_infinity::{decode, encode, AnnotationKind, InfinityModule, Inode, Limits, NodeId};

/// A module whose only link between the two nodes is a Constraint
/// annotation: the expression node is not a child of the subject.
fn annotated_module() -> (InfinityModule, NodeId, NodeId) {
    let mut module = InfinityModule::new();
    let subject = module.push(Inode::Int(1));
    let expression = module.push(Inode::Int(2));
    module.set_root(Some(subject));
    module.annotate(
        subject,
        AnnotationKind::Constraint {
            source: "x > 0".into(),
            expr: expression,
        },
    );
    (module, subject, expression)
}

fn wire_edges(module: &InfinityModule) -> Vec<(NodeId, NodeId)> {
    let image = encode(module).expect("annotated module must encode");
    let view = active_infinity::view::InfinityView::new(&image, Limits::default())
        .expect("encoded image must validate");
    view.edges().expect("wire edge table must read back")
}

#[test]
fn edges_matches_wire_edge_table_for_constraint_annotated_module() {
    let (module, subject, expression) = annotated_module();
    let wire = wire_edges(&module);
    // The wire table is derived from node references only, so it holds no
    // annotation-expression edge for this module at all.
    assert!(
        !wire.contains(&(expression, subject)),
        "wire table unexpectedly carries the annotation edge: {wire:?}"
    );
    assert_eq!(
        module.edges(),
        wire,
        "module.edges() diverges from the wire edge table: module={:?} wire={wire:?}",
        module.edges()
    );
    // The structural reverse map agrees too.
    let map = module.dependency_map();
    assert!(
        !map.get(&subject)
            .is_some_and(|deps| deps.contains(&expression)),
        "dependency_map() carries the annotation edge: {map:?}"
    );
}

#[test]
fn edges_including_annotations_keeps_annotation_expression_edge() {
    let (module, subject, expression) = annotated_module();
    let edges = module.edges_including_annotations();
    assert!(
        edges.contains(&(expression, subject)),
        "the annotation edge is missing from edges_including_annotations(): {edges:?}"
    );
    let map = module.dependency_map_including_annotations();
    assert!(
        map.get(&subject)
            .is_some_and(|deps| deps.contains(&expression)),
        "the reverse map omits the annotation expression: {map:?}"
    );
    // The including set is a strict superset of the structural set here.
    assert!(
        edges.len() > module.edges().len(),
        "including set is not a superset: including={edges:?} structural={:?}",
        module.edges()
    );
}

#[test]
fn edges_without_annotations_is_unchanged() {
    let mut module = InfinityModule::new();
    let first = module.push(Inode::Int(1));
    let second = module.push(Inode::Int(2));
    let root = module.push(Inode::Array {
        elements: vec![first, second],
    });
    module.set_root(Some(root));
    let expected = vec![(first, root), (second, root)];
    assert_eq!(module.edges(), expected);
    assert_eq!(module.edges_including_annotations(), expected);
    let map = module.dependency_map();
    assert_eq!(map.get(&root), Some(&vec![first, second]));
    assert_eq!(module.dependency_map_including_annotations(), map);
    // The wire table is in canonical numbering (roots first), so compare
    // through the round trip: the decoded module's structural edges are
    // exactly the stored wire table.
    let image = encode(&module).expect("module must encode");
    let decoded = decode(&image).expect("image must decode");
    assert_eq!(decoded.edges(), wire_edges(&module));
}
