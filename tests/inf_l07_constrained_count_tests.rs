//! INF-L07: `NodeView::count()` doc/code disagree for Constrained (kind 17).
//!
//! The audit (INF-VIEW-02) found that `count()`'s doc says "a Constrained
//! counts every aux entry (some are strings)", but the code returned 1 for
//! kind 17 (`6|10|11|16|17|21|22 => 1`). A caller sizing work by `count()`
//! undercounts Constrained aux by up to the aux range: an Enum with N items
//! has `c == N` aux entries but reported a count of 1.
//!
//! The audit's suggested remedy — return `self.c` for 17, as 18/19 already
//! do — is incomplete, and these tests pin why. A Constrained node always
//! carries its target as a child (`children()` returns `[target]`,
//! `validate.rs` `node_children_into` kind 17 pushes `rec.a`), so the
//! count must stay an upper bound on the node references too: for an `Odd`
//! constraint (and a `MinMax` with neither bound) the aux range is empty
//! (`c == 0`, the only legal encoding — `check_nodes` requires
//! `seen_kinds.is_empty()` for `CONSTRAINT_KIND_ODD`), and a bare `self.c`
//! would report 0 while `children()` returns one node, breaking the
//! documented upper-bound contract and the `count_covers_children_for_every_kind`
//! invariant in `tests/marathon_view_tests.rs`. The fix is therefore
//! `1 + self.c`: the target reference plus every aux entry. Kinds 18/19
//! need no change: their children are a subset of their aux entries
//! (Patch values, SchemaField non-deprecated entries), so `self.c` already
//! bounds them.
//!
//! Expected aux counts (`c`, the `b..b+c` aux range) per shape, from
//! `encode.rs`: MinMax one entry per bound present (2, 1, or 0), Enum one
//! per item, Pattern one, Custom one, Odd zero.

use active_infinity::view::InfinityView;
use active_infinity::{encode, Constraint, InfinityModule, Inode, Limits, NodeId};

/// Encode a module whose root is a single Constrained node over an Int
/// target, and return a view over it. The image bytes are leaked so the
/// view can borrow them for the duration of the test.
fn view_with_constrained(constraint: Constraint) -> InfinityView<'static> {
    let mut module = InfinityModule::new();
    let target = module.push(Inode::Int(7));
    let root = module.push(Inode::Constrained { target, constraint });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode");
    let boxed: Box<[u8]> = image.into_boxed_slice();
    let leaked: &'static [u8] = Box::leak(boxed);
    InfinityView::new(leaked, Limits::default()).expect("view")
}

/// The Constrained node of a one-constraint module: its `count()`, its raw
/// `c` (aux entry count), and its children.
fn constrained_node(constraint: Constraint) -> (u64, u64, Vec<NodeId>, NodeId) {
    let view = view_with_constrained(constraint);
    let id = (0..view.node_count())
        .map(NodeId)
        .find(|id| view.node(*id).map(|node| node.kind == 17).unwrap_or(false))
        .expect("the fixture has a Constrained node");
    let node = view.node(id).expect("node");
    let children = view.children(id).expect("children");
    (node.count(), node.c, children, id)
}

/// `count()` must be the target (1) plus every aux entry (`c`), and must
/// stay an upper bound on the node references `children()` returns.
fn assert_constrained_count(constraint: Constraint, expected_aux: u64) {
    let (count, c, children, _id) = constrained_node(constraint);
    assert_eq!(c, expected_aux, "aux entry count for this shape");
    assert_eq!(
        count,
        1 + expected_aux,
        "a Constrained counts its target plus every aux entry"
    );
    assert!(
        children.len() as u64 <= count,
        "count() must stay an upper bound on children(): {} children, count {count}",
        children.len()
    );
    assert_eq!(
        children.len(),
        1,
        "a Constrained has exactly one child: its target"
    );
}

#[test]
fn count_counts_both_min_max_aux_entries() {
    assert_constrained_count(
        Constraint::MinMax {
            min: Some(-10),
            max: Some(10),
        },
        2,
    );
}

#[test]
fn count_counts_a_lone_min_aux_entry() {
    assert_constrained_count(
        Constraint::MinMax {
            min: Some(-10),
            max: None,
        },
        1,
    );
}

#[test]
fn count_counts_a_lone_max_aux_entry() {
    assert_constrained_count(
        Constraint::MinMax {
            min: None,
            max: Some(10),
        },
        1,
    );
}

#[test]
fn count_of_a_boundless_min_max_is_one_for_the_target() {
    // The audit's literal `self.c` remedy would report 0 here while
    // `children()` still returns the target: the bound that keeps the
    // upper-bound contract honest.
    assert_constrained_count(
        Constraint::MinMax {
            min: None,
            max: None,
        },
        0,
    );
}

#[test]
fn count_counts_every_enum_item() {
    assert_constrained_count(
        Constraint::Enum(vec!["x".into(), "y".into(), "z".into()]),
        3,
    );
}

#[test]
fn count_counts_the_pattern_aux_entry() {
    assert_constrained_count(Constraint::Pattern("[a-z]+".into()), 1);
}

#[test]
fn count_counts_the_custom_aux_entry() {
    assert_constrained_count(Constraint::Custom("is-prime".into()), 1);
}

#[test]
fn count_of_an_odd_constraint_is_one_for_the_target() {
    // `Odd` carries no aux entries at all (`c == 0` is its only legal
    // encoding), so this is the sharpest form of the same trap as the
    // boundless MinMax: `self.c` alone would report 0 for a node with
    // one child.
    assert_constrained_count(Constraint::Odd, 0);
}

#[test]
fn count_still_bounds_children_for_every_constrained_shape() {
    // Sweep every shape in one module: the `count_covers_children` invariant
    // must hold for each of them, not just for the kinds the marathon view
    // fixture happens to build.
    let mut module = InfinityModule::new();
    let target = module.push(Inode::Int(7));
    let shapes = [
        Constraint::MinMax {
            min: Some(-10),
            max: Some(10),
        },
        Constraint::MinMax {
            min: Some(-10),
            max: None,
        },
        Constraint::MinMax {
            min: None,
            max: None,
        },
        Constraint::Enum(vec!["x".into(), "y".into(), "z".into()]),
        Constraint::Pattern("[a-z]+".into()),
        Constraint::Custom("is-prime".into()),
        Constraint::Odd,
    ];
    let mut elements = Vec::new();
    for shape in shapes {
        elements.push(module.push(Inode::Constrained {
            target,
            constraint: shape,
        }));
    }
    let root = module.push(Inode::Array { elements });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode");
    let view = InfinityView::new(&image, Limits::default()).expect("view");
    // NB: do NOT reuse the push-order ids — encode canonicalises and
    // renumbers nodes, so find the Constrained nodes by kind in the view.
    let mut found = 0;
    for index in 0..view.node_count() {
        let id = NodeId(index);
        let node = view.node(id).expect("node");
        if node.kind != 17 {
            continue;
        }
        found += 1;
        let children = view.children(id).expect("children");
        assert!(
            children.len() as u64 <= node.count(),
            "kind {} reports {} but carries {} children",
            node.kind_name(),
            node.count(),
            children.len()
        );
        assert_eq!(node.count(), 1 + node.c);
    }
    assert_eq!(found, 7, "all seven Constrained shapes survive encoding");
}
