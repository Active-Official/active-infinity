//! INF-L08: `dependents()` is O(E) per call and `edges()` materialises the table.
//!
//! The audit (INF-VIEW-03) found that `InfinityView::dependents()` calls
//! `edges()`, which allocates the full edge table (up to 16M edges = 128 MiB)
//! and then filters it — so a caller looping `dependents()` over nodes is
//! O(V x E) in time and pays a full-table allocation per call. The audit's
//! remedy is to scan the stored edge table without materialising it
//! (iterate `Validated::edge(i)` and collect matches), or document O(E) per
//! call and add a `dependents_map()` bulk API. The fix does both: the
//! per-node call scans in place, and the bulk call pays one O(E) scan for
//! every node at once.
//!
//! The finding is about allocation and repeated work, not wrong answers:
//! `dependents()` already returns the right sets (it filters the same table
//! the fix scans), so the correctness tests below pass on the old code too
//! and exist to pin the results while the implementation changes under
//! them. The allocation probe (`dependents_does_not_materialise_the_edge_table`)
//! is the test that distinguishes the old code from the fixed code: on the
//! old code it fails because `dependents()` allocates the whole edge table
//! (about 800 KiB gross for the 50,000-edge fixture, through Vec growth),
//! and on the fixed code it passes because the call allocates only its
//! result (16 bytes for one dependent). The probe counts gross bytes
//! allocated on the measuring thread only, via a counting global allocator
//! (see `allocated_during`), so parallel tests in this binary cannot
//! pollute the count.
//!
//! Oracles: `dependents(id)` must equal the set of nodes whose `children()`
//! contains `id` (an independent code path — node records, not the edge
//! table), and must equal the filter of `edges()` over the stored table.
//! `dependents_map()[id]` must equal `dependents(id)` for every node.

use active_infinity::view::InfinityView;
use active_infinity::{encode, Constraint, InfinityModule, Inode, Limits, NodeId};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Gross bytes allocated on the measuring thread while counting is on.
/// Only allocations made by the thread that set the flag are counted.
static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static MEASURING: Cell<bool> = const { Cell::new(false) };
}

struct CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        MEASURING.with(|measuring| {
            if measuring.get() {
                ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            }
        });
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// Turns allocation counting on for this thread; counting stops when the
/// guard is dropped (including on panic), so a failure cannot leak the
/// flag into a later test on the same thread.
struct MeasureGuard;

impl MeasureGuard {
    fn start() -> Self {
        ALLOCATED_BYTES.store(0, Ordering::Relaxed);
        MEASURING.with(|measuring| measuring.set(true));
        MeasureGuard
    }
}

impl Drop for MeasureGuard {
    fn drop(&mut self) {
        MEASURING.with(|measuring| measuring.set(false));
    }
}

/// Runs `f` and returns its value together with the gross bytes it
/// allocated on this thread. Freed bytes are not subtracted: the number
/// is the allocation the call forced, which is what the finding is about.
fn allocated_during<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let guard = MeasureGuard::start();
    let out = f();
    let bytes = ALLOCATED_BYTES.load(Ordering::Relaxed);
    drop(guard);
    (out, bytes)
}

/// Encode a module and return a view over it. The image bytes are leaked
/// so the view can borrow them for the duration of the test.
fn view_of(module: &InfinityModule) -> InfinityView<'static> {
    let image = encode(module).expect("encode");
    let boxed: Box<[u8]> = image.into_boxed_slice();
    let leaked: &'static [u8] = Box::leak(boxed);
    InfinityView::new(leaked, Limits::default()).expect("view")
}

/// The nodes whose `children()` contains `id`: the children-oracle for
/// `dependents(id)`, computed from node records instead of the edge table.
fn children_oracle(view: &InfinityView<'_>, id: NodeId) -> Vec<NodeId> {
    let mut out = Vec::new();
    for index in 0..view.node_count() {
        let parent = NodeId(index);
        if view.children(parent).expect("children").contains(&id) {
            out.push(parent);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// The stored edge table, re-derived from node records instead of read
/// from the table: one `(child, parent)` pair per node reference.
fn edges_from_children(view: &InfinityView<'_>) -> Vec<(NodeId, NodeId)> {
    let mut out = Vec::new();
    for index in 0..view.node_count() {
        let parent = NodeId(index);
        for child in view.children(parent).expect("children") {
            out.push((child, parent));
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// A diamond: D is shared by B and C, and A references B and C.
/// Returns the view plus the canonical ids of (a, b, c, d).
fn diamond_view() -> (InfinityView<'static>, NodeId, NodeId, NodeId, NodeId) {
    let mut module = InfinityModule::new();
    let d = module.push(Inode::Int(1));
    let b = module.push(Inode::Array { elements: vec![d] });
    let c = module.push(Inode::Array { elements: vec![d] });
    let a = module.push(Inode::Array {
        elements: vec![b, c],
    });
    module.set_root(Some(a));
    let view = view_of(&module);
    // Encode canonicalises and renumbers nodes, so find them by kind and
    // children in the view instead of reusing the push-order ids.
    let mut found_d = None;
    let mut found_b_c = Vec::new();
    let mut found_a = None;
    for index in 0..view.node_count() {
        let id = NodeId(index);
        let node = view.node(id).expect("node");
        let children = view.children(id).expect("children");
        match node.kind {
            2 => found_d = Some(id),
            7 if children.len() == 1 => found_b_c.push(id),
            7 if children.len() == 2 => found_a = Some(id),
            _ => {}
        }
    }
    let d = found_d.expect("the diamond has one Int node");
    assert_eq!(found_b_c.len(), 2, "B and C are the two one-child arrays");
    assert!(
        found_b_c
            .iter()
            .all(|id| view.children(*id).expect("children") == vec![d]),
        "B and C each reference only D"
    );
    let a = found_a.expect("the diamond has one two-child array");
    (view, a, found_b_c[0], found_b_c[1], d)
}

/// A richer module: leaves shared across arrays, a table, a Ref and a
/// Constrained node, so several nodes have more than one dependent and
/// several share one.
fn rich_view() -> InfinityView<'static> {
    let mut module = InfinityModule::new();
    let leaf_int = module.push(Inode::Int(1));
    let leaf_str = module.push(Inode::Str("s".into()));
    let leaf_bool = module.push(Inode::Bool(true));
    let arr1 = module.push(Inode::Array {
        elements: vec![leaf_int, leaf_str],
    });
    let arr2 = module.push(Inode::Array {
        elements: vec![leaf_str, leaf_bool],
    });
    let tbl = module.push(Inode::Table {
        fields: vec![("a".into(), leaf_int), ("b".into(), arr1)],
    });
    let r = module.push(Inode::Ref(leaf_bool));
    let constrained = module.push(Inode::Constrained {
        target: leaf_int,
        constraint: Constraint::Odd,
    });
    let root = module.push(Inode::Array {
        elements: vec![arr2, tbl, r, constrained],
    });
    module.set_root(Some(root));
    view_of(&module)
}

#[test]
fn dependents_matches_children_oracle_on_a_diamond() {
    let (view, a, b, c, d) = diamond_view();
    // Hand-computed expectations for the diamond.
    let mut d_dependents = vec![b, c];
    d_dependents.sort_unstable();
    assert_eq!(
        view.dependents(d).expect("dependents"),
        d_dependents,
        "D is referenced by B and C"
    );
    assert_eq!(
        view.dependents(b).expect("dependents"),
        vec![a],
        "B is referenced only by A"
    );
    assert_eq!(
        view.dependents(c).expect("dependents"),
        vec![a],
        "C is referenced only by A"
    );
    assert_eq!(
        view.dependents(a).expect("dependents"),
        Vec::<NodeId>::new(),
        "nothing references the root A"
    );
    // The oracle agrees for every node, not just the named ones.
    for index in 0..view.node_count() {
        let id = NodeId(index);
        assert_eq!(
            view.dependents(id).expect("dependents"),
            children_oracle(&view, id),
            "dependents({id:?}) disagrees with the children-oracle"
        );
    }
}

#[test]
fn dependents_agrees_with_edges_for_every_node() {
    let view = rich_view();
    let edges = view.edges().expect("edges");
    assert_eq!(
        edges,
        edges_from_children(&view),
        "the stored edge table disagrees with the children-oracle"
    );
    for index in 0..view.node_count() {
        let id = NodeId(index);
        let mut expected: Vec<NodeId> = edges
            .iter()
            .filter(|(from, _)| *from == id)
            .map(|(_, to)| *to)
            .collect();
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(
            view.dependents(id).expect("dependents"),
            expected,
            "dependents({id:?}) disagrees with the stored edge table"
        );
        assert_eq!(
            view.dependents(id).expect("dependents"),
            children_oracle(&view, id),
            "dependents({id:?}) disagrees with the children-oracle"
        );
    }
}

#[test]
fn dependents_map_agrees_with_dependents_for_every_node() {
    let view = rich_view();
    let map = view.dependents_map().expect("dependents_map");
    assert_eq!(
        map.len() as u32,
        view.node_count(),
        "one map entry per node, indexed by node id"
    );
    for index in 0..view.node_count() {
        let id = NodeId(index);
        let entry = &map[id.index()];
        assert_eq!(
            *entry,
            view.dependents(id).expect("dependents"),
            "dependents_map()[{index}] disagrees with dependents()"
        );
        let mut sorted = entry.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            *entry, sorted,
            "dependents_map()[{index}] is not sorted and deduplicated"
        );
    }
    // The shared leaves are the ones with more than one dependent.
    let multi: Vec<usize> = map
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.len() > 1)
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        multi.len(),
        3,
        "exactly three nodes have more than one dependent (the three shared leaves)"
    );
}

#[test]
fn dependents_of_the_root_and_of_an_unknown_id_is_empty() {
    let view = rich_view();
    let root = (0..view.node_count())
        .map(NodeId)
        .find(|id| view.dependents(*id).expect("dependents").is_empty())
        .expect("some node has no dependents");
    assert_eq!(
        view.children(root).expect("children").len(),
        4,
        "the node with no dependents is the four-child root"
    );
    // Preserved lenient behaviour (same as the pre-fix code, which also
    // filtered the table without validating the id): an id no edge names
    // simply has no dependents, it is not an error.
    assert_eq!(
        view.dependents(NodeId(999_999)).expect("dependents"),
        Vec::<NodeId>::new(),
        "an unknown id has no dependents"
    );
}

#[test]
fn edges_still_returns_the_full_stored_table() {
    // `edges()` itself is unchanged by this fix — it still materialises
    // the whole table, by design. This pins that behaviour so the fix
    // cannot silently change what `edges()` returns.
    let view = rich_view();
    let edges = view.edges().expect("edges");
    assert_eq!(
        edges,
        edges_from_children(&view),
        "edges() no longer returns the stored edge table"
    );
    assert_eq!(edges.len(), 12, "the rich fixture has exactly 12 edges");
    let mut sorted = edges.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(edges, sorted, "edges() is sorted and deduplicated");
}

#[test]
fn dependents_does_not_materialise_the_edge_table() {
    // One wide array over 50,000 distinct leaves: a 50,000-edge table
    // (400 KiB on the wire). Every leaf has exactly one dependent (the
    // root array), so `dependents(leaf)` has a one-element result — but
    // the old code allocated the whole 400 KiB table to find it.
    const LEAVES: usize = 50_000;
    let mut module = InfinityModule::new();
    let mut elements = Vec::with_capacity(LEAVES);
    for value in 0..LEAVES as i64 {
        elements.push(module.push(Inode::Int(value)));
    }
    let root = module.push(Inode::Array { elements });
    module.set_root(Some(root));
    let view = view_of(&module);
    assert_eq!(
        view.edges().expect("edges").len(),
        LEAVES,
        "the wide fixture has one edge per leaf"
    );
    let leaf = (0..view.node_count())
        .map(NodeId)
        .find(|id| view.node(*id).map(|node| node.kind == 2).unwrap_or(false))
        .expect("the fixture has Int leaves");
    let (dependents, bytes) = allocated_during(|| view.dependents(leaf).expect("dependents"));
    assert_eq!(
        dependents.len(),
        1,
        "a leaf has exactly one dependent (the root array)"
    );
    assert!(
        bytes < 4096,
        "dependents() allocated {bytes} bytes for a one-element result over a {LEAVES}-edge table — the full table was materialised (INF-L08)"
    );
    // The empty case is sharpest: the old code still allocated the whole
    // table to return nothing.
    let root_id = (0..view.node_count())
        .map(NodeId)
        .find(|id| view.dependents(*id).expect("dependents").is_empty())
        .expect("some node has no dependents");
    let (empty, empty_bytes) = allocated_during(|| view.dependents(root_id).expect("dependents"));
    assert!(empty.is_empty(), "the root has no dependents");
    assert!(
        empty_bytes < 1024,
        "dependents() of the root allocated {empty_bytes} bytes for an empty result over a {LEAVES}-edge table (INF-L08)"
    );
}
