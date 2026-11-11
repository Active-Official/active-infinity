//! Zero-copy views over a validated image.
//!
//! A [`InfinityView`] can only be built from bytes that passed
//! [`crate::validate::validate`], so every accessor is bounds-checked by construction.
//! Variable-length payloads (strings, blobs, secrets) are returned as borrows
//! into the caller's buffer — no copy, no alignment requirement, and no
//! `unsafe`: the format stores integers little-endian and the view decodes them
//! with `from_le_bytes`, which makes the zero-copy contract memory-safe by
//! construction (ADR-0004).

// Module-level: item docs for this layer live in docs/spec/layout.md and
// docs/spec/streaming.md; the crate root keeps deny(missing_docs) for the
// hand-written public surface.
#![allow(missing_docs)]

use crate::error::{Error, Result};
use crate::ir::{NodeId, ProvEntry, Provenance};
use crate::layout::{DecodeOpts, Meta};
use crate::validate::Validated;

/// A node record in a validated image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeView {
    pub id: NodeId,
    pub kind: u8,
    pub flags: u8,
    pub aux: u32,
    pub a: u64,
    pub b: u64,
    pub c: u64,
}

impl NodeView {
    pub fn kind_name(&self) -> &'static str {
        node_kind_name(self.kind)
    }

    /// Child count for the kind, matching [`InfinityView::children`].
    ///
    /// Every kind that carries references reports them here; a caller that sizes
    /// or bounds work by `count()` must not skip the children of a scalar that
    /// points at another node.
    /// Number of child entries the record declares.
    ///
    /// This is an **upper bound** on node references for a mixed record: an
    /// `Interpolate` counts its literal parts, a `Constrained` counts its target plus every aux
    /// entry (some are strings), a `Patch` counts path aux entries. Use
    /// [`InfinityView::children`] for the node references themselves.
    pub fn count(&self) -> u64 {
        match self.kind {
            7 | 8 | 14 | 20 => self.b,
            15 | 24 => 2,
            17 => self.c.saturating_add(1),
            18 | 19 => self.c,
            12 => u64::from(self.a != u32::MAX as u64),
            6 | 10 | 11 | 16 | 21 | 22 => 1,
            _ => 0,
        }
    }
}

/// A validated, borrow-only module view.
#[derive(Debug, Clone, Copy)]
pub struct InfinityView<'a> {
    validated: Validated<'a>,
}

impl<'a> InfinityView<'a> {
    /// Validate `buf` and borrow it.
    ///
    /// The default decode options apply (INF-02, INF-12): the content hash
    /// is verified **and** canonicality is proven, so a structurally valid
    /// but non-canonical image is refused with `infinity/not-canonical`
    /// instead of yielding a view. That is what makes the provenance a
    /// `new`-built view reports safe to display: a canonical image's
    /// provenance was redacted against the module's secrets at encode
    /// time, so `provenance_entries()` cannot return an unredacted copy
    /// of a secret through this constructor. A caller that must read a
    /// trusted non-canonical image (migration, repair) opts out
    /// explicitly with [`InfinityView::with_opts`] and
    /// `verify_canonical: false` — and then owns redaction (see
    /// `provenance_entries()`).
    pub fn new(buf: &'a [u8], limits: crate::layout::Limits) -> Result<Self> {
        let opts = DecodeOpts {
            limits,
            ..DecodeOpts::default()
        };
        Ok(Self {
            validated: Validated::new(buf, opts)?,
        })
    }

    /// Validate `buf` and borrow it, with full option control.
    pub fn with_opts(buf: &'a [u8], opts: DecodeOpts) -> Result<Self> {
        Ok(Self {
            validated: Validated::new(buf, opts)?,
        })
    }

    /// Borrow an image that was already validated.
    pub fn from_validated(validated: Validated<'a>) -> Self {
        Self { validated }
    }

    pub fn validated(&self) -> &Validated<'a> {
        &self.validated
    }

    pub fn buf(&self) -> &'a [u8] {
        self.validated.buf()
    }

    pub fn meta(&self) -> Meta {
        self.validated.meta()
    }

    /// The header's content hash.
    ///
    /// With [`InfinityView::with_opts`] and `verify_hash: false` this is a
    /// claim the reader did not check; [`InfinityView::hash_verified`] reports
    /// which case applies.
    pub fn content_hash(&self) -> [u8; 32] {
        self.validated.header().content_hash
    }

    /// Whether [`InfinityView::content_hash`] was recomputed and checked.
    pub fn hash_verified(&self) -> bool {
        self.validated.hash_verified()
    }

    pub fn content_hash_hex(&self) -> String {
        crate::ir::hash_hex(&self.content_hash())
    }

    pub fn node_count(&self) -> u32 {
        self.validated.node_count()
    }

    pub fn root(&self) -> Result<Option<NodeId>> {
        self.validated.root()
    }

    pub fn bindings(&self) -> Result<Vec<(&'a str, NodeId)>> {
        self.validated.bindings()
    }

    /// Annotation records: `(subject, kind, a, b)`.
    ///
    /// `b` is the constraint expression node for a constraint annotation; dropping
    /// it would hide the expression a caller is expected to check.
    pub fn annotations(&self) -> Result<Vec<(NodeId, u32, u32, u32)>> {
        let mut out = Vec::new();
        for index in 0..self
            .validated
            .span(crate::layout::Section::Annotations)
            .count
        {
            let (node, kind, a, b) = self.validated.annotation(index)?;
            out.push((NodeId(node), kind, a, b));
        }
        Ok(out)
    }

    /// The stored provenance block, verbatim: this is the raw accessor.
    ///
    /// For a view built by [`InfinityView::new`] the image is canonical,
    /// so the block was redacted against the module's secrets at encode
    /// time. For a leniently built view ([`InfinityView::with_opts`] with
    /// `verify_canonical: false`, or [`InfinityView::from_validated`]
    /// over leniently validated bytes) it may carry unredacted
    /// provenance — use `interop::provenance_json` for output that leaves
    /// the process.
    pub fn provenance(&self) -> Result<Option<Provenance>> {
        self.validated.provenance()
    }

    /// Read a node record.
    pub fn node(&self, id: NodeId) -> Result<NodeView> {
        let rec = self.validated.node(id)?;
        Ok(NodeView {
            id,
            kind: rec.kind,
            flags: rec.flags,
            aux: rec.aux,
            a: rec.a,
            b: rec.b,
            c: rec.c,
        })
    }

    /// Borrow string `id` from the image (zero copy).
    pub fn string(&self, id: u32) -> Result<&'a str> {
        self.validated.string(id)
    }

    /// Borrow blob payload `id` from the image (zero copy).
    pub fn blob(&self, id: u32) -> Result<&'a [u8]> {
        self.validated.blob(id)
    }

    /// The string id a node points at, for the string-bearing scalar kinds.
    pub fn node_string_id(&self, id: NodeId) -> Result<Option<u32>> {
        let node = self.node(id)?;
        Ok(match node.kind {
            // 12 is `Env`, whose variable name is a string id in `aux`.
            4 | 12 | 13 | 23 => Some(node.aux),
            _ => None,
        })
    }

    /// Borrow the primary string of a string-bearing node (zero copy).
    pub fn primary_string(&self, id: NodeId) -> Result<Option<&'a str>> {
        match self.node_string_id(id)? {
            Some(sid) => Ok(Some(self.string(sid)?)),
            None => Ok(None),
        }
    }

    /// Child ids of a container node, in stored order.
    pub fn children(&self, id: NodeId) -> Result<Vec<NodeId>> {
        let node = self.node(id)?;
        let mut out = Vec::new();
        match node.kind {
            6 => out.push(NodeId(node.aux)),
            7 => {
                for offset in node.a..node.a + node.b {
                    out.push(NodeId(self.validated.child(offset as u32)?));
                }
            }
            8 | 20 => {
                for offset in node.a..node.a + node.b {
                    out.push(self.validated.field(offset as u32)?.1);
                }
            }
            10 | 11 | 12 | 14 | 15 | 16 | 17 | 18 | 19 | 21 | 22 | 24 => {
                let rec = self.validated.node(id)?;
                for child in self.validated.node_children(id.0, &rec)? {
                    out.push(NodeId(child));
                }
            }
            _ => {}
        }
        Ok(out)
    }

    /// Table fields of a table node, borrowing names from the image.
    pub fn fields(&self, id: NodeId) -> Result<Vec<(&'a str, NodeId)>> {
        let node = self.node(id)?;
        if node.kind != 8 && node.kind != 20 {
            return Err(Error::Node {
                id: id.0,
                reason: "not a table node",
            });
        }
        let mut out = Vec::with_capacity(node.b as usize);
        for offset in node.a..node.a + node.b {
            let (name, child) = self.validated.field(offset as u32)?;
            out.push((self.string(name)?, child));
        }
        Ok(out)
    }

    /// Derived dependents of a node (nodes that reference it), sorted.
    ///
    /// Scans the stored edge table directly, one entry at a time
    /// (`Validated::edge(i)`) — it never materialises the full table the
    /// way `edges()` does (INF-L08). Time is O(E) per call: the stored
    /// table carries no reverse index, so every edge must be examined.
    /// Allocation is O(result). A caller that needs the dependents of many
    /// nodes should use `dependents_map()` instead, which pays the O(E)
    /// scan once for every node.
    pub fn dependents(&self, id: NodeId) -> Result<Vec<NodeId>> {
        let mut out = Vec::new();
        for index in 0..self.validated.span(crate::layout::Section::Edges).count {
            let (from, to) = self.validated.edge(index)?;
            if from == id.0 {
                out.push(NodeId(to));
            }
        }
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    /// Every node's dependents in a single scan of the stored edge table.
    ///
    /// The bulk form of `dependents()` (INF-L08): one O(E) pass over the
    /// table builds the whole reverse map, instead of one O(E) scan per
    /// node for a caller looping `dependents()` over all nodes (O(V x E)).
    /// Returns one entry per node, indexed by node id; each entry is
    /// sorted and deduplicated, exactly as `dependents()` returns it.
    /// The map itself is O(V + E) by construction — it holds every edge
    /// once, grouped by its dependency.
    pub fn dependents_map(&self) -> Result<Vec<Vec<NodeId>>> {
        let mut out: Vec<Vec<NodeId>> = vec![Vec::new(); self.validated.node_count() as usize];
        for index in 0..self.validated.span(crate::layout::Section::Edges).count {
            let (from, to) = self.validated.edge(index)?;
            let dependents = out.get_mut(from as usize).ok_or(Error::Edge { from, to })?;
            dependents.push(NodeId(to));
        }
        for dependents in &mut out {
            dependents.sort_unstable();
            dependents.dedup();
        }
        Ok(out)
    }

    /// Derived dependencies of a node (nodes it references), sorted.
    pub fn dependencies(&self, id: NodeId) -> Result<Vec<NodeId>> {
        let mut out = self.children(id)?;
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    /// All edges, as (dependency, dependent).
    ///
    /// This materialises the whole table (one entry per stored edge, up
    /// to `max_edges`), by design: a caller that only needs one node's
    /// dependents should use `dependents()` — which scans the table
    /// without materialising it — or `dependents_map()` for the bulk form
    /// (INF-L08).
    pub fn edges(&self) -> Result<Vec<(NodeId, NodeId)>> {
        let mut out = Vec::new();
        for index in 0..self.validated.span(crate::layout::Section::Edges).count {
            let (from, to) = self.validated.edge(index)?;
            out.push((NodeId(from), NodeId(to)));
        }
        Ok(out)
    }

    /// Provenance entries, borrowed.
    ///
    /// For a view built by [`InfinityView::new`] the image is canonical,
    /// so the entries are redacted-by-construction: canonicalization
    /// redacts provenance against the module's secrets at encode time,
    /// and `new` refuses a non-canonical image instead of yielding a
    /// view (INF-12). A view built leniently —
    /// [`InfinityView::with_opts`] with `verify_canonical: false`, or
    /// [`InfinityView::from_validated`] over leniently validated bytes —
    /// returns the stored entries as they are, and a caller that builds
    /// such a view must use `interop::provenance_json` for output that
    /// leaves the process.
    pub fn provenance_entries(&self) -> Result<Vec<(String, ProvEntry)>> {
        Ok(self
            .validated
            .provenance()?
            .map(|prov| {
                prov.entries
                    .into_iter()
                    .map(|entry| (entry.key.clone(), entry))
                    .collect()
            })
            .unwrap_or_default())
    }
}

/// Display name of a node kind.
pub const fn node_kind_name(kind: u8) -> &'static str {
    match kind {
        0 => "Null",
        1 => "Bool",
        2 => "Int",
        3 => "Float",
        4 => "Str",
        5 => "DurationMs",
        6 => "Quantity",
        7 => "Array",
        8 => "Table",
        9 => "Secret",
        10 => "SecretRef",
        11 => "Ref",
        12 => "Env",
        13 => "Ident",
        14 => "Interpolate",
        15 => "Binary",
        16 => "Unary",
        17 => "Constrained",
        18 => "Patch",
        19 => "SchemaField",
        20 => "SchemaTable",
        21 => "SchemaArray",
        22 => "Semantic",
        23 => "Blob",
        24 => "ContentAddressed",
        _ => "Unknown",
    }
}
