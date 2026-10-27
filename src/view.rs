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

    /// Child count for container kinds.
    pub fn count(&self) -> u64 {
        match self.kind {
            7 | 8 | 14 | 20 => self.b,
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
    pub fn new(buf: &'a [u8], limits: crate::layout::Limits) -> Result<Self> {
        let opts = DecodeOpts {
            limits,
            verify_hash: true,
            verify_canonical: false,
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

    pub fn content_hash(&self) -> [u8; 32] {
        self.validated.header().content_hash
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

    pub fn annotations(&self) -> Result<Vec<(NodeId, u32, u32)>> {
        let mut out = Vec::new();
        for index in 0..self
            .validated
            .span(crate::layout::Section::Annotations)
            .count
        {
            let (node, kind, a, _b) = self.validated.annotation(index)?;
            out.push((NodeId(node), kind, a));
        }
        Ok(out)
    }

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
            4 | 13 | 23 => Some(node.aux),
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
    pub fn dependents(&self, id: NodeId) -> Result<Vec<NodeId>> {
        let mut out = Vec::new();
        for (from, to) in self.edges()? {
            if from == id {
                out.push(to);
            }
        }
        out.sort_unstable();
        out.dedup();
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
    pub fn edges(&self) -> Result<Vec<(NodeId, NodeId)>> {
        let mut out = Vec::new();
        for index in 0..self.validated.span(crate::layout::Section::Edges).count {
            let (from, to) = self.validated.edge(index)?;
            out.push((NodeId(from), NodeId(to)));
        }
        Ok(out)
    }

    /// Provenance entries, borrowed.
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
