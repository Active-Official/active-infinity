//! Structural validation of untrusted images.
//!
//! Validation is total and fail-closed: every byte of the buffer is accounted
//! for before any caller receives a node, a string, a blob or a
//! [`crate::view::InfinityView`]. The checker enforces the canonical form as
//! well as safety — sorted symbol tables, zeroed padding, zeroed unused record
//! fields — so a validated image cannot carry covert payload in slack space,
//! and a validated image re-encodes to itself.
//!
//! Work is bounded by [`Limits`]: counts are checked against the remaining
//! bytes before allocation, traversals are iterative (no recursion), and every
//! reference is bounds-checked.

// Module-level: item docs for this layer live in docs/spec/layout.md and
// docs/spec/streaming.md; the crate root keeps deny(missing_docs) for the
// hand-written public surface.
#![allow(missing_docs)]

use crate::encode::{hash_image, NodeRec};
use crate::error::{Error, Result};
use crate::ir::{NodeId, ProvValue, Provenance};
use crate::layout::{
    align8, dialect_hash, read_u32, read_u64, Header, Limits, Meta, Section, BLOB_ENTRY_SIZE,
    EXT_DIR_SIZE, FIELD_SIZE, FLAG_ANNOTATIONS, FLAG_CANONICAL, FLAG_EXTENSIONS, FLAG_PROVENANCE,
    FLAG_SECRETS, HEADER_SIZE, NODE_FLAG_0, NODE_FLAG_1, NODE_FLAG_KNOWN, NODE_RECORD_SIZE,
    PROV_ENTRY_SIZE, PROV_HEADER_SIZE, SECTION_COUNT,
};
use crate::unit::{UnitTag, UNIT_NAMED};

/// A validated image plus zero-copy accessors.
#[derive(Debug, Clone, Copy)]
pub struct Validated<'a> {
    buf: &'a [u8],
    header: Header,
    ends: [u64; SECTION_COUNT],
    limits: Limits,
}

impl<'a> Validated<'a> {
    /// Parse and validate `buf`.
    pub fn new(buf: &'a [u8], opts: crate::layout::DecodeOpts) -> Result<Self> {
        opts.limits.check()?;
        let header = Header::parse(buf)?;
        if header.dialect_hash != dialect_hash() {
            return Err(Error::DialectMismatch(header.dialect_hash));
        }
        let limits = opts.limits;
        if buf.len() as u64 > limits.max_total_bytes {
            return Err(Error::Limit {
                kind: "total bytes",
                limit: limits.max_total_bytes,
            });
        }
        validate_counts(&header, limits)?;
        let ends = validate_layout(buf, &header)?;
        let validated = Validated {
            buf,
            header,
            ends,
            limits,
        };

        if header.flags & FLAG_ANNOTATIONS != 0 && validated.span(Section::Annotations).count == 0 {
            return Err(Error::Annotation {
                id: 0,
                reason: "annotations flag set with an empty table",
            });
        }
        if header.flags & FLAG_ANNOTATIONS == 0 && validated.span(Section::Annotations).count != 0 {
            return Err(Error::Annotation {
                id: 0,
                reason: "annotations present without the flag",
            });
        }
        if header.flags & FLAG_PROVENANCE != 0 && validated.span(Section::Provenance).count == 0 {
            return Err(Error::Provenance("provenance flag with an empty block"));
        }
        if header.flags & FLAG_PROVENANCE == 0 && validated.span(Section::Provenance).count != 0 {
            return Err(Error::Provenance("provenance block without the flag"));
        }
        if header.flags & FLAG_EXTENSIONS != 0 && validated.span(Section::Extensions).count == 0 {
            return Err(Error::Extension {
                tag: 0,
                reason: "extensions flag with an empty directory",
            });
        }
        if header.flags & FLAG_EXTENSIONS == 0 && validated.span(Section::Extensions).count != 0 {
            return Err(Error::Extension {
                tag: 0,
                reason: "extension blocks without the flag",
            });
        }
        if header.flags & FLAG_SECRETS != 0 && validated.span(Section::Secrets).count == 0 {
            return Err(Error::SecretEntry(0));
        }
        if header.flags & FLAG_SECRETS == 0 && validated.span(Section::Secrets).count != 0 {
            return Err(Error::SecretEntry(0));
        }

        validated.check_strings()?;
        validated.check_units(limits)?;
        validated.check_types(limits)?;
        validated.check_numbers()?;
        validated.check_hashes()?;
        validated.check_secrets(limits)?;
        validated.check_blobs(limits)?;
        validated.check_nodes(limits)?;
        validated.check_fields()?;
        validated.check_parts()?;
        validated.check_edges()?;
        validated.check_annotations()?;
        validated.check_provenance(limits)?;
        validated.check_extensions()?;
        validated.check_reachability(limits)?;
        validated.check_depth(limits)?;

        if opts.verify_hash {
            let computed = hash_image(buf)?;
            if computed != header.content_hash {
                return Err(Error::HashMismatch);
            }
        }
        if opts.verify_canonical && header.flags & FLAG_CANONICAL != 0 {
            let module = crate::decode::decode_validated(&validated)?;
            let image = crate::encode::encode_with(
                &module,
                crate::layout::EncodeOpts {
                    write_hash: true,
                    mark_canonical: true,
                    streamed: header.flags & crate::layout::FLAG_STREAMED != 0,
                },
            )?;
            if image != buf {
                return Err(Error::NotCanonical);
            }
        }
        Ok(validated)
    }

    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }

    /// The limits this image was validated against.
    pub fn limits_snapshot(&self) -> Limits {
        self.limits
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn limits_span(&self, section: Section) -> (u32, u32) {
        let span = self.header.span(section);
        (span.offset, span.count)
    }

    pub fn span(&self, section: Section) -> crate::layout::SectionSpan {
        self.header.span(section)
    }

    /// Byte length of a section body (from its offset to its computed end).
    pub fn section_len(&self, section: Section) -> u64 {
        self.ends[section as usize] - self.header.span(section).offset as u64
    }

    pub fn section(&self, section: Section) -> &'a [u8] {
        let (offset, _) = self.limits_span(section);
        let end = self.ends[section as usize];
        &self.buf[offset as usize..end as usize]
    }

    /// `Meta` describing this image.
    pub fn meta(&self) -> Meta {
        let header = &self.header;
        Meta {
            flags: header.flags,
            major: header.major,
            minor: header.minor,
            dialect_hash: header.dialect_hash,
            content_hash: header.content_hash,
            total_size: header.total_size,
            nodes: header.span(Section::Nodes).count,
            edges: header.span(Section::Edges).count,
            strings: header.span(Section::Strings).count,
            string_bytes: self.string_heap_len(),
            blobs: header.span(Section::Blobs).count,
            blob_bytes: self.blob_heap_len(),
            annotations: header.span(Section::Annotations).count,
            units: header.span(Section::Units).count,
            types: header.span(Section::Types).count,
            secrets: header.span(Section::Secrets).count,
            extensions: header.span(Section::Extensions).count,
        }
    }

    pub fn node_count(&self) -> u32 {
        self.header.span(Section::Nodes).count
    }

    /// Read a node record.
    pub(crate) fn node(&self, id: NodeId) -> Result<NodeRec> {
        let count = self.node_count();
        if id.0 >= count {
            return Err(Error::NodeRef(id.0));
        }
        let offset =
            self.header.span(Section::Nodes).offset as usize + id.index() * NODE_RECORD_SIZE;
        let rec = &self.buf[offset..offset + NODE_RECORD_SIZE];
        Ok(NodeRec {
            kind: rec[0],
            flags: rec[1],
            aux: u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]),
            a: u64::from_le_bytes(rec[8..16].try_into().expect("8 bytes")),
            b: u64::from_le_bytes(rec[16..24].try_into().expect("8 bytes")),
            c: u64::from_le_bytes(rec[24..32].try_into().expect("8 bytes")),
        })
    }

    /// Read a child index entry.
    pub fn child(&self, index: u32) -> Result<u32> {
        let count = self.header.span(Section::Children).count;
        if index >= count {
            return Err(Error::Node {
                id: index,
                reason: "child index out of range",
            });
        }
        let offset = self.header.span(Section::Children).offset as usize + index as usize * 4;
        read_u32(self.buf, offset)
    }

    /// Read a field entry (string id, node id).
    pub fn field(&self, index: u32) -> Result<(u32, NodeId)> {
        let count = self.header.span(Section::Fields).count;
        if index >= count {
            return Err(Error::Node {
                id: index,
                reason: "field index out of range",
            });
        }
        let offset =
            self.header.span(Section::Fields).offset as usize + index as usize * FIELD_SIZE;
        let name = read_u32(self.buf, offset)?;
        let node = read_u32(self.buf, offset + 8)?;
        Ok((name, NodeId(node)))
    }

    /// Read an interpolation part (tag, value).
    pub fn part(&self, index: u32) -> Result<(u32, u32)> {
        let count = self.header.span(Section::Parts).count;
        if index >= count {
            return Err(Error::Node {
                id: index,
                reason: "part index out of range",
            });
        }
        let offset = self.header.span(Section::Parts).offset as usize + index as usize * 8;
        Ok((read_u32(self.buf, offset)?, read_u32(self.buf, offset + 4)?))
    }

    /// Read an edge (from, to).
    pub fn edge(&self, index: u32) -> Result<(u32, u32)> {
        let count = self.header.span(Section::Edges).count;
        if index >= count {
            return Err(Error::Edge {
                from: index,
                to: index,
            });
        }
        let offset = self.header.span(Section::Edges).offset as usize + index as usize * 8;
        Ok((read_u32(self.buf, offset)?, read_u32(self.buf, offset + 4)?))
    }

    /// Byte length of the string heap (excluding the offset table).
    pub fn string_heap_len(&self) -> u32 {
        let count = self.header.span(Section::Strings).count;
        if count == 0 {
            return 0;
        }
        let offset = self.header.span(Section::Strings).offset as usize + count as usize * 4;
        read_u32(self.buf, offset).unwrap_or(0)
    }

    /// Borrow string `id` directly from the buffer (zero copy).
    pub fn string(&self, id: u32) -> Result<&'a str> {
        let count = self.header.span(Section::Strings).count;
        if id >= count {
            return Err(Error::StringRef(id));
        }
        let table = self.header.span(Section::Strings).offset as usize;
        let start = read_u32(self.buf, table + id as usize * 4)?;
        let end = read_u32(self.buf, table + id as usize * 4 + 4)?;
        let heap = table + (count as usize + 1) * 4;
        let bytes = &self.buf[heap + start as usize..heap + end as usize];
        std::str::from_utf8(bytes).map_err(|_| Error::Utf8 {
            offset: (heap + start as usize) as u64,
        })
    }

    /// Total blob payload heap length.
    pub fn blob_heap_len(&self) -> u32 {
        let count = self.header.span(Section::Blobs).count;
        if count == 0 {
            return 0;
        }
        let table = self.header.span(Section::Blobs).offset as usize;
        let last = table + (count as usize - 1) * BLOB_ENTRY_SIZE;
        let off = read_u32(self.buf, last + 32).unwrap_or(0);
        let len = read_u32(self.buf, last + 36).unwrap_or(0);
        off.saturating_add(len)
    }

    /// Read a blob index entry: (hash, offset-in-heap, length).
    pub fn blob_entry(&self, id: u32) -> Result<([u8; 32], u32, u32)> {
        let count = self.header.span(Section::Blobs).count;
        if id >= count {
            return Err(Error::Blob {
                id,
                reason: "index out of range",
            });
        }
        let offset =
            self.header.span(Section::Blobs).offset as usize + id as usize * BLOB_ENTRY_SIZE;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&self.buf[offset..offset + 32]);
        Ok((
            hash,
            read_u32(self.buf, offset + 32)?,
            read_u32(self.buf, offset + 36)?,
        ))
    }

    /// Borrow a blob payload directly from the buffer (zero copy).
    pub fn blob(&self, id: u32) -> Result<&'a [u8]> {
        let count = self.header.span(Section::Blobs).count;
        let (_, off, len) = self.blob_entry(id)?;
        let heap =
            self.header.span(Section::Blobs).offset as usize + count as usize * BLOB_ENTRY_SIZE;
        let start = heap + off as usize;
        let end = start + len as usize;
        if end > self.ends[Section::Blobs as usize] as usize {
            return Err(Error::Blob {
                id,
                reason: "payload out of range",
            });
        }
        Ok(&self.buf[start..end])
    }

    /// Read an annotation record: (node, kind, a, b).
    pub fn annotation(&self, index: u32) -> Result<(u32, u32, u32, u32)> {
        let count = self.header.span(Section::Annotations).count;
        if index >= count {
            return Err(Error::Annotation {
                id: index,
                reason: "index out of range",
            });
        }
        let offset = self.header.span(Section::Annotations).offset as usize + index as usize * 16;
        Ok((
            read_u32(self.buf, offset)?,
            read_u32(self.buf, offset + 4)?,
            read_u32(self.buf, offset + 8)?,
            read_u32(self.buf, offset + 12)?,
        ))
    }

    /// Resolve a unit table entry.
    pub fn unit(&self, id: u32) -> Result<UnitTag> {
        let count = self.header.span(Section::Units).count;
        if id >= count {
            return Err(Error::UnitRef(id));
        }
        let offset = self.header.span(Section::Units).offset as usize + id as usize * 8;
        let disc = read_u32(self.buf, offset)?;
        let name = read_u32(self.buf, offset + 4)?;
        if disc == UNIT_NAMED {
            Ok(UnitTag::Named(self.string(name)?.to_string()))
        } else {
            UnitTag::from_discriminant(disc).ok_or(Error::UnknownUnit(disc))
        }
    }

    /// Read a type table entry: (code, flags, aux start, aux count).
    pub fn type_entry(&self, id: u32) -> Result<(u32, u32, u32, u32)> {
        let count = self.header.span(Section::Types).count;
        if id >= count {
            return Err(Error::Type {
                id,
                reason: "index out of range",
            });
        }
        let offset = self.header.span(Section::Types).offset as usize + id as usize * 16;
        Ok((
            read_u32(self.buf, offset)?,
            read_u32(self.buf, offset + 4)?,
            read_u32(self.buf, offset + 8)?,
            read_u32(self.buf, offset + 12)?,
        ))
    }

    /// Read an aux record.
    pub fn aux(&self, index: u32) -> Result<(u32, u32)> {
        let count = self.header.span(Section::Aux).count;
        if index >= count {
            return Err(Error::Node {
                id: index,
                reason: "aux index out of range",
            });
        }
        let offset = self.header.span(Section::Aux).offset as usize + index as usize * 8;
        Ok((read_u32(self.buf, offset)?, read_u32(self.buf, offset + 4)?))
    }

    /// Read a number table entry.
    pub fn number(&self, index: u32) -> Result<i64> {
        let count = self.header.span(Section::Numbers).count;
        if index >= count {
            return Err(Error::Node {
                id: index,
                reason: "number index out of range",
            });
        }
        let offset = self.header.span(Section::Numbers).offset as usize + index as usize * 8;
        Ok(read_u64(self.buf, offset)? as i64)
    }

    /// Borrow a secret's raw bytes (crate-internal: no public unlock API).
    pub fn secret(&self, id: u32) -> Result<&'a [u8]> {
        let count = self.header.span(Section::Secrets).count;
        if id >= count {
            return Err(Error::SecretEntry(id));
        }
        let table = self.header.span(Section::Secrets).offset as usize;
        let off = read_u32(self.buf, table + id as usize * 8)?;
        let len = read_u32(self.buf, table + id as usize * 8 + 4)?;
        let heap = table + count as usize * 8;
        let start = heap + off as usize;
        let end = start + len as usize;
        if end > self.ends[Section::Secrets as usize] as usize {
            return Err(Error::SecretEntry(id));
        }
        Ok(&self.buf[start..end])
    }

    /// Read a hash table entry.
    pub fn hash_entry(&self, index: u32) -> Result<[u8; 32]> {
        let count = self.header.span(Section::Hashes).count;
        if index >= count {
            return Err(Error::Provenance("hash index out of range"));
        }
        let offset = self.header.span(Section::Hashes).offset as usize + index as usize * 32;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&self.buf[offset..offset + 32]);
        Ok(hash)
    }

    /// Parse the provenance block.
    pub fn provenance(&self) -> Result<Option<Provenance>> {
        let len = self.header.span(Section::Provenance).count as usize;
        if len == 0 {
            return Ok(None);
        }
        let start = self.header.span(Section::Provenance).offset as usize;
        if len < PROV_HEADER_SIZE {
            return Err(Error::Provenance("block shorter than its header"));
        }
        let block = &self.buf[start..start + len];
        let version = read_u32(block, 0)?;
        if version != 1 {
            return Err(Error::Provenance("unsupported provenance version"));
        }
        let count = read_u32(block, 4)?;
        let timestamp_ms = read_u64(block, 8)?;
        let read_sid = |offset: usize| -> Result<Option<String>> {
            let id = read_u32(block, offset)?;
            if id == u32::MAX {
                Ok(None)
            } else {
                Ok(Some(self.string(id)?.to_string()))
            }
        };
        let producer = read_sid(16)?;
        let model = read_sid(20)?;
        let tool = read_sid(24)?;
        let flags = read_u32(block, 28)?;
        if flags & !1 != 0 {
            return Err(Error::Provenance("unknown provenance flags"));
        }
        let parent = if flags & 1 != 0 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&block[32..64]);
            Some(hash)
        } else {
            if block[32..64].iter().any(|byte| *byte != 0) {
                return Err(Error::Provenance("parent hash without the flag"));
            }
            None
        };
        if block[64..PROV_HEADER_SIZE].iter().any(|byte| *byte != 0) {
            return Err(Error::Provenance("non-zero provenance reserved bytes"));
        }
        let mut entries = Vec::with_capacity(count.min(1024) as usize);
        for index in 0..count as usize {
            let offset = PROV_HEADER_SIZE + index * PROV_ENTRY_SIZE;
            if offset + PROV_ENTRY_SIZE > block.len() {
                return Err(Error::Provenance("entry exceeds block"));
            }
            let kind = read_u32(block, offset)?;
            let key = self.string(read_u32(block, offset + 4)?)?.to_string();
            let a = read_u32(block, offset + 8)?;
            let b = read_u32(block, offset + 12)?;
            if kind > 3 {
                // Kinds 4+ are reserved. Accepting them would decode to a
                // value that re-encodes as kind 3, i.e. a non-canonical image.
                return Err(Error::Provenance("reserved provenance entry kind"));
            }
            if b != 0 {
                return Err(Error::Provenance("non-zero entry reserved word"));
            }
            let value = match kind {
                0 => ProvValue::Text(self.string(a)?.to_string()),
                1 => ProvValue::Int(self.number(a)?),
                2 => {
                    if a > 1 {
                        return Err(Error::Provenance("flag entry is not 0/1"));
                    }
                    ProvValue::Flag(a == 1)
                }
                3 => ProvValue::Hash(self.hash_entry(a)?),
                _ => unreachable!("kind checked above"),
            };
            entries.push(crate::ir::ProvEntry { key, value });
        }
        if PROV_HEADER_SIZE + count as usize * PROV_ENTRY_SIZE != block.len() {
            return Err(Error::Provenance("trailing bytes in provenance block"));
        }
        Ok(Some(Provenance {
            producer,
            timestamp_ms,
            model,
            tool,
            parent,
            entries,
        }))
    }

    /// Module root recorded in the bindings index (row 0), if any.
    pub fn root(&self) -> Result<Option<NodeId>> {
        let count = self.header.span(Section::Bindings).count;
        if count == 0 {
            return Err(Error::Offset {
                section: "bindings",
                offset: self.header.span(Section::Bindings).offset as u64,
            });
        }
        let offset = self.header.span(Section::Bindings).offset as usize;
        let root = read_u32(self.buf, offset)?;
        if root == u32::MAX {
            Ok(None)
        } else if root < self.node_count() {
            Ok(Some(NodeId(root)))
        } else {
            Err(Error::NodeRef(root))
        }
    }

    /// Name bindings in canonical order (sorted by name).
    pub fn bindings(&self) -> Result<Vec<(&'a str, NodeId)>> {
        let count = self.header.span(Section::Bindings).count;
        if count == 0 {
            return Err(Error::Offset {
                section: "bindings",
                offset: self.header.span(Section::Bindings).offset as u64,
            });
        }
        let base = self.header.span(Section::Bindings).offset as usize;
        let mut out = Vec::with_capacity(count.saturating_sub(1) as usize);
        for index in 1..count {
            let offset = base + index as usize * 8;
            let name = read_u32(self.buf, offset)?;
            let node = read_u32(self.buf, offset + 4)?;
            if node >= self.node_count() {
                return Err(Error::NodeRef(node));
            }
            out.push((self.string(name)?, NodeId(node)));
        }
        Ok(out)
    }

    fn check_bindings(&self) -> Result<()> {
        let count = self.header.span(Section::Bindings).count;
        if count == 0 {
            return Err(Error::Offset {
                section: "bindings",
                offset: self.header.span(Section::Bindings).offset as u64,
            });
        }
        let base = self.header.span(Section::Bindings).offset as usize;
        if read_u32(self.buf, base + 4)? != 0 {
            return Err(Error::ReservedNonZero {
                section: "bindings",
                offset: (base + 4) as u64,
            });
        }
        if count as u64 > self.limits.max_nodes as u64 {
            return Err(Error::Limit {
                kind: "bindings",
                limit: self.limits.max_nodes as u64,
            });
        }
        let mut previous: Option<&str> = None;
        for (name, _) in self.bindings()? {
            if let Some(previous) = previous {
                if previous >= name {
                    return Err(Error::DuplicateBinding);
                }
            }
            previous = Some(name);
        }
        Ok(())
    }

    // ---- checks -------------------------------------------------------

    fn check_strings(&self) -> Result<()> {
        let count = self.header.span(Section::Strings).count;
        if count == 0 {
            return Ok(());
        }
        let table = self.header.span(Section::Strings).offset as usize;
        let heap_len = self.string_heap_len();
        if heap_len as u64 > self.limits_snapshot().max_string_bytes as u64 {
            return Err(Error::Limit {
                kind: "string bytes",
                limit: self.limits_snapshot().max_string_bytes as u64,
            });
        }
        let heap_len = self.string_heap_len();
        let heap = table + (count as usize + 1) * 4;
        if heap + heap_len as usize > self.ends[Section::Strings as usize] as usize {
            return Err(Error::Offset {
                section: "strings",
                offset: table as u64,
            });
        }
        let mut previous: Option<&[u8]> = None;
        let mut last_end = 0u32;
        for id in 0..count {
            let start = read_u32(self.buf, table + id as usize * 4)?;
            let end = read_u32(self.buf, table + id as usize * 4 + 4)?;
            if start != last_end || end < start || end > heap_len {
                return Err(Error::Offset {
                    section: "strings",
                    offset: (heap + start as usize) as u64,
                });
            }
            last_end = end;
            let bytes = &self.buf[heap + start as usize..heap + end as usize];
            std::str::from_utf8(bytes).map_err(|_| Error::Utf8 {
                offset: (heap + start as usize) as u64,
            })?;
            if let Some(previous) = previous {
                if previous >= bytes {
                    return Err(Error::Offset {
                        section: "strings",
                        offset: (heap + start as usize) as u64,
                    });
                }
            }
            previous = Some(bytes);
        }
        if last_end != heap_len {
            return Err(Error::Offset {
                section: "strings",
                offset: (heap + last_end as usize) as u64,
            });
        }
        Ok(())
    }

    fn check_units(&self, limits: Limits) -> Result<()> {
        let count = self.header.span(Section::Units).count;
        if count > limits.max_units {
            return Err(Error::Limit {
                kind: "units",
                limit: limits.max_units as u64,
            });
        }
        let mut previous: Option<(u32, u32)> = None;
        for id in 0..count {
            let offset = self.header.span(Section::Units).offset as usize + id as usize * 8;
            let disc = read_u32(self.buf, offset)?;
            let name = read_u32(self.buf, offset + 4)?;
            if disc == UNIT_NAMED {
                if name >= self.header.span(Section::Strings).count {
                    return Err(Error::UnitRef(name));
                }
                if self.string(name)?.is_empty() {
                    return Err(Error::UnitRef(name));
                }
            } else {
                if UnitTag::from_discriminant(disc).is_none() {
                    return Err(Error::UnknownUnit(disc));
                }
                if name != 0 {
                    return Err(Error::UnitRef(name));
                }
            }
            if let Some(previous) = previous {
                if previous >= (disc, name) {
                    return Err(Error::Offset {
                        section: "units",
                        offset: offset as u64,
                    });
                }
            }
            previous = Some((disc, name));
        }
        Ok(())
    }

    fn check_types(&self, limits: Limits) -> Result<()> {
        let count = self.header.span(Section::Types).count;
        if count > limits.max_types {
            return Err(Error::Limit {
                kind: "types",
                limit: limits.max_types as u64,
            });
        }
        let aux_count = self.header.span(Section::Aux).count;
        let mut previous: Option<(u32, u32, u32, u32)> = None;
        for id in 0..count {
            let offset = self.header.span(Section::Types).offset as usize + id as usize * 16;
            let code = read_u32(self.buf, offset)?;
            let flags = read_u32(self.buf, offset + 4)?;
            let start = read_u32(self.buf, offset + 8)?;
            let len = read_u32(self.buf, offset + 12)?;
            if code > 11 {
                return Err(Error::Type {
                    id,
                    reason: "unknown type code",
                });
            }
            if code != 7 && flags != 0 {
                return Err(Error::Type {
                    id,
                    reason: "flags on a non-table type",
                });
            }
            if code == 7 && flags > 1 {
                return Err(Error::Type {
                    id,
                    reason: "table closed flag must be 0 or 1",
                });
            }
            if start > aux_count || len > aux_count - start {
                return Err(Error::Type {
                    id,
                    reason: "aux range out of bounds",
                });
            }
            for index in start..start + len {
                let (tag, value) = self.aux(index)?;
                match (code, tag) {
                    (8, crate::layout::AUX_TYPE_ENUM_ITEM) => {
                        if value >= self.header.span(Section::Strings).count {
                            return Err(Error::StringRef(value));
                        }
                    }
                    (7, crate::layout::AUX_TYPE_TABLE) => {
                        if value > 1 {
                            return Err(Error::Type {
                                id,
                                reason: "closed flag must be 0 or 1",
                            });
                        }
                    }
                    _ => {
                        return Err(Error::Type {
                            id,
                            reason: "unexpected aux record",
                        })
                    }
                }
            }
            if code == 8 && len == 0 {
                return Err(Error::Type {
                    id,
                    reason: "enum type without members",
                });
            }
            if let Some(previous) = previous {
                if previous >= (code, flags, start, len) {
                    return Err(Error::Offset {
                        section: "types",
                        offset: offset as u64,
                    });
                }
            }
            previous = Some((code, flags, start, len));
        }
        Ok(())
    }

    fn check_numbers(&self) -> Result<()> {
        let count = self.header.span(Section::Numbers).count;
        let base = self.header.span(Section::Numbers).offset as usize;
        let mut previous: Option<i64> = None;
        for index in 0..count {
            let value = read_u64(self.buf, base + index as usize * 8)? as i64;
            if let Some(previous) = previous {
                if previous >= value {
                    return Err(Error::Offset {
                        section: "numbers",
                        offset: (base + index as usize * 8) as u64,
                    });
                }
            }
            previous = Some(value);
        }
        Ok(())
    }

    fn check_hashes(&self) -> Result<()> {
        let count = self.header.span(Section::Hashes).count;
        if count as u64 > self.limits.max_nodes as u64 {
            return Err(Error::Limit {
                kind: "hashes",
                limit: self.limits.max_nodes as u64,
            });
        }
        let base = self.header.span(Section::Hashes).offset as usize;
        let mut previous: Option<[u8; 32]> = None;
        for index in 0..count {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(
                &self.buf[base + index as usize * 32..base + (index as usize + 1) * 32],
            );
            if let Some(previous) = previous {
                if previous >= hash {
                    return Err(Error::Offset {
                        section: "hashes",
                        offset: (base + index as usize * 32) as u64,
                    });
                }
            }
            previous = Some(hash);
        }
        Ok(())
    }

    fn check_secrets(&self, limits: Limits) -> Result<()> {
        let count = self.header.span(Section::Secrets).count;
        if count > limits.max_secrets {
            return Err(Error::Limit {
                kind: "secrets",
                limit: limits.max_secrets as u64,
            });
        }
        let table = self.header.span(Section::Secrets).offset as usize;
        let heap = table + count as usize * 8;
        let end = self.ends[Section::Secrets as usize] as usize;
        let mut cursor = 0u32;
        for id in 0..count {
            let off = read_u32(self.buf, table + id as usize * 8)?;
            let len = read_u32(self.buf, table + id as usize * 8 + 4)?;
            if off != cursor || heap + off as usize + len as usize > end {
                return Err(Error::SecretEntry(id));
            }
            cursor = cursor.checked_add(len).ok_or(Error::SecretEntry(id))?;
        }
        if cursor as u64 > limits.max_secret_bytes as u64 {
            return Err(Error::Limit {
                kind: "secret bytes",
                limit: limits.max_secret_bytes as u64,
            });
        }
        Ok(())
    }

    fn check_blobs(&self, limits: Limits) -> Result<()> {
        let count = self.header.span(Section::Blobs).count;
        if count > limits.max_blobs {
            return Err(Error::Limit {
                kind: "blobs",
                limit: limits.max_blobs as u64,
            });
        }
        let table = self.header.span(Section::Blobs).offset as usize;
        let heap = table + count as usize * BLOB_ENTRY_SIZE;
        let end = self.ends[Section::Blobs as usize] as usize;
        let mut cursor = 0u32;
        let mut previous: Option<([u8; 32], u32, u32)> = None;
        for id in 0..count {
            let offset = table + id as usize * BLOB_ENTRY_SIZE;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&self.buf[offset..offset + 32]);
            let off = read_u32(self.buf, offset + 32)?;
            let len = read_u32(self.buf, offset + 36)?;
            if off != cursor || heap + off as usize + len as usize > end {
                return Err(Error::Blob {
                    id,
                    reason: "payload out of range",
                });
            }
            cursor = cursor.checked_add(len).ok_or(Error::Blob {
                id,
                reason: "payload heap overflows",
            })?;
            if let Some(previous) = previous {
                if previous >= (hash, off, len) {
                    return Err(Error::Offset {
                        section: "blobs",
                        offset: offset as u64,
                    });
                }
            }
            previous = Some((hash, off, len));
        }
        if cursor > limits.max_blob_bytes {
            return Err(Error::Limit {
                kind: "blob bytes",
                limit: limits.max_blob_bytes as u64,
            });
        }
        Ok(())
    }

    fn check_nodes(&self, limits: Limits) -> Result<()> {
        let count = self.node_count();
        if count > limits.max_nodes {
            return Err(Error::Limit {
                kind: "nodes",
                limit: limits.max_nodes as u64,
            });
        }
        let child_count = self.header.span(Section::Children).count;
        let field_count = self.header.span(Section::Fields).count;
        let part_count = self.header.span(Section::Parts).count;
        let string_count = self.header.span(Section::Strings).count;
        let unit_count = self.header.span(Section::Units).count;
        let type_count = self.header.span(Section::Types).count;
        let aux_count = self.header.span(Section::Aux).count;
        let blob_count = self.header.span(Section::Blobs).count;
        let secret_count = self.header.span(Section::Secrets).count;
        for index in 0..count {
            let id = NodeId(index);
            let rec = self.node(id)?;
            if rec.kind > 24 {
                return Err(Error::Node {
                    id: index,
                    reason: "unknown node kind",
                });
            }
            if rec.flags & !NODE_FLAG_KNOWN != 0 {
                return Err(Error::Node {
                    id: index,
                    reason: "reserved node flag set",
                });
            }
            let node = |value: u64| -> Result<()> {
                if value >= count as u64 {
                    Err(Error::NodeRef(value as u32))
                } else {
                    Ok(())
                }
            };
            let range = |start: u64, len: u64, total: u32, what: &'static str| -> Result<()> {
                if start > total as u64 || len > total as u64 - start {
                    return Err(Error::Node {
                        id: index,
                        reason: what,
                    });
                }
                Ok(())
            };
            let string = |value: u32| -> Result<()> {
                if value >= string_count {
                    Err(Error::StringRef(value))
                } else {
                    Ok(())
                }
            };
            let zero = |what: &'static str| -> Result<()> {
                if rec.aux != 0 || rec.a != 0 || rec.b != 0 || rec.c != 0 || rec.flags != 0 {
                    return Err(Error::Node {
                        id: index,
                        reason: what,
                    });
                }
                Ok(())
            };
            match rec.kind {
                0 => zero("unused fields in Null node")?,
                1 => {
                    if rec.a > 1 || rec.aux != 0 || rec.b != 0 || rec.c != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "invalid Bool node",
                        });
                    }
                }
                2 => {
                    if rec.aux != 0 || rec.b != 0 || rec.c != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in Int node",
                        });
                    }
                }
                3 => {
                    let value = f64::from_bits(rec.a);
                    if rec.aux != 0 || rec.b != 0 || rec.c != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in Float node",
                        });
                    }
                    if value.is_nan() && !crate::canonical::is_canonical_nan(value) {
                        return Err(Error::Node {
                            id: index,
                            reason: "non-canonical NaN",
                        });
                    }
                    if value == 0.0 && value.is_sign_negative() {
                        return Err(Error::Node {
                            id: index,
                            reason: "negative zero must be canonicalized",
                        });
                    }
                }
                4 | 13 => {
                    string(rec.aux)?;
                    if rec.a != 0 || rec.b != 0 || rec.c != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in string node",
                        });
                    }
                }
                5 => {
                    if rec.aux != 0 || rec.b != 0 || rec.c != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in Duration node",
                        });
                    }
                }
                6 => {
                    node(rec.aux as u64)?;
                    if rec.a >= unit_count as u64 {
                        return Err(Error::UnitRef(rec.a as u32));
                    }
                    if rec.b != 0 || rec.c != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in Quantity node",
                        });
                    }
                }
                7 => {
                    range(rec.a, rec.b, child_count, "array range out of bounds")?;
                    if rec.aux != 0 || rec.c != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in Array node",
                        });
                    }
                    for offset in rec.a..rec.a + rec.b {
                        let child = self.child(offset as u32)?;
                        node(child as u64)?;
                    }
                }
                8 | 20 => {
                    range(rec.a, rec.b, field_count, "field range out of bounds")?;
                    if rec.aux != 0 || rec.c != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in table node",
                        });
                    }
                    if rec.kind == 8 && rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "flags on a data table",
                        });
                    }
                    if rec.kind == 20 && rec.flags & !NODE_FLAG_0 != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unknown schema-table flag",
                        });
                    }
                    let mut previous: Option<u32> = None;
                    for offset in rec.a..rec.a + rec.b {
                        let (name, node_id) = self.field(offset as u32)?;
                        string(name)?;
                        node(node_id.0 as u64)?;
                        if let Some(previous) = previous {
                            if previous >= name {
                                return Err(Error::Node {
                                    id: index,
                                    reason: "table fields not sorted by key",
                                });
                            }
                        }
                        previous = Some(name);
                    }
                }
                9 => {
                    if rec.a >= secret_count as u64 {
                        return Err(Error::SecretEntry(rec.a as u32));
                    }
                    if rec.aux != 0 || rec.b != 0 || rec.c != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in Secret node",
                        });
                    }
                }
                10 | 11 | 21 => {
                    node(rec.a)?;
                    if rec.aux != 0 || rec.b != 0 || rec.c != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in reference node",
                        });
                    }
                }
                12 => {
                    string(rec.aux)?;
                    if rec.a != u32::MAX as u64 {
                        node(rec.a)?;
                    }
                    if rec.b != 0 || rec.c != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in Env node",
                        });
                    }
                }
                14 => {
                    range(rec.a, rec.b, part_count, "part range out of bounds")?;
                    if rec.aux != 0 || rec.c != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in Interpolate node",
                        });
                    }
                    for offset in rec.a..rec.a + rec.b {
                        let (tag, value) = self.part(offset as u32)?;
                        match tag {
                            crate::layout::PART_LITERAL => string(value)?,
                            crate::layout::PART_EXPR => node(value as u64)?,
                            _ => {
                                return Err(Error::Node {
                                    id: index,
                                    reason: "unknown interpolation part tag",
                                })
                            }
                        }
                    }
                }
                15 => {
                    if crate::ir::BinOp::from_code(rec.aux).is_none() {
                        return Err(Error::Node {
                            id: index,
                            reason: "unknown binary operator",
                        });
                    }
                    node(rec.a)?;
                    node(rec.b)?;
                    if rec.c != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in Binary node",
                        });
                    }
                }
                16 => {
                    if crate::ir::UnOp::from_code(rec.aux).is_none() {
                        return Err(Error::Node {
                            id: index,
                            reason: "unknown unary operator",
                        });
                    }
                    node(rec.a)?;
                    if rec.b != 0 || rec.c != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in Unary node",
                        });
                    }
                }
                17 => {
                    node(rec.a)?;
                    if rec.aux > crate::layout::CONSTRAINT_KIND_CUSTOM {
                        return Err(Error::Node {
                            id: index,
                            reason: "unknown constraint kind",
                        });
                    }
                    range(rec.b, rec.c, aux_count, "constraint aux out of range")?;
                    if rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "flags on a constraint node",
                        });
                    }
                    let mut seen_kinds = Vec::new();
                    for offset in rec.b..rec.b + rec.c {
                        let (tag, value) = self.aux(offset as u32)?;
                        seen_kinds.push(tag);
                        match tag {
                            crate::layout::AUX_CONSTRAINT_MIN
                            | crate::layout::AUX_CONSTRAINT_MAX => {
                                if value >= self.header.span(Section::Numbers).count {
                                    return Err(Error::Node {
                                        id: index,
                                        reason: "constraint bound out of range",
                                    });
                                }
                            }
                            crate::layout::AUX_CONSTRAINT_ENUM_ITEM
                            | crate::layout::AUX_CONSTRAINT_PATTERN
                            | crate::layout::AUX_CONSTRAINT_CUSTOM => string(value)?,
                            _ => {
                                return Err(Error::Node {
                                    id: index,
                                    reason: "unknown constraint aux tag",
                                })
                            }
                        }
                    }
                    let expected_matches = match rec.aux {
                        crate::layout::CONSTRAINT_KIND_MIN_MAX => seen_kinds.iter().all(|tag| {
                            *tag == crate::layout::AUX_CONSTRAINT_MIN
                                || *tag == crate::layout::AUX_CONSTRAINT_MAX
                        }),
                        crate::layout::CONSTRAINT_KIND_ENUM => seen_kinds
                            .iter()
                            .all(|tag| *tag == crate::layout::AUX_CONSTRAINT_ENUM_ITEM),
                        crate::layout::CONSTRAINT_KIND_PATTERN => {
                            seen_kinds == [crate::layout::AUX_CONSTRAINT_PATTERN]
                        }
                        crate::layout::CONSTRAINT_KIND_ODD => seen_kinds.is_empty(),
                        _ => seen_kinds == [crate::layout::AUX_CONSTRAINT_CUSTOM],
                    };
                    if !expected_matches {
                        return Err(Error::Node {
                            id: index,
                            reason: "constraint payload does not match its kind",
                        });
                    }
                    if rec.aux == crate::layout::CONSTRAINT_KIND_ENUM && rec.c == 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "empty enum constraint",
                        });
                    }
                }
                18 => {
                    if rec.aux > crate::layout::PATCH_KIND_RENAME {
                        return Err(Error::Node {
                            id: index,
                            reason: "unknown patch kind",
                        });
                    }
                    range(rec.b, rec.c, aux_count, "patch aux out of range")?;
                    if rec.a != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in Patch node",
                        });
                    }
                    let mut tags = Vec::new();
                    for offset in rec.b..rec.b + rec.c {
                        let (tag, value) = self.aux(offset as u32)?;
                        tags.push(tag);
                        match tag {
                            crate::layout::AUX_PATCH_PATH | crate::layout::AUX_PATCH_RENAME_TO => {
                                string(value)?
                            }
                            crate::layout::AUX_PATCH_VALUE => node(value as u64)?,
                            _ => {
                                return Err(Error::Node {
                                    id: index,
                                    reason: "unknown patch aux tag",
                                })
                            }
                        }
                    }
                    let ok = match rec.aux {
                        crate::layout::PATCH_KIND_SET => {
                            tags == [
                                crate::layout::AUX_PATCH_PATH,
                                crate::layout::AUX_PATCH_VALUE,
                            ]
                        }
                        crate::layout::PATCH_KIND_REMOVE => tags == [crate::layout::AUX_PATCH_PATH],
                        _ => {
                            tags == [
                                crate::layout::AUX_PATCH_PATH,
                                crate::layout::AUX_PATCH_RENAME_TO,
                            ]
                        }
                    };
                    if !ok {
                        return Err(Error::Node {
                            id: index,
                            reason: "patch payload does not match its kind",
                        });
                    }
                }
                19 => {
                    if rec.aux >= type_count {
                        return Err(Error::Type {
                            id: rec.aux,
                            reason: "schema field references a missing type",
                        });
                    }
                    range(rec.b, rec.c, aux_count, "schema aux out of range")?;
                    if rec.a != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in SchemaField node",
                        });
                    }
                    for offset in rec.b..rec.b + rec.c {
                        let (tag, value) = self.aux(offset as u32)?;
                        match tag {
                            crate::layout::AUX_SCHEMA_MIN
                            | crate::layout::AUX_SCHEMA_MAX
                            | crate::layout::AUX_SCHEMA_MIN_LEN
                            | crate::layout::AUX_SCHEMA_MAX_LEN
                            | crate::layout::AUX_SCHEMA_PATTERN
                            | crate::layout::AUX_SCHEMA_DEFAULT => node(value as u64)?,
                            crate::layout::AUX_SCHEMA_DEPRECATED => string(value)?,
                            _ => {
                                return Err(Error::Node {
                                    id: index,
                                    reason: "unknown schema aux tag",
                                })
                            }
                        }
                    }
                }
                22 => {
                    if rec.aux > 2 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unknown semantic tag",
                        });
                    }
                    node(rec.a)?;
                    if rec.b != 0 || rec.c != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in Semantic node",
                        });
                    }
                }
                23 => {
                    if rec.a >= blob_count as u64 {
                        return Err(Error::Blob {
                            id: rec.a as u32,
                            reason: "node references a missing blob",
                        });
                    }
                    string(rec.aux)?;
                    if rec.c != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused field in Blob node",
                        });
                    }
                    if rec.flags & !(NODE_FLAG_0 | NODE_FLAG_1) != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unknown blob flag",
                        });
                    }
                    let (hash, _, len) = self.blob_entry(rec.a as u32)?;
                    let tainted = rec.flags & NODE_FLAG_0 != 0;
                    let has_payload = rec.flags & NODE_FLAG_1 != 0;
                    if tainted && has_payload {
                        return Err(Error::Blob {
                            id: rec.a as u32,
                            reason: "tainted blob must not carry a payload",
                        });
                    }
                    let size = rec.b;
                    if has_payload {
                        let payload = self.blob(rec.a as u32)?;
                        if payload.len() as u64 != size {
                            return Err(Error::Blob {
                                id: rec.a as u32,
                                reason: "payload length disagrees with size",
                            });
                        }
                        let mut hasher = blake3::Hasher::new();
                        hasher.update(payload);
                        if hasher.finalize().as_bytes() != &hash {
                            return Err(Error::Blob {
                                id: rec.a as u32,
                                reason: "payload hash mismatch",
                            });
                        }
                    } else if len != 0 {
                        return Err(Error::Blob {
                            id: rec.a as u32,
                            reason: "payload present without the flag",
                        });
                    }
                }
                24 => {
                    node(rec.a)?;
                    node(rec.b)?;
                    if rec.aux != 0 || rec.c != 0 || rec.flags != 0 {
                        return Err(Error::Node {
                            id: index,
                            reason: "unused fields in ContentAddressed node",
                        });
                    }
                }
                _ => unreachable!("kind checked above"),
            }
        }
        Ok(())
    }

    fn check_fields(&self) -> Result<()> {
        let count = self.header.span(Section::Fields).count;
        let base = self.header.span(Section::Fields).offset as usize;
        for index in 0..count {
            let offset = base + index as usize * FIELD_SIZE;
            if read_u32(self.buf, offset + 4)? != 0 || read_u32(self.buf, offset + 12)? != 0 {
                return Err(Error::ReservedNonZero {
                    section: "fields",
                    offset: (offset + 4) as u64,
                });
            }
        }
        Ok(())
    }

    fn check_parts(&self) -> Result<()> {
        let count = self.header.span(Section::Parts).count;
        let base = self.header.span(Section::Parts).offset as usize;
        for index in 0..count {
            let tag = read_u32(self.buf, base + index as usize * 8)?;
            if tag > crate::layout::PART_EXPR {
                return Err(Error::Node {
                    id: index,
                    reason: "unknown part tag",
                });
            }
        }
        Ok(())
    }

    fn check_edges(&self) -> Result<()> {
        let count = self.header.span(Section::Edges).count;
        let node_count = self.node_count();
        let base = self.header.span(Section::Edges).offset as usize;
        let mut previous: Option<(u32, u32)> = None;
        let mut edges = Vec::with_capacity(count.min(1 << 20) as usize);
        for index in 0..count {
            let from = read_u32(self.buf, base + index as usize * 8)?;
            let to = read_u32(self.buf, base + index as usize * 8 + 4)?;
            if from >= node_count || to >= node_count || from == to {
                return Err(Error::Edge { from, to });
            }
            if let Some(previous) = previous {
                if previous >= (from, to) {
                    return Err(Error::Edge { from, to });
                }
            }
            previous = Some((from, to));
            edges.push((from, to));
        }
        // The edge table must be exactly the derived graph: no extra edges,
        // no missing edges. This is what makes the graph unforgeable.
        let mut derived: Vec<(u32, u32)> = Vec::new();
        let mut scratch: Vec<u32> = Vec::new();
        for index in 0..node_count {
            let rec = self.node(NodeId(index))?;
            self.node_children_into(&rec, &mut scratch)?;
            for child in &scratch {
                derived.push((*child, index));
            }
        }
        derived.sort_unstable();
        derived.dedup();
        if derived != edges {
            return Err(Error::Edge { from: 0, to: 0 });
        }
        Ok(())
    }

    /// Node references in canonical order, written into a reusable buffer.
    ///
    /// Validation walks every node three times (nodes, edges, reachability); a
    /// fresh `Vec` per node dominated the profile, so the hot paths reuse one
    /// scratch buffer per traversal.
    pub(crate) fn node_children_into(&self, rec: &NodeRec, out: &mut Vec<u32>) -> Result<()> {
        out.clear();
        match rec.kind {
            6 => out.push(rec.aux),
            7 => {
                for offset in rec.a..rec.a + rec.b {
                    out.push(self.child(offset as u32)?);
                }
            }
            8 | 20 => {
                for offset in rec.a..rec.a + rec.b {
                    out.push(self.field(offset as u32)?.1 .0);
                }
            }
            10 | 11 | 21 | 22 => out.push(rec.a as u32),
            12 => {
                if rec.a != u32::MAX as u64 {
                    out.push(rec.a as u32);
                }
            }
            14 => {
                for offset in rec.a..rec.a + rec.b {
                    let (tag, value) = self.part(offset as u32)?;
                    if tag == crate::layout::PART_EXPR {
                        out.push(value);
                    }
                }
            }
            15 => {
                out.push(rec.a as u32);
                out.push(rec.b as u32);
            }
            16 | 17 => out.push(rec.a as u32),
            18 => {
                for offset in rec.b..rec.b + rec.c {
                    let (tag, value) = self.aux(offset as u32)?;
                    if tag == crate::layout::AUX_PATCH_VALUE {
                        out.push(value);
                    }
                }
            }
            19 => {
                for offset in rec.b..rec.b + rec.c {
                    let (tag, value) = self.aux(offset as u32)?;
                    if tag != crate::layout::AUX_SCHEMA_DEPRECATED {
                        out.push(value);
                    }
                }
            }
            24 => {
                out.push(rec.a as u32);
                out.push(rec.b as u32);
            }
            _ => {}
        }
        Ok(())
    }

    /// Node references in canonical order for a record.
    pub(crate) fn node_children(&self, _index: u32, rec: &NodeRec) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        match rec.kind {
            6 => out.push(rec.aux),
            7 => {
                for offset in rec.a..rec.a + rec.b {
                    out.push(self.child(offset as u32)?);
                }
            }
            8 | 20 => {
                for offset in rec.a..rec.a + rec.b {
                    out.push(self.field(offset as u32)?.1 .0);
                }
            }
            10 | 11 | 21 | 22 => out.push(rec.a as u32),
            12 => {
                if rec.a != u32::MAX as u64 {
                    out.push(rec.a as u32);
                }
            }
            14 => {
                for offset in rec.a..rec.a + rec.b {
                    let (tag, value) = self.part(offset as u32)?;
                    if tag == crate::layout::PART_EXPR {
                        out.push(value);
                    }
                }
            }
            15 => {
                out.push(rec.a as u32);
                out.push(rec.b as u32);
            }
            16 => out.push(rec.a as u32),
            17 => out.push(rec.a as u32),
            18 => {
                for offset in rec.b..rec.b + rec.c {
                    let (tag, value) = self.aux(offset as u32)?;
                    if tag == crate::layout::AUX_PATCH_VALUE {
                        out.push(value);
                    }
                }
            }
            19 => {
                for offset in rec.b..rec.b + rec.c {
                    let (tag, value) = self.aux(offset as u32)?;
                    if tag != crate::layout::AUX_SCHEMA_DEPRECATED {
                        out.push(value);
                    }
                }
            }
            24 => {
                out.push(rec.a as u32);
                out.push(rec.b as u32);
            }
            _ => {}
        }
        Ok(out)
    }

    fn check_annotations(&self) -> Result<()> {
        let count = self.header.span(Section::Annotations).count;
        let node_count = self.node_count();
        let mut previous: Option<(u32, u32, u32, u32)> = None;
        for index in 0..count {
            let (node, kind, a, b) = self.annotation(index)?;
            if node >= node_count {
                return Err(Error::Annotation {
                    id: index,
                    reason: "annotation subject out of range",
                });
            }
            match kind {
                crate::layout::ANN_KIND_INTENT => {
                    if a >= self.header.span(Section::Strings).count || b != 0 {
                        return Err(Error::Annotation {
                            id: index,
                            reason: "invalid intent annotation",
                        });
                    }
                }
                crate::layout::ANN_KIND_CONSTRAINT => {
                    if a >= self.header.span(Section::Strings).count || b >= node_count {
                        return Err(Error::Annotation {
                            id: index,
                            reason: "invalid constraint annotation",
                        });
                    }
                }
                crate::layout::ANN_KIND_AI_IMMUTABLE => {
                    if a > 1 || b != 0 {
                        return Err(Error::Annotation {
                            id: index,
                            reason: "invalid immutability annotation",
                        });
                    }
                }
                _ => {
                    return Err(Error::Annotation {
                        id: index,
                        reason: "unknown annotation kind",
                    })
                }
            }
            if let Some(previous) = previous {
                if previous >= (node, kind, a, b) {
                    return Err(Error::Annotation {
                        id: index,
                        reason: "annotations not sorted",
                    });
                }
            }
            previous = Some((node, kind, a, b));
        }
        Ok(())
    }

    fn check_provenance(&self, limits: Limits) -> Result<()> {
        let len = self.header.span(Section::Provenance).count as usize;
        if len == 0 {
            return Ok(());
        }
        let start = self.header.span(Section::Provenance).offset as usize;
        let count = read_u32(self.buf, start + 4)?;
        if count > limits.max_prov_entries {
            return Err(Error::Limit {
                kind: "provenance entries",
                limit: limits.max_prov_entries as u64,
            });
        }
        let prov = self.provenance()?;
        if let Some(prov) = prov {
            let mut previous: Option<&str> = None;
            for entry in &prov.entries {
                if let Some(previous) = previous {
                    if previous >= entry.key.as_str() {
                        return Err(Error::Provenance("entries not sorted by key"));
                    }
                }
                previous = Some(entry.key.as_str());
            }
            if let Some(text) = &prov.producer {
                if text.is_empty() {
                    return Err(Error::Provenance("empty producer"));
                }
            }
        }
        Ok(())
    }

    fn check_extensions(&self) -> Result<()> {
        let count = self.header.span(Section::Extensions).count;
        if count == 0 {
            return Ok(());
        }
        let start = self.header.span(Section::Extensions).offset as u64;
        let end = self.ends[Section::Extensions as usize];
        let dir_end = start + count as u64 * EXT_DIR_SIZE as u64;
        if dir_end > end {
            return Err(Error::Offset {
                section: "extensions",
                offset: start,
            });
        }
        let mut previous_tag: Option<u64> = None;
        let mut previous_end = dir_end;
        for index in 0..count {
            let offset = start as usize + index as usize * EXT_DIR_SIZE;
            let tag = read_u64(self.buf, offset)?;
            let payload_offset = read_u32(self.buf, offset + 8)? as u64;
            let payload_len = read_u32(self.buf, offset + 12)? as u64;
            if let Some(previous) = previous_tag {
                if previous >= tag {
                    return Err(Error::Extension {
                        tag,
                        reason: "extension tags not sorted",
                    });
                }
            }
            previous_tag = Some(tag);
            if payload_offset < align8(previous_end) || payload_offset + payload_len > end {
                return Err(Error::Extension {
                    tag,
                    reason: "payload out of range",
                });
            }
            previous_end = payload_offset + payload_len;
        }
        if align8(previous_end) != end {
            return Err(Error::Extension {
                tag: 0,
                reason: "extension section has trailing bytes",
            });
        }
        Ok(())
    }

    fn check_reachability(&self, limits: Limits) -> Result<()> {
        self.check_bindings()?;
        let count = self.node_count();
        if count == 0 {
            return Ok(());
        }
        let mut roots = Vec::new();
        if let Some(root) = self.root()? {
            roots.push(root.0);
        }
        for (_, id) in self.bindings()? {
            roots.push(id.0);
        }
        for index in 0..self.header.span(Section::Annotations).count {
            let (node, kind, _, b) = self.annotation(index)?;
            roots.push(node);
            if kind == crate::layout::ANN_KIND_CONSTRAINT {
                roots.push(b);
            }
        }
        roots.sort_unstable();
        roots.dedup();
        let mut seen = vec![false; count as usize];
        let mut stack: Vec<u32> = roots;
        let mut scratch: Vec<u32> = Vec::new();
        let mut visited = 0u32;
        while let Some(node) = stack.pop() {
            if seen[node as usize] {
                continue;
            }
            seen[node as usize] = true;
            visited += 1;
            let rec = self.node(NodeId(node))?;
            self.node_children_into(&rec, &mut scratch)?;
            for child in &scratch {
                if !seen[*child as usize] {
                    stack.push(*child);
                }
            }
        }
        if visited != count {
            return Err(Error::Node {
                id: (0..count).find(|id| !seen[*id as usize]).unwrap_or(0),
                reason: "unreachable node",
            });
        }
        let _ = limits;
        Ok(())
    }

    fn check_depth(&self, limits: Limits) -> Result<()> {
        if limits.max_depth == 0 {
            return Ok(());
        }
        let count = self.node_count();
        if count == 0 {
            return Ok(());
        }
        let mut depth = vec![0u32; count as usize];
        let mut scratch: Vec<u32> = Vec::new();
        // Every node with no incoming edge is a root (module root, bindings,
        // annotation subjects). Starting only at node 0 would let a second root
        // carry an arbitrarily deep chain past the ceiling.
        let mut has_parent = vec![false; count as usize];
        for node in 0..count {
            let rec = self.node(NodeId(node))?;
            self.node_children_into(&rec, &mut scratch)?;
            for child in &scratch {
                has_parent[*child as usize] = true;
            }
        }
        let mut stack: Vec<(u32, u32)> = Vec::new();
        for node in 0..count {
            if !has_parent[node as usize] {
                depth[node as usize] = 1;
                stack.push((node, 0));
            }
        }
        while let Some((node, cursor)) = stack.pop() {
            let rec = self.node(NodeId(node))?;
            self.node_children_into(&rec, &mut scratch)?;
            if cursor as usize >= scratch.len() {
                continue;
            }
            stack.push((node, cursor + 1));
            let child = scratch[cursor as usize];
            let candidate = depth[node as usize] + 1;
            if candidate > limits.max_depth {
                return Err(Error::Depth {
                    limit: limits.max_depth,
                });
            }
            if candidate > depth[child as usize] {
                depth[child as usize] = candidate;
                stack.push((child, 0));
            }
        }
        Ok(())
    }
}

/// Check every count against the configured limits and the remaining bytes.
fn validate_counts(header: &Header, limits: Limits) -> Result<()> {
    let checks: [(Section, u32, u32); SECTION_COUNT] = [
        (
            Section::Nodes,
            header.span(Section::Nodes).count,
            limits.max_nodes,
        ),
        (
            Section::Children,
            header.span(Section::Children).count,
            limits.max_children,
        ),
        (
            Section::Fields,
            header.span(Section::Fields).count,
            limits.max_fields,
        ),
        (
            Section::Parts,
            header.span(Section::Parts).count,
            limits.max_parts,
        ),
        (
            Section::Edges,
            header.span(Section::Edges).count,
            limits.max_edges,
        ),
        (
            Section::Strings,
            header.span(Section::Strings).count,
            limits.max_strings,
        ),
        (
            Section::Blobs,
            header.span(Section::Blobs).count,
            limits.max_blobs,
        ),
        (
            Section::Annotations,
            header.span(Section::Annotations).count,
            limits.max_annotations,
        ),
        (
            Section::Units,
            header.span(Section::Units).count,
            limits.max_units,
        ),
        (
            Section::Types,
            header.span(Section::Types).count,
            limits.max_types,
        ),
        (
            Section::Aux,
            header.span(Section::Aux).count,
            limits.max_aux,
        ),
        (
            Section::Numbers,
            header.span(Section::Numbers).count,
            limits.max_numbers,
        ),
        (
            Section::Secrets,
            header.span(Section::Secrets).count,
            limits.max_secrets,
        ),
        (
            Section::Provenance,
            header.span(Section::Provenance).count,
            u32::MAX,
        ),
        (
            Section::Hashes,
            header.span(Section::Hashes).count,
            u32::MAX,
        ),
        (
            Section::Extensions,
            header.span(Section::Extensions).count,
            limits.max_extensions,
        ),
        (
            Section::Bindings,
            header.span(Section::Bindings).count,
            u32::MAX,
        ),
    ];
    for (section, count, limit) in checks {
        if count > limit {
            return Err(Error::Limit {
                kind: section.name(),
                limit: limit as u64,
            });
        }
    }
    Ok(())
}

/// Check section ranges: canonical order, alignment, no overlap, zero padding,
/// and an exact total size.
fn validate_layout(buf: &[u8], header: &Header) -> Result<[u64; SECTION_COUNT]> {
    // Bound the buffer first: every later read is in range only after this.
    if header.total_size > buf.len() as u64 {
        return Err(Error::Truncated {
            needed: header.total_size,
            found: buf.len() as u64,
        });
    }
    if header.total_size < buf.len() as u64 {
        return Err(Error::TrailingBytes {
            at: header.total_size,
        });
    }
    let mut ends = [0u64; SECTION_COUNT];
    let mut cursor = HEADER_SIZE as u64;
    for section in Section::ALL {
        let span = header.span(section);
        if span.offset as u64 != align8(cursor) {
            return Err(Error::Offset {
                section: section.name(),
                offset: span.offset as u64,
            });
        }
        if span.offset as u64 > buf.len() as u64 {
            return Err(Error::Truncated {
                needed: span.offset as u64,
                found: buf.len() as u64,
            });
        }
        // Padding between the previous section and this one must be zero.
        for offset in cursor..span.offset as u64 {
            if buf[offset as usize] != 0 {
                return Err(Error::Padding { offset });
            }
        }
        let end = section_end(buf, header, section, span.offset as u64, span.count)?;
        if end > header.total_size || end > buf.len() as u64 {
            // The declared count cannot be satisfied by the image: a count
            // fault, distinct from an offset/alignment fault.
            return Err(Error::Count {
                field: section.name(),
                value: span.count as u64,
            });
        }
        ends[section as usize] = end;
        cursor = end;
    }
    if header.total_size != align8(cursor) {
        return Err(Error::Offset {
            section: "total-size",
            offset: header.total_size,
        });
    }
    if header.total_size != buf.len() as u64 {
        if header.total_size < buf.len() as u64 {
            return Err(Error::TrailingBytes {
                at: header.total_size,
            });
        }
        return Err(Error::Truncated {
            needed: header.total_size,
            found: buf.len() as u64,
        });
    }
    Ok(ends)
}

fn section_end(
    buf: &[u8],
    _header: &Header,
    section: Section,
    offset: u64,
    count: u32,
) -> Result<u64> {
    let end = match section {
        Section::Strings => {
            if count == 0 {
                offset
            } else {
                let table = offset as usize;
                let heap_len = read_u32(buf, table + count as usize * 4)? as u64;
                offset + (count as u64 + 1) * 4 + heap_len
            }
        }
        Section::Blobs => {
            let table = offset as usize;
            let mut heap = 0u64;
            for index in 0..count {
                let len = read_u32(buf, table + index as usize * BLOB_ENTRY_SIZE + 36)? as u64;
                heap = heap.checked_add(len).ok_or(Error::Blob {
                    id: index,
                    reason: "payload heap overflows",
                })?;
            }
            offset + count as u64 * BLOB_ENTRY_SIZE as u64 + heap
        }
        Section::Provenance => offset + count as u64,
        Section::Secrets => {
            let table = offset as usize;
            let mut heap = 0u64;
            for index in 0..count {
                let len = read_u32(buf, table + index as usize * 8 + 4)? as u64;
                heap = heap.checked_add(len).ok_or(Error::SecretEntry(index))?;
            }
            offset + count as u64 * 8 + heap
        }
        Section::Extensions => {
            if count == 0 {
                offset
            } else {
                let mut max_end = offset + count as u64 * EXT_DIR_SIZE as u64;
                for index in 0..count {
                    let dir = offset as usize + index as usize * EXT_DIR_SIZE;
                    let payload_offset = read_u32(buf, dir + 8)? as u64;
                    let payload_len = read_u32(buf, dir + 12)? as u64;
                    max_end = max_end.max(payload_offset + payload_len);
                }
                max_end
            }
        }
        Section::Nodes => offset + count as u64 * NODE_RECORD_SIZE as u64,
        Section::Children => offset + count as u64 * 4,
        Section::Fields => offset + count as u64 * FIELD_SIZE as u64,
        Section::Parts => offset + count as u64 * 8,
        Section::Edges => offset + count as u64 * 8,
        Section::Annotations => offset + count as u64 * 16,
        Section::Units => offset + count as u64 * 8,
        Section::Types => offset + count as u64 * 16,
        Section::Aux => offset + count as u64 * 8,
        Section::Numbers => offset + count as u64 * 8,
        Section::Hashes => offset + count as u64 * 32,
        Section::Bindings => offset + count as u64 * 8,
    };
    Ok(end)
}

/// Validate a buffer with the default options.
pub fn validate(buf: &[u8]) -> Result<Meta> {
    Validated::new(buf, crate::layout::DecodeOpts::default()).map(|validated| validated.meta())
}

/// Validate a buffer with explicit options.
pub fn validate_with(buf: &[u8], opts: crate::layout::DecodeOpts) -> Result<Meta> {
    Validated::new(buf, opts).map(|validated| validated.meta())
}

/// Validate and additionally prove `buf` is exactly the canonical encoding of
/// its own content.
pub fn validate_canonical(buf: &[u8], limits: Limits) -> Result<Meta> {
    let opts = crate::layout::DecodeOpts {
        limits,
        verify_hash: true,
        verify_canonical: true,
    };
    let validated = Validated::new(buf, opts)?;
    let module = crate::decode::decode_validated(&validated)?;
    let image = crate::encode::encode_with(
        &module,
        crate::layout::EncodeOpts {
            write_hash: true,
            mark_canonical: true,
            streamed: validated.header.flags & crate::layout::FLAG_STREAMED != 0,
        },
    )?;
    if image != buf {
        return Err(Error::NotCanonical);
    }
    Ok(validated.meta())
}

/// Parse a provenance block from bytes already validated (used by tests).
pub fn provenance_hash_of(prov: Option<&Provenance>) -> Option<[u8; 32]> {
    prov.and_then(|prov| prov.parent)
}

/// Report whether a value is a hash provenance entry (helper for projections).
pub fn is_hash_entry(entry: &crate::ir::ProvEntry) -> bool {
    matches!(entry.value, ProvValue::Hash(_))
}
