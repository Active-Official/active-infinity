//! Wire layout primitives: the fixed header, node records, section table and
//! the limits that bound untrusted input.
//!
//! Everything here is a pure description of bytes; the normative document is
//! `docs/spec/layout.md`, and `tests/doc_gate.rs` fails the build if constants
//! and prose drift apart.

// Field names mirror the wire header exactly; `docs/spec/layout.md` is the
// normative description of every byte.
#![allow(missing_docs)]

use crate::error::{Error, Result};

/// Magic at offset 0: `A I N F`.
pub const MAGIC: [u8; 4] = *b"AINF";
/// Stream frame magic: `A I N S`.
pub const STREAM_MAGIC: [u8; 4] = *b"AINS";
/// Major format version implemented by this crate.
pub const FORMAT_MAJOR: u16 = 1;
/// Minor format version implemented by this crate.
pub const FORMAT_MINOR: u16 = 0;
/// Fixed header size in bytes.
pub const HEADER_SIZE: usize = 224;
/// Fixed node record size in bytes.
pub const NODE_RECORD_SIZE: usize = 32;
/// Child index entry size.
pub const CHILD_SIZE: usize = 4;
/// Table field entry size: name string id + node id + two pad words.
pub const FIELD_SIZE: usize = 16;
/// Interpolation part entry size.
pub const PART_SIZE: usize = 8;
/// Edge entry size.
pub const EDGE_SIZE: usize = 8;
/// Blob index entry size.
pub const BLOB_ENTRY_SIZE: usize = 40;
/// Annotation entry size.
pub const ANNOTATION_SIZE: usize = 16;
/// Unit table entry size.
pub const UNIT_SIZE: usize = 8;
/// Type table entry size.
pub const TYPE_SIZE: usize = 16;
/// Aux record size.
pub const AUX_SIZE: usize = 8;
/// Numeric side-table entry size.
pub const NUM_SIZE: usize = 8;
/// Extension directory entry size.
pub const EXT_DIR_SIZE: usize = 16;
/// Provenance block fixed header size.
pub const PROV_HEADER_SIZE: usize = 96;
/// Provenance entry size.
pub const PROV_ENTRY_SIZE: usize = 16;
/// Secret table entry size.
pub const SECRET_ENTRY_SIZE: usize = 8;

// ---- aux record tags (wire contract) ----------------------------------
/// Constraint `min` bound; value is a `numbers` index.
pub const AUX_CONSTRAINT_MIN: u32 = 0;
/// Constraint `max` bound; value is a `numbers` index.
pub const AUX_CONSTRAINT_MAX: u32 = 1;
/// Constraint enum member; value is a string id.
pub const AUX_CONSTRAINT_ENUM_ITEM: u32 = 2;
/// Constraint regex pattern; value is a string id.
pub const AUX_CONSTRAINT_PATTERN: u32 = 3;
/// Custom constraint payload; value is a string id.
pub const AUX_CONSTRAINT_CUSTOM: u32 = 4;
/// Patch target path; value is a string id.
pub const AUX_PATCH_PATH: u32 = 10;
/// Patch value node; value is a node id.
pub const AUX_PATCH_VALUE: u32 = 11;
/// Patch rename destination; value is a string id.
pub const AUX_PATCH_RENAME_TO: u32 = 12;
/// Schema field `min` node.
pub const AUX_SCHEMA_MIN: u32 = 20;
/// Schema field `max` node.
pub const AUX_SCHEMA_MAX: u32 = 21;
/// Schema field `min_len` node.
pub const AUX_SCHEMA_MIN_LEN: u32 = 22;
/// Schema field `max_len` node.
pub const AUX_SCHEMA_MAX_LEN: u32 = 23;
/// Schema field `pattern` node.
pub const AUX_SCHEMA_PATTERN: u32 = 24;
/// Schema field `default` node.
pub const AUX_SCHEMA_DEFAULT: u32 = 25;
/// Schema field `deprecated` message; value is a string id.
pub const AUX_SCHEMA_DEPRECATED: u32 = 26;
/// Enum type member; value is a string id.
pub const AUX_TYPE_ENUM_ITEM: u32 = 30;
/// Table type closed flag; value is `0` or `1`.
pub const AUX_TYPE_TABLE: u32 = 31;

/// Constraint kind: `MinMax`.
pub const CONSTRAINT_KIND_MIN_MAX: u32 = 0;
/// Constraint kind: `Enum`.
pub const CONSTRAINT_KIND_ENUM: u32 = 1;
/// Constraint kind: `Pattern`.
pub const CONSTRAINT_KIND_PATTERN: u32 = 2;
/// Constraint kind: `Odd`.
pub const CONSTRAINT_KIND_ODD: u32 = 3;
/// Constraint kind: `Custom`.
pub const CONSTRAINT_KIND_CUSTOM: u32 = 4;

/// Patch kind: `Set`.
pub const PATCH_KIND_SET: u32 = 0;
/// Patch kind: `Remove`.
pub const PATCH_KIND_REMOVE: u32 = 1;
/// Patch kind: `Rename`.
pub const PATCH_KIND_RENAME: u32 = 2;

/// Annotation kind: `Intent`.
pub const ANN_KIND_INTENT: u32 = 0;
/// Annotation kind: `Constraint`.
pub const ANN_KIND_CONSTRAINT: u32 = 1;
/// Annotation kind: `AiImmutable`.
pub const ANN_KIND_AI_IMMUTABLE: u32 = 2;

/// Interpolation part: literal string; value is a string id.
pub const PART_LITERAL: u32 = 0;
/// Interpolation part: expression; value is a node id.
pub const PART_EXPR: u32 = 1;

/// Header flag: the image is in canonical form (self-declaration the reader
/// verifies).
pub const FLAG_CANONICAL: u16 = 1 << 0;
/// Header flag: an annotation table is present.
pub const FLAG_ANNOTATIONS: u16 = 1 << 1;
/// Header flag: a provenance block is present.
pub const FLAG_PROVENANCE: u16 = 1 << 2;
/// Header flag: an extension directory is present.
pub const FLAG_EXTENSIONS: u16 = 1 << 3;
/// Header flag: the module was reassembled from a stream.
pub const FLAG_STREAMED: u16 = 1 << 4;
/// Header flag: a secret table is present.
pub const FLAG_SECRETS: u16 = 1 << 5;
/// All flags this reader understands.
pub const FLAG_KNOWN_MASK: u16 = FLAG_CANONICAL
    | FLAG_ANNOTATIONS
    | FLAG_PROVENANCE
    | FLAG_EXTENSIONS
    | FLAG_STREAMED
    | FLAG_SECRETS;

/// Node flag bit 0 (meaning depends on kind).
pub const NODE_FLAG_0: u8 = 1 << 0;
/// Node flag bit 1.
pub const NODE_FLAG_1: u8 = 1 << 1;
/// Node flag bit 2.
pub const NODE_FLAG_2: u8 = 1 << 2;
/// Node flag bit 3.
pub const NODE_FLAG_3: u8 = 1 << 3;
/// Node flag bit 4.
pub const NODE_FLAG_4: u8 = 1 << 4;
/// Node flag bit 5.
pub const NODE_FLAG_5: u8 = 1 << 5;
/// Node flag bit 6.
pub const NODE_FLAG_6: u8 = 1 << 6;
/// All node flag bits (bit 7 is reserved and must be zero).
pub const NODE_FLAG_KNOWN: u8 =
    NODE_FLAG_0 | NODE_FLAG_1 | NODE_FLAG_2 | NODE_FLAG_3 | NODE_FLAG_4 | NODE_FLAG_5 | NODE_FLAG_6;

/// Number of sections in the canonical image.
pub const SECTION_COUNT: usize = 17;

/// Ordinal of a section in the canonical image. Sections appear in this exact
/// order, each starting at an 8-byte aligned offset with no gaps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Nodes,
    Children,
    Fields,
    Parts,
    Edges,
    Strings,
    Blobs,
    Annotations,
    Provenance,
    Extensions,
    Units,
    Types,
    Aux,
    Numbers,
    Secrets,
    Hashes,
    /// Module index (root id) and name bindings.
    Bindings,
}

impl Section {
    pub const ALL: [Section; SECTION_COUNT] = [
        Section::Nodes,
        Section::Children,
        Section::Fields,
        Section::Parts,
        Section::Edges,
        Section::Strings,
        Section::Blobs,
        Section::Annotations,
        Section::Provenance,
        Section::Extensions,
        Section::Units,
        Section::Types,
        Section::Aux,
        Section::Numbers,
        Section::Secrets,
        Section::Hashes,
        Section::Bindings,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Section::Nodes => "nodes",
            Section::Children => "children",
            Section::Fields => "fields",
            Section::Parts => "parts",
            Section::Edges => "edges",
            Section::Strings => "strings",
            Section::Blobs => "blobs",
            Section::Annotations => "annotations",
            Section::Provenance => "provenance",
            Section::Extensions => "extensions",
            Section::Units => "units",
            Section::Types => "types",
            Section::Aux => "aux",
            Section::Numbers => "numbers",
            Section::Secrets => "secrets",
            Section::Hashes => "hashes",
            Section::Bindings => "bindings",
        }
    }
}

/// Round `value` up to the next multiple of 8.
///
/// Saturating: `u64::MAX` stays at the top of the range instead of wrapping to
/// a small number (or panicking in a debug build). A size that large is then
/// refused by the caller's bound check, which is the fail-closed direction.
pub const fn align8(value: u64) -> u64 {
    value.saturating_add(7) & !7
}

/// Canonical form of a float: `-0.0` becomes `+0.0`; every NaN becomes the
/// single quiet NaN `0x7ff8_0000_0000_0000`.
pub fn canonical_f64(value: f64) -> f64 {
    if value.is_nan() {
        f64::from_bits(CANONICAL_NAN_BITS)
    } else if value == 0.0 {
        0.0
    } else {
        value
    }
}

/// The one NaN bit pattern the format permits.
pub const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;

/// Parsed fixed header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub major: u16,
    pub minor: u16,
    pub flags: u16,
    pub header_size: u16,
    pub content_hash: [u8; 32],
    pub dialect_hash: u64,
    pub total_size: u64,
    pub sections: [SectionSpan; SECTION_COUNT],
}

/// Offset and element count (or byte length) of one section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SectionSpan {
    pub offset: u32,
    pub count: u32,
}

impl SectionSpan {
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Byte length of the section body for a fixed-stride section.
    pub fn bytes(&self, stride: usize) -> u64 {
        self.count as u64 * stride as u64
    }
}

impl Header {
    pub fn span(&self, section: Section) -> SectionSpan {
        self.sections[section as usize]
    }

    pub fn span_mut(&mut self, section: Section) -> &mut SectionSpan {
        &mut self.sections[section as usize]
    }

    /// Parse and structurally check the fixed header.
    ///
    /// This checks the prefix, versions and flags only. Section ranges are
    /// validated by [`crate::validate::validate`], which owns the full invariants.
    pub fn parse(buf: &[u8]) -> Result<Header> {
        if buf.len() < 4 || buf[0..4] != MAGIC {
            return Err(Error::Magic);
        }
        if buf.len() < HEADER_SIZE {
            return Err(Error::HeaderTruncated);
        }
        let major = u16::from_le_bytes([buf[4], buf[5]]);
        let minor = u16::from_le_bytes([buf[6], buf[7]]);
        let flags = u16::from_le_bytes([buf[8], buf[9]]);
        let header_size = u16::from_le_bytes([buf[10], buf[11]]);
        if major != FORMAT_MAJOR {
            return Err(Error::VersionMajor(major));
        }
        if minor > FORMAT_MINOR {
            return Err(Error::VersionMinor(minor));
        }
        if header_size as usize != HEADER_SIZE {
            return Err(Error::HeaderSize(header_size));
        }
        if flags & !FLAG_KNOWN_MASK != 0 {
            return Err(Error::UnknownFlags(flags & !FLAG_KNOWN_MASK));
        }
        if read_u32(buf, 12)? != 0 {
            return Err(Error::ReservedNonZero {
                section: "header",
                offset: 12,
            });
        }
        let mut content_hash = [0u8; 32];
        content_hash.copy_from_slice(&buf[16..48]);
        let dialect_hash = read_u64(buf, 48)?;
        let total_size = read_u64(buf, 56)?;
        let mut sections = [SectionSpan::default(); SECTION_COUNT];
        for (index, span) in sections.iter_mut().enumerate() {
            let base = 64 + index * 8;
            span.offset = read_u32(buf, base)?;
            span.count = read_u32(buf, base + 4)?;
        }
        let reserved_start = 64 + SECTION_COUNT * 8;
        if let Some(position) = (reserved_start..HEADER_SIZE).find(|offset| buf[*offset] != 0) {
            return Err(Error::ReservedNonZero {
                section: "header",
                offset: position as u64,
            });
        }
        Ok(Header {
            major,
            minor,
            flags,
            header_size,
            content_hash,
            dialect_hash,
            total_size,
            sections,
        })
    }

    /// Serialize this header, returning an error when `out` is too short.
    ///
    /// Prefer this over [`Header::write`] in code that accepts a caller-owned
    /// buffer: the failure is a value, not a panic.
    pub fn try_write(&self, out: &mut [u8]) -> crate::Result<()> {
        if out.len() < HEADER_SIZE {
            return Err(crate::Error::Encode("header buffer is too short"));
        }
        self.write(out);
        Ok(())
    }

    /// Serialize this header into the first [`HEADER_SIZE`] bytes of `out`.
    ///
    /// # Panics
    ///
    /// Panics when `out` is shorter than [`HEADER_SIZE`]. Use
    /// [`Header::try_write`] for a fallible form.
    pub fn write(&self, out: &mut [u8]) {
        // Enforced in release too: a short output buffer is a caller bug, not a
        // debug-only precondition. The audit in `tests/redteam_battery.rs`
        // refuses any debug-only security branch.
        assert!(out.len() >= HEADER_SIZE, "header buffer is too short");
        out[0..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&self.major.to_le_bytes());
        out[6..8].copy_from_slice(&self.minor.to_le_bytes());
        out[8..10].copy_from_slice(&self.flags.to_le_bytes());
        out[10..12].copy_from_slice(&self.header_size.to_le_bytes());
        out[12..16].copy_from_slice(&0u32.to_le_bytes());
        out[16..48].copy_from_slice(&self.content_hash);
        out[48..56].copy_from_slice(&self.dialect_hash.to_le_bytes());
        out[56..64].copy_from_slice(&self.total_size.to_le_bytes());
        for (index, span) in self.sections.iter().enumerate() {
            let base = 64 + index * 8;
            out[base..base + 4].copy_from_slice(&span.offset.to_le_bytes());
            out[base + 4..base + 8].copy_from_slice(&span.count.to_le_bytes());
        }
        // The reserved tail is part of the image and `parse` refuses a non-zero
        // byte there, so it is written, not inherited from the caller's buffer
        // (which may hold anything, including bytes from a previous secret).
        out[64 + SECTION_COUNT * 8..HEADER_SIZE].fill(0);
    }
}

/// Decode limits applied to every untrusted buffer.
///
/// Defaults are generous for real modules (millions of nodes) and tight
/// enough that a hostile [`HEADER_SIZE`]-byte buffer cannot make a reader
/// allocate gigabytes. Every field is a hard ceiling; `0` is rejected by
/// [`Limits::check`] (there is no unlimited mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_nodes: u32,
    pub max_edges: u32,
    pub max_children: u32,
    pub max_fields: u32,
    pub max_parts: u32,
    pub max_strings: u32,
    pub max_string_bytes: u32,
    pub max_blobs: u32,
    pub max_blob_bytes: u32,
    pub max_annotations: u32,
    pub max_units: u32,
    pub max_types: u32,
    pub max_aux: u32,
    pub max_numbers: u32,
    pub max_secrets: u32,
    pub max_secret_bytes: u32,
    pub max_extensions: u32,
    pub max_prov_entries: u32,
    /// Provenance hash-table entries.
    pub max_hashes: u32,
    /// Binding entries (the table carries a root word, then name/node pairs).
    pub max_bindings: u32,
    pub max_total_bytes: u64,
    pub max_depth: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_nodes: 1 << 22,
            max_edges: 1 << 24,
            max_children: 1 << 24,
            max_fields: 1 << 24,
            max_parts: 1 << 22,
            max_strings: 1 << 22,
            max_string_bytes: 64 << 20,
            max_blobs: 1 << 20,
            max_blob_bytes: 512 << 20,
            max_annotations: 1 << 22,
            max_units: 1 << 16,
            max_types: 1 << 20,
            max_aux: 1 << 24,
            max_numbers: 1 << 24,
            max_secrets: 1 << 20,
            max_secret_bytes: 16 << 20,
            max_extensions: 1 << 16,
            max_prov_entries: 1 << 16,
            max_hashes: 1 << 20,
            max_bindings: 1 << 20,
            max_total_bytes: 1 << 30,
            max_depth: 4096,
        }
    }
}

impl Limits {
    /// A tight profile for tests and adversarial surfaces.
    pub fn strict() -> Self {
        Self {
            max_nodes: 4096,
            max_edges: 16384,
            max_children: 16384,
            max_fields: 16384,
            max_parts: 4096,
            max_strings: 4096,
            max_string_bytes: 1 << 20,
            max_blobs: 256,
            max_blob_bytes: 1 << 20,
            max_annotations: 4096,
            max_units: 1024,
            max_types: 1024,
            max_aux: 16384,
            max_numbers: 16384,
            max_secrets: 256,
            max_secret_bytes: 1 << 16,
            max_extensions: 64,
            max_prov_entries: 256,
            max_hashes: 4096,
            max_bindings: 4096,
            max_total_bytes: 8 << 20,
            max_depth: 128,
        }
    }

    /// Reject a limits value whose ceiling would disable it.
    ///
    /// Every field is covered: a zero anywhere is an argument error, not a
    /// "limit" the reader discovers later as `infinity/limit` on the first
    /// hostile input. The message names the field so a caller can fix it.
    pub fn check(&self) -> Result<()> {
        let ceilings: [(&'static str, u64); 22] = [
            ("max_nodes", self.max_nodes as u64),
            ("max_edges", self.max_edges as u64),
            ("max_children", self.max_children as u64),
            ("max_fields", self.max_fields as u64),
            ("max_parts", self.max_parts as u64),
            ("max_strings", self.max_strings as u64),
            ("max_string_bytes", self.max_string_bytes as u64),
            ("max_blobs", self.max_blobs as u64),
            ("max_blob_bytes", self.max_blob_bytes as u64),
            ("max_annotations", self.max_annotations as u64),
            ("max_units", self.max_units as u64),
            ("max_types", self.max_types as u64),
            ("max_aux", self.max_aux as u64),
            ("max_numbers", self.max_numbers as u64),
            ("max_secrets", self.max_secrets as u64),
            ("max_secret_bytes", self.max_secret_bytes as u64),
            ("max_extensions", self.max_extensions as u64),
            ("max_prov_entries", self.max_prov_entries as u64),
            ("max_hashes", self.max_hashes as u64),
            ("max_bindings", self.max_bindings as u64),
            ("max_total_bytes", self.max_total_bytes),
            ("max_depth", self.max_depth as u64),
        ];
        for (name, value) in ceilings {
            if value == 0 {
                return Err(Error::InvalidArgument(match name {
                    "max_nodes" => "max_nodes must be non-zero",
                    "max_edges" => "max_edges must be non-zero",
                    "max_children" => "max_children must be non-zero",
                    "max_fields" => "max_fields must be non-zero",
                    "max_parts" => "max_parts must be non-zero",
                    "max_strings" => "max_strings must be non-zero",
                    "max_string_bytes" => "max_string_bytes must be non-zero",
                    "max_blobs" => "max_blobs must be non-zero",
                    "max_blob_bytes" => "max_blob_bytes must be non-zero",
                    "max_annotations" => "max_annotations must be non-zero",
                    "max_units" => "max_units must be non-zero",
                    "max_types" => "max_types must be non-zero",
                    "max_aux" => "max_aux must be non-zero",
                    "max_numbers" => "max_numbers must be non-zero",
                    "max_secrets" => "max_secrets must be non-zero",
                    "max_secret_bytes" => "max_secret_bytes must be non-zero",
                    "max_extensions" => "max_extensions must be non-zero",
                    "max_prov_entries" => "max_prov_entries must be non-zero",
                    "max_hashes" => "max_hashes must be non-zero",
                    "max_bindings" => "max_bindings must be non-zero",
                    "max_total_bytes" => "max_total_bytes must be non-zero",
                    _ => "max_depth must be non-zero",
                }));
            }
        }
        Ok(())
    }
}

/// Decode options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeOpts {
    pub limits: Limits,
    /// Verify the stored content hash (always recommended; only tests that
    /// intentionally mutate bytes turn it off).
    pub verify_hash: bool,
    /// Prove that the image is exactly the canonical encoding of its own
    /// content. This is unconditional: an unflagged image fails, because the
    /// canonical encoding of its content carries the canonical flag.
    pub verify_canonical: bool,
}

impl Default for DecodeOpts {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            verify_hash: true,
            verify_canonical: false,
        }
    }
}

impl DecodeOpts {
    /// Everything on: the profile for untrusted network input.
    pub fn paranoid() -> Self {
        Self {
            limits: Limits::strict(),
            verify_hash: true,
            verify_canonical: true,
        }
    }
}

/// Encode options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeOpts {
    /// Store the full 32-byte Blake3 content hash.
    pub write_hash: bool,
    /// Mark the image canonical (the encoder always writes canonical form).
    pub mark_canonical: bool,
    /// Preserve the `streamed` flag when re-encoding a reassembled module.
    pub streamed: bool,
}

impl Default for EncodeOpts {
    fn default() -> Self {
        Self {
            write_hash: true,
            mark_canonical: true,
            streamed: false,
        }
    }
}

/// Metadata describing a validated image, returned by `validate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    pub flags: u16,
    pub major: u16,
    pub minor: u16,
    pub dialect_hash: u64,
    pub content_hash: [u8; 32],
    pub total_size: u64,
    pub nodes: u32,
    pub edges: u32,
    pub strings: u32,
    pub string_bytes: u32,
    pub blobs: u32,
    pub blob_bytes: u32,
    pub annotations: u32,
    pub units: u32,
    pub types: u32,
    pub secrets: u32,
    pub extensions: u32,
}

impl Meta {
    pub fn has_annotations(&self) -> bool {
        self.annotations > 0
    }

    pub fn has_provenance(&self) -> bool {
        self.flags & FLAG_PROVENANCE != 0
    }
}

/// Read a little-endian `u32`, mapping short input to a truncation error.
pub fn read_u32(buf: &[u8], offset: usize) -> Result<u32> {
    // A caller-supplied offset can be `usize::MAX`; `offset + 4` would wrap (or
    // panic in a debug build) instead of reporting a truncated buffer.
    let end = offset.checked_add(4).ok_or(Error::Truncated {
        needed: u64::MAX,
        found: buf.len() as u64,
    })?;
    if end > buf.len() {
        return Err(Error::Truncated {
            needed: end as u64,
            found: buf.len() as u64,
        });
    }
    Ok(u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

/// Read a little-endian `u64`, mapping short input to a truncation error.
pub fn read_u64(buf: &[u8], offset: usize) -> Result<u64> {
    let end = offset.checked_add(8).ok_or(Error::Truncated {
        needed: u64::MAX,
        found: buf.len() as u64,
    })?;
    if end > buf.len() {
        return Err(Error::Truncated {
            needed: end as u64,
            found: buf.len() as u64,
        });
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..end]);
    Ok(u64::from_le_bytes(bytes))
}

/// Write helpers used by the encoder.
pub fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Pad `out` with zero bytes to the next 8-byte boundary.
pub fn pad8(out: &mut Vec<u8>) {
    while out.len() % 8 != 0 {
        out.push(0);
    }
}

/// The dialect this build implements: a hash over the format version and the
/// Highest node kind this dialect defines.
///
/// A new kind is a dialect change: bump this, the preimage text below and the
/// golden hash together, and treat the wire format as a new minor version.
pub const NODE_KIND_MAX: u8 = 24;

/// Aux tag values the dialect defines, in the order the preimage lists them.
///
/// The decoder validates every aux tag against this vocabulary; the preimage
/// text and the golden hash are pinned to it by
/// `tests/marathon_layout_tests.rs`, so adding a tag without updating the
/// dialect fails the build's test gate instead of shipping quietly.
pub const AUX_TAGS: &[u32] = &[
    0, 1, 2, 3, 4, 10, 11, 12, 20, 21, 22, 23, 24, 25, 26, 30, 31,
];

/// The node-kind fragment of the dialect preimage.
pub const DIALECT_KINDS_TEXT: &str = "node-kinds:0..=24";

/// The aux-tag fragment of the dialect preimage.
pub const DIALECT_AUX_TAGS_TEXT: &str = "aux-tags:0,1,2,3,4,10,11,12,20,21,22,23,24,25,26,30,31";

/// The dialect hash every image carries at this format version.
///
/// Pinned by a test: changing the value changes every image, so it is a format
/// decision with a version bump, never a side effect of an edit.
pub const DIALECT_HASH_GOLDEN: u64 = 0x7782_d0ea_5e28_b75d;

/// Dialect identity: format version plus the semantic tables (unit
/// discriminants, node kinds, aux tags). Stored in every header so a peer can
/// refuse a module produced by an incompatible build before parsing a single
/// record.
pub fn dialect_hash() -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"active-infinity/dialect");
    hasher.update(&FORMAT_MAJOR.to_le_bytes());
    hasher.update(&FORMAT_MINOR.to_le_bytes());
    hasher.update(&crate::unit::UNIT_MAX_BUILTIN.to_le_bytes());
    hasher.update(DIALECT_KINDS_TEXT.as_bytes());
    hasher.update(DIALECT_AUX_TAGS_TEXT.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips() {
        let mut header = Header {
            major: FORMAT_MAJOR,
            minor: FORMAT_MINOR,
            flags: FLAG_CANONICAL,
            header_size: HEADER_SIZE as u16,
            content_hash: [7u8; 32],
            dialect_hash: dialect_hash(),
            total_size: 512,
            sections: [SectionSpan::default(); SECTION_COUNT],
        };
        header.span_mut(Section::Nodes).offset = 192;
        header.span_mut(Section::Nodes).count = 3;
        let mut bytes = vec![0u8; HEADER_SIZE];
        header.write(&mut bytes);
        let parsed = Header::parse(&bytes).expect("parse");
        assert_eq!(parsed, header);
    }

    #[test]
    fn rejects_short_and_misversioned_input() {
        assert_eq!(Header::parse(b"AI"), Err(Error::Magic));
        assert_eq!(Header::parse(b"XXXX").unwrap_err(), Error::Magic);
        let mut bytes = vec![0u8; HEADER_SIZE];
        bytes[0..4].copy_from_slice(&MAGIC);
        // major defaults to 0 in the zeroed buffer
        assert!(matches!(Header::parse(&bytes), Err(Error::VersionMajor(0))));
        bytes[4..6].copy_from_slice(&FORMAT_MAJOR.to_le_bytes());
        // A zeroed header-size field is refused before any section is read.
        assert_eq!(Header::parse(&bytes).unwrap_err(), Error::HeaderSize(0));
        bytes[10..12].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
        assert!(Header::parse(&bytes).is_ok());
    }

    #[test]
    fn alignment_and_rounding() {
        assert_eq!(align8(0), 0);
        assert_eq!(align8(1), 8);
        assert_eq!(align8(8), 8);
        assert_eq!(align8(9), 16);
    }

    #[test]
    fn floats_canonicalize() {
        assert_eq!(canonical_f64(-0.0).to_bits(), 0.0f64.to_bits());
        assert_eq!(canonical_f64(f64::NAN).to_bits(), CANONICAL_NAN_BITS);
        assert_eq!(canonical_f64(1.5), 1.5);
    }

    #[test]
    fn dialect_hash_is_stable() {
        assert_eq!(dialect_hash(), dialect_hash());
        assert_ne!(dialect_hash(), 0);
    }
}
