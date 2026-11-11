//! Encoder: canonical module → `AINF` bytes.
//!
//! The encoder is a pure function of the canonical prepared module, so
//! two logically equal modules always produce byte-identical images. It is
//! fail-closed on unreachable nodes (INF-04): a node no root reaches is
//! refused (`infinity/node`, reason `unreachable node`) instead of being
//! silently dropped, because a dropped node — above all a secret — is data
//! loss the caller never sees. Only the explicit opt-in
//! `EncodeOpts::drop_unreachable` (stream deltas, merge) drops them.
//!
//! Emission
//! is a single forward pass: every section is laid out in the fixed order
//! declared by [`crate::layout::Section`], each starting on an 8-byte
//! boundary, padded with zero bytes, and the content hash is computed over
//! the finished image with the hash field itself zeroed.

// Module-level: item docs for this layer live in docs/spec/layout.md and
// docs/spec/streaming.md; the crate root keeps deny(missing_docs) for the
// hand-written public surface.
#![allow(missing_docs)]

use crate::canonical::{prepare, Prepared};
use crate::error::{Error, Result};
use crate::ir::{
    AnnotationKind, Constraint, InfinityModule, Inode, InterpPart, PatchOp, ProvValue, Provenance,
    TypeSpec,
};
use crate::layout::{
    align8, dialect_hash, EncodeOpts, Header, Section, SectionSpan, ANNOTATION_SIZE,
    ANN_KIND_AI_IMMUTABLE, ANN_KIND_CONSTRAINT, ANN_KIND_INTENT, AUX_CONSTRAINT_CUSTOM,
    AUX_CONSTRAINT_ENUM_ITEM, AUX_CONSTRAINT_MAX, AUX_CONSTRAINT_MIN, AUX_CONSTRAINT_PATTERN,
    AUX_PATCH_PATH, AUX_PATCH_RENAME_TO, AUX_PATCH_VALUE, AUX_SCHEMA_DEFAULT,
    AUX_SCHEMA_DEPRECATED, AUX_SCHEMA_MAX, AUX_SCHEMA_MAX_LEN, AUX_SCHEMA_MIN, AUX_SCHEMA_MIN_LEN,
    AUX_SCHEMA_PATTERN, AUX_SIZE, AUX_TYPE_ENUM_ITEM, AUX_TYPE_TABLE, BLOB_ENTRY_SIZE, CHILD_SIZE,
    CONSTRAINT_KIND_CUSTOM, CONSTRAINT_KIND_ENUM, CONSTRAINT_KIND_MIN_MAX, CONSTRAINT_KIND_ODD,
    CONSTRAINT_KIND_PATTERN, EDGE_SIZE, EXT_DIR_SIZE, FIELD_SIZE, FLAG_ANNOTATIONS, FLAG_CANONICAL,
    FLAG_EXTENSIONS, FLAG_PROVENANCE, FLAG_SECRETS, FLAG_STREAMED, FORMAT_MAJOR, FORMAT_MINOR,
    HEADER_SIZE, NODE_FLAG_0, NODE_FLAG_1, NODE_RECORD_SIZE, NUM_SIZE, PART_EXPR, PART_LITERAL,
    PART_SIZE, PATCH_KIND_REMOVE, PATCH_KIND_RENAME, PATCH_KIND_SET, PROV_ENTRY_SIZE,
    PROV_HEADER_SIZE, SECRET_ENTRY_SIZE, TYPE_SIZE, UNIT_SIZE,
};

/// One wire node record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct NodeRec {
    pub kind: u8,
    pub flags: u8,
    /// Kind-specific small field (string id, op code, node id, type index).
    pub aux: u32,
    pub a: u64,
    pub b: u64,
    pub c: u64,
}

impl NodeRec {
    pub(crate) fn to_bytes(self) -> [u8; NODE_RECORD_SIZE] {
        let mut out = [0u8; NODE_RECORD_SIZE];
        out[0] = self.kind;
        out[1] = self.flags;
        out[2..4].copy_from_slice(&0u16.to_le_bytes());
        out[4..8].copy_from_slice(&self.aux.to_le_bytes());
        out[8..16].copy_from_slice(&self.a.to_le_bytes());
        out[16..24].copy_from_slice(&self.b.to_le_bytes());
        out[24..32].copy_from_slice(&self.c.to_le_bytes());
        out
    }
}

struct NodeTables {
    records: Vec<NodeRec>,
    children: Vec<u32>,
    fields: Vec<(u32, u32)>,
    parts: Vec<(u32, u32)>,
    aux: Vec<(u32, u32)>,
}

/// Encode a module with default options.
///
/// An unreachable node is refused (`infinity/node`, reason
/// `unreachable node`); pass
/// `EncodeOpts { drop_unreachable: true, ..EncodeOpts::default() }` to
/// [`encode_with`] when the drop is intended (stream deltas, merge).
pub fn encode(module: &InfinityModule) -> Result<Vec<u8>> {
    encode_with(module, EncodeOpts::default())
}

/// Encode a module with explicit options.
pub fn encode_with(module: &InfinityModule, opts: EncodeOpts) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_into_with(module, &mut out, opts)?;
    Ok(out)
}

/// Encode into an existing buffer, reusing its capacity.
///
/// The buffer is cleared and refilled. A caller that encodes repeatedly (a
/// server, a store, a test harness) pays one allocation instead of one per
/// image; the bytes are identical to [`encode`]. On error the buffer is
/// left empty (INF-L06): a failed encode never leaves the previous image
/// behind for a caller to mistake for the new one.
pub fn encode_into(module: &InfinityModule, out: &mut Vec<u8>) -> Result<()> {
    encode_into_with(module, out, EncodeOpts::default())
}

/// Encode into an existing buffer with explicit options.
///
/// An unreachable node is refused unless `opts.drop_unreachable` is set:
/// canonicalization drops such a node, so encoding without this check would
/// silently delete data — including secrets — and return `Ok` (INF-04).
/// The wire validator refuses unreachable nodes for the same reason; the
/// in-memory and wire rules now agree.
///
/// On error `out` is empty (INF-L06): it is cleared here, before the
/// reachability check and `prepare()`, so a failure in either leaves no
/// stale image behind, and it is cleared again if emission itself fails
/// after writing has begun, so a partial image never survives either.
pub fn encode_into_with(
    module: &InfinityModule,
    out: &mut Vec<u8>,
    opts: EncodeOpts,
) -> Result<()> {
    // INF-L06: clear first, before anything can fail. On a `prepare()`
    // failure this used to return `Err` with `out` still holding the
    // previous image — a caller that read `out` without checking the `Err`
    // (or that retried) could publish or use a stale image for the wrong
    // module. Clearing preserves capacity, so the buffer-reuse contract is
    // unchanged; only the bytes go.
    out.clear();
    if !opts.drop_unreachable {
        module.check_reachable()?;
    }
    let prepared = prepare(module)?;
    // The exact-size check runs inside `encode_prepared_into` (INF-L05):
    // it needs the built node tables, so it cannot run here, but it still
    // runs before the encoder allocates the image itself.
    match encode_prepared_into(&prepared, opts, out) {
        Ok(()) => Ok(()),
        Err(err) => {
            // INF-L06: emission can still fail after writing has begun (an
            // encoder fault on a prepared module — unreachable from the
            // public API, since `prepare()` validates the invariants
            // emission relies on, but not impossible for a future fallible
            // step). A partial image is the same hazard as a stale one, so
            // it goes too: `Err` always leaves `out` empty.
            out.clear();
            Err(err)
        }
    }
}

/// The scalar inputs to the exact image-size computation (INF-L05).
///
/// Every field is a count or a byte sum in `u64`, so the computation below
/// needs no table allocation of its own: the boundary tests feed it counts
/// past 4 GiB directly, without building a multi-gigabyte module.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ImageSizeCounts {
    /// Node records (`Section::Nodes`).
    nodes: u64,
    /// Child ids (`Section::Children`).
    children: u64,
    /// Table/schema-table fields (`Section::Fields`).
    fields: u64,
    /// Interpolation parts (`Section::Parts`).
    parts: u64,
    /// Derived edges (`Section::Edges`).
    edges: u64,
    /// Annotations (`Section::Annotations`).
    annotations: u64,
    /// Aux entries: node-table aux plus every type's aux (`Section::Aux`).
    aux: u64,
    /// Type records (`Section::Types`).
    types: u64,
    /// Unit records (`Section::Units`).
    units: u64,
    /// Number records (`Section::Numbers`).
    numbers: u64,
    /// Hash records (`Section::Hashes`).
    hashes: u64,
    /// Bindings, excluding the root entry the wire always writes
    /// (`Section::Bindings`).
    bindings: u64,
    /// Number of interned strings (`Section::Strings`).
    strings: u64,
    /// Sum of the interned string lengths in bytes.
    string_bytes: u64,
    /// Blob table entries (`Section::Blobs`).
    blobs: u64,
    /// Payload bytes actually emitted: only `has_payload` blobs carry bytes
    /// in the image; a detached blob contributes its 40-byte entry alone.
    blob_payload_bytes: u64,
    /// Secret heap entries (`Section::Secrets`).
    secrets: u64,
    /// Sum of the secret lengths in bytes.
    secret_bytes: u64,
    /// Extension directory entries (`Section::Extensions`).
    extensions: u64,
    /// Sum of the extension payload lengths, each rounded up to 8 bytes
    /// (the encoder pads every payload, `encode_extensions`).
    extension_bytes: u64,
    /// Provenance block bytes: `0` when there is no provenance, else
    /// `PROV_HEADER_SIZE + PROV_ENTRY_SIZE * entries`.
    provenance_bytes: u64,
}

/// Add `amount` to `total`, refusing with [`Error::TooLarge`] on overflow.
///
/// An overflow here means the size is astronomically past the u32 offset
/// space, so refusing is correct even though the arithmetic itself wrapped.
fn size_add(total: u64, amount: u64) -> Result<u64> {
    total.checked_add(amount).ok_or(Error::TooLarge)
}

/// Multiply `count` by `stride`, refusing with [`Error::TooLarge`] on
/// overflow (same reasoning as [`size_add`]).
fn size_mul(count: u64, stride: u64) -> Result<u64> {
    count.checked_mul(stride).ok_or(Error::TooLarge)
}

/// Padding bytes `pad` appends after a section of `len` bytes: every section
/// starts on an 8-byte boundary, so a section's pad depends only on its own
/// length.
fn size_pad(len: u64) -> u64 {
    (8 - len % 8) % 8
}

/// Compute the exact size, in bytes, of the image `encode_prepared_into`
/// is about to write, or refuse with [`Error::TooLarge`] when it cannot fit
/// the u32 offset space (INF-L05).
///
/// This replaces `estimate_image_size`, which summed only nodes, types,
/// units, numbers, hashes, bindings, strings, blobs, secrets and extensions
/// — a lower bound that omitted children (64 MiB at the decode limits, and
/// unbounded on encode, where `prepare()` enforces no table limits),
/// fields (256 MiB), parts, edges (128 MiB), annotations, aux (128 MiB)
/// and the provenance block. Its stated purpose — "fail fast … before the
/// encoder allocates the heaps" — therefore failed for images whose omitted
/// tables push the true size past 4 GiB: the encoder allocated most of 4 GiB
/// before the final `u32::try_from(image.len())` failed with `TooLarge`.
///
/// The size is now exact, not an estimate, because every section's byte
/// count is a fixed function of the built tables and the prepared module,
/// and every section starts 8-byte aligned (the header is 224 bytes and
/// each section is padded back to alignment before the next starts):
///
/// * nodes `32 * nodes`; children `4 * children` plus its pad; fields
///   `16 * fields`; parts `8 * parts`; edges `8 * edges`;
/// * strings: `sum(len) + 4 * (strings + 1)` plus its pad when non-empty
///   (one offset per string plus the trailing heap length), `0` when empty;
/// * blobs: `40 * blobs +` emitted payload bytes, plus its pad;
/// * annotations `16 * annotations`; provenance `96 + 16 * entries` when
///   present, else `0`;
/// * extensions: `16 * extensions + sum(align8(payload len))`;
/// * units `8 * units`; types `16 * types`; aux `8 * aux`; numbers
///   `8 * numbers`;
/// * secrets: `sum(len + 8)` plus its pad;
/// * hashes `32 * hashes`; bindings `8 * (bindings + 1)` — the wire always
///   writes the root entry first, even with no bindings.
///
/// The old estimate also under-counted three counted sections by a few
/// bytes each (bindings missed the root entry, strings missed the trailing
/// heap length, extensions missed per-payload alignment padding) and
/// over-counted detached blobs (it charged `payload_len` for every blob,
/// but only `has_payload` blobs emit payload bytes); all three are exact
/// now. Only the four sections whose entry size is not a multiple of 8 —
/// children, strings, blobs, secrets — can carry a pad at all, so the pad
/// terms are exact too, and the total is always a multiple of 8.
///
/// The check runs after `build_node_tables` — the tables are what the
/// omitted sizes are read from — but before `image` is cleared or reserved,
/// so a too-large module still fails before the encoder allocates the
/// image. Building the tables is not the allocation this guards: the tables
/// are proportional to the module the caller already holds, while the image
/// would be a second ~4 GiB. The final `u32::try_from(image.len())` in
/// `encode_prepared_into` stays as the exact-size backstop.
fn exact_image_size(prepared: &Prepared, tables: &NodeTables, edges: &[(u32, u32)]) -> Result<u64> {
    let mut counts = ImageSizeCounts {
        nodes: prepared.nodes.len() as u64,
        children: tables.children.len() as u64,
        fields: tables.fields.len() as u64,
        parts: tables.parts.len() as u64,
        edges: edges.len() as u64,
        annotations: prepared.annotations.len() as u64,
        aux: tables.aux.len() as u64,
        types: prepared.types.len() as u64,
        units: prepared.units.len() as u64,
        numbers: prepared.numbers.len() as u64,
        hashes: prepared.hashes.len() as u64,
        bindings: prepared.bindings.len() as u64,
        strings: prepared.strings.len() as u64,
        blobs: prepared.blobs.len() as u64,
        extensions: prepared.extensions.len() as u64,
        ..ImageSizeCounts::default()
    };
    for text in &prepared.strings {
        counts.string_bytes = size_add(counts.string_bytes, text.len() as u64)?;
    }
    for blob in &prepared.blobs {
        if blob.has_payload {
            counts.blob_payload_bytes = size_add(counts.blob_payload_bytes, blob.payload_len)?;
        }
    }
    for bytes in prepared.secret_bytes() {
        counts.secrets = size_add(counts.secrets, 1)?;
        counts.secret_bytes = size_add(counts.secret_bytes, bytes.len() as u64)?;
    }
    for (_, payload) in &prepared.extensions {
        counts.extension_bytes = size_add(counts.extension_bytes, align8(payload.len() as u64))?;
    }
    for prepared_type in &prepared.types {
        counts.aux = size_add(counts.aux, prepared_type.aux.len() as u64)?;
    }
    counts.provenance_bytes = match &prepared.provenance {
        Some(prov) => size_add(
            PROV_HEADER_SIZE as u64,
            size_mul(prov.entries.len() as u64, PROV_ENTRY_SIZE as u64)?,
        )?,
        None => 0,
    };
    image_size_from_counts(&counts)
}

/// The pure arithmetic half of [`exact_image_size`]: the exact image size
/// for scalar counts, with no table allocation.
///
/// Kept separate so the boundary tests can feed it counts past 4 GiB
/// directly — building a real multi-gigabyte module to exercise the same
/// path would allocate gigabytes on the test machine for no extra signal:
/// the counts are the function's whole input, and `exact_image_size` above
/// is a mechanical transcription of the tables into counts.
fn image_size_from_counts(counts: &ImageSizeCounts) -> Result<u64> {
    let mut total: u64 = HEADER_SIZE as u64;
    total = size_add(total, size_mul(counts.nodes, NODE_RECORD_SIZE as u64)?)?;
    let children = size_mul(counts.children, CHILD_SIZE as u64)?;
    total = size_add(total, size_add(children, size_pad(children))?)?;
    total = size_add(total, size_mul(counts.fields, FIELD_SIZE as u64)?)?;
    total = size_add(total, size_mul(counts.parts, PART_SIZE as u64)?)?;
    total = size_add(total, size_mul(counts.edges, EDGE_SIZE as u64)?)?;
    if counts.strings > 0 {
        let strings = size_add(
            counts.string_bytes,
            size_mul(
                size_add(counts.strings, 1)?,
                4, // one u32 offset per string, plus the trailing heap length
            )?,
        )?;
        total = size_add(total, size_add(strings, size_pad(strings))?)?;
    }
    let blobs = size_add(
        size_mul(counts.blobs, BLOB_ENTRY_SIZE as u64)?,
        counts.blob_payload_bytes,
    )?;
    total = size_add(total, size_add(blobs, size_pad(blobs))?)?;
    total = size_add(total, size_mul(counts.annotations, ANNOTATION_SIZE as u64)?)?;
    total = size_add(total, counts.provenance_bytes)?;
    total = size_add(
        total,
        size_add(
            size_mul(counts.extensions, EXT_DIR_SIZE as u64)?,
            counts.extension_bytes,
        )?,
    )?;
    total = size_add(total, size_mul(counts.units, UNIT_SIZE as u64)?)?;
    total = size_add(total, size_mul(counts.types, TYPE_SIZE as u64)?)?;
    total = size_add(total, size_mul(counts.aux, AUX_SIZE as u64)?)?;
    total = size_add(total, size_mul(counts.numbers, NUM_SIZE as u64)?)?;
    let secrets = size_add(
        size_mul(counts.secrets, SECRET_ENTRY_SIZE as u64)?,
        counts.secret_bytes,
    )?;
    total = size_add(total, size_add(secrets, size_pad(secrets))?)?;
    // One 32-byte Blake3 hash per entry; there is no HASH_SIZE constant.
    total = size_add(total, size_mul(counts.hashes, 32)?)?;
    total = size_add(
        total,
        size_mul(size_add(counts.bindings, 1)?, 8)?, // root entry + one per binding
    )?;
    if total > u32::MAX as u64 {
        return Err(Error::TooLarge);
    }
    Ok(total)
}

/// Encode a batch, reusing the capacity of every output buffer.
///
/// `out` is resized to the batch length; existing buffers keep their capacity.
/// This is the batch path a server uses to encode many modules per tick
/// without an allocation per image.
///
/// Every slot is cleared at entry (INF-L06), so a failed batch never leaves
/// a stale image anywhere: the slots before the failure hold the fresh
/// images for their modules, and the failed slot and every later slot are
/// empty. On success the result is identical to encoding each module in
/// turn; clearing preserves capacity, so the reuse contract is unchanged.
pub fn encode_many<'a, I>(modules: I, out: &mut Vec<Vec<u8>>) -> Result<()>
where
    I: IntoIterator<Item = &'a InfinityModule>,
{
    let modules: Vec<&InfinityModule> = modules.into_iter().collect();
    out.resize_with(modules.len(), Vec::new);
    // INF-L06: clear every slot up front. `encode_into` already clears the
    // failed slot itself, but the slots after the failure are never reached
    // by the loop — without this they would keep the previous batch's
    // images, and a caller reading past the failure would see a stale image
    // for the wrong module. `clear` keeps each buffer's capacity.
    for buffer in out.iter_mut() {
        buffer.clear();
    }
    for (buffer, module) in out.iter_mut().zip(modules) {
        encode_into(module, buffer)?;
    }
    Ok(())
}

/// Encode an already-prepared module.
pub(crate) fn encode_prepared_into(
    prepared: &Prepared,
    opts: EncodeOpts,
    image: &mut Vec<u8>,
) -> Result<()> {
    let mut header = Header {
        major: FORMAT_MAJOR,
        minor: FORMAT_MINOR,
        flags: 0,
        header_size: HEADER_SIZE as u16,
        content_hash: [0u8; 32],
        dialect_hash: dialect_hash(),
        total_size: 0,
        sections: [SectionSpan::default(); crate::layout::SECTION_COUNT],
    };
    if opts.mark_canonical {
        header.flags |= FLAG_CANONICAL;
    }
    if opts.streamed {
        header.flags |= FLAG_STREAMED;
    }
    if !prepared.annotations.is_empty() {
        header.flags |= FLAG_ANNOTATIONS;
    }
    if prepared.provenance.is_some() {
        header.flags |= FLAG_PROVENANCE;
    }
    if !prepared.extensions.is_empty() {
        header.flags |= FLAG_EXTENSIONS;
    }
    if prepared.secret_count() > 0 {
        header.flags |= FLAG_SECRETS;
    }

    let tables = build_node_tables(prepared)?;

    // INF-L05: the exact size is computed from the built tables (children,
    // fields, parts, aux, edges, provenance) before the image is allocated,
    // so a module whose true size cannot fit the u32 offset space fails
    // here instead of after allocating most of 4 GiB. The edges are derived
    // here — moved up from the edges section, where they were previously
    // computed — because the size check needs their count.
    let edges = derive_edges(prepared);
    exact_image_size(prepared, &tables, &edges)?;

    let capacity = HEADER_SIZE + prepared.nodes.len() * NODE_RECORD_SIZE;
    image.clear();
    image.reserve(capacity);
    image.resize(HEADER_SIZE, 0);

    // --- nodes ---------------------------------------------------------
    header.span_mut(Section::Nodes).offset = image.len() as u32;
    header.span_mut(Section::Nodes).count = prepared.nodes.len() as u32;
    for record in &tables.records {
        image.extend_from_slice(&record.to_bytes());
    }
    pad(image);

    // --- children ------------------------------------------------------
    set_span(
        &mut header,
        image.as_slice(),
        Section::Children,
        tables.children.len(),
    )?;
    for child in &tables.children {
        image.extend_from_slice(&child.to_le_bytes());
    }
    pad(image);

    // --- fields --------------------------------------------------------
    set_span(
        &mut header,
        image.as_slice(),
        Section::Fields,
        tables.fields.len(),
    )?;
    for (name, node) in &tables.fields {
        image.extend_from_slice(&name.to_le_bytes());
        image.extend_from_slice(&0u32.to_le_bytes());
        image.extend_from_slice(&node.to_le_bytes());
        image.extend_from_slice(&0u32.to_le_bytes());
    }
    pad(image);

    // --- parts ---------------------------------------------------------
    set_span(
        &mut header,
        image.as_slice(),
        Section::Parts,
        tables.parts.len(),
    )?;
    for (tag, value) in &tables.parts {
        image.extend_from_slice(&tag.to_le_bytes());
        image.extend_from_slice(&value.to_le_bytes());
    }
    pad(image);

    // --- edges (derived) ----------------------------------------------
    // (Derived above, before the INF-L05 size check, which needs the count.)
    set_span(&mut header, image.as_slice(), Section::Edges, edges.len())?;
    for (from, to) in &edges {
        image.extend_from_slice(&from.to_le_bytes());
        image.extend_from_slice(&to.to_le_bytes());
    }
    pad(image);

    // --- strings -------------------------------------------------------
    header.span_mut(Section::Strings).offset = image.len() as u32;
    header.span_mut(Section::Strings).count = prepared.strings.len() as u32;
    if !prepared.strings.is_empty() {
        let mut heap_len = 0u32;
        for string in &prepared.strings {
            image.extend_from_slice(&heap_len.to_le_bytes());
            // INF-L06: the length conversion is checked, like
            // `encode_extensions` already does. The INF-L05 exact-size
            // check refuses any module past 4 GiB before emission, so this
            // cannot wrap in practice — but the site must not depend on a
            // distant gate for its own correctness.
            let len = u32::try_from(string.len()).map_err(|_| Error::TooLarge)?;
            heap_len = heap_len.checked_add(len).ok_or(Error::TooLarge)?;
        }
        image.extend_from_slice(&heap_len.to_le_bytes());
        for string in &prepared.strings {
            image.extend_from_slice(string.as_bytes());
        }
    }
    pad(image);

    // --- blobs ---------------------------------------------------------
    header.span_mut(Section::Blobs).offset = image.len() as u32;
    header.span_mut(Section::Blobs).count = prepared.blobs.len() as u32;
    let mut blob_heap_len = 0u32;
    for blob in &prepared.blobs {
        // INF-L06: checked, as in the strings heap above. `payload_len` is
        // the materialised payload length (0 for a detached blob), and the
        // INF-L05 exact-size check already bounds it — this is defence in
        // depth, so the entry length cannot wrap if the gate ever moves.
        let len = u32::try_from(blob.payload_len).map_err(|_| Error::TooLarge)?;
        image.extend_from_slice(&blob.hash);
        image.extend_from_slice(&blob_heap_len.to_le_bytes());
        image.extend_from_slice(&len.to_le_bytes());
        blob_heap_len = blob_heap_len.checked_add(len).ok_or(Error::TooLarge)?;
    }
    // The payload bytes are written straight from the representative
    // node (`BlobPayload::source`, INF-11): the table holds no copies
    // of its own. A `has_payload` entry whose bytes do not resolve is
    // an encoder fault, not a zero-length entry — silently writing
    // nothing would emit a heap shorter than the table promises.
    for blob in &prepared.blobs {
        if blob.has_payload {
            let payload = blob
                .payload_in(&prepared.nodes)
                .ok_or(Error::Encode("blob payload missing from prepared module"))?;
            debug_assert_eq!(
                payload.len() as u64,
                blob.payload_len,
                "representative payload length must match the table entry"
            );
            image.extend_from_slice(payload);
        }
    }
    pad(image);

    // --- annotations ---------------------------------------------------
    set_span(
        &mut header,
        image.as_slice(),
        Section::Annotations,
        prepared.annotations.len(),
    )?;
    for annotation in &prepared.annotations {
        let (kind, a, b) = match &annotation.kind {
            AnnotationKind::Intent(text) => (
                ANN_KIND_INTENT,
                *prepared
                    .string_index
                    .get(text)
                    .ok_or(Error::Encode("annotation string missing"))?,
                0,
            ),
            AnnotationKind::Constraint { source, expr } => (
                ANN_KIND_CONSTRAINT,
                *prepared
                    .string_index
                    .get(source)
                    .ok_or(Error::Encode("constraint source missing"))?,
                expr.0,
            ),
            AnnotationKind::AiImmutable(flag) => (ANN_KIND_AI_IMMUTABLE, u32::from(*flag), 0),
        };
        image.extend_from_slice(&annotation.node.0.to_le_bytes());
        image.extend_from_slice(&kind.to_le_bytes());
        image.extend_from_slice(&a.to_le_bytes());
        image.extend_from_slice(&b.to_le_bytes());
    }
    pad(image);

    // --- provenance ----------------------------------------------------
    header.span_mut(Section::Provenance).offset = image.len() as u32;
    if let Some(prov) = &prepared.provenance {
        let block = encode_provenance(prov, prepared)?;
        header.span_mut(Section::Provenance).count = block.len() as u32;
        image.extend_from_slice(&block);
    } else {
        header.span_mut(Section::Provenance).count = 0;
    }
    pad(image);

    // --- extensions ----------------------------------------------------
    header.span_mut(Section::Extensions).offset = image.len() as u32;
    header.span_mut(Section::Extensions).count = prepared.extensions.len() as u32;
    encode_extensions(&prepared.extensions, image.len(), image)?;
    pad(image);

    // --- unit table ----------------------------------------------------
    set_span(
        &mut header,
        image.as_slice(),
        Section::Units,
        prepared.units.len(),
    )?;
    for unit in &prepared.units {
        image.extend_from_slice(&unit.discriminant().to_le_bytes());
        let name = if unit.is_builtin() {
            0
        } else {
            *prepared
                .string_index
                .get(unit.name())
                .ok_or(Error::Encode("unit name missing from heap"))?
        };
        image.extend_from_slice(&name.to_le_bytes());
    }
    pad(image);

    // --- type table ----------------------------------------------------
    set_span(
        &mut header,
        image.as_slice(),
        Section::Types,
        prepared.types.len(),
    )?;
    let mut type_aux_start = vec![0u32; prepared.types.len()];
    let mut type_aux_count = vec![0u32; prepared.types.len()];
    {
        let mut offset = tables.aux.len() as u32;
        for (index, prepared_type) in prepared.types.iter().enumerate() {
            type_aux_start[index] = offset;
            type_aux_count[index] = prepared_type.aux.len() as u32;
            offset = offset
                .checked_add(prepared_type.aux.len() as u32)
                .ok_or(Error::TooLarge)?;
        }
    }
    for (index, prepared_type) in prepared.types.iter().enumerate() {
        let (code, flags) = type_code(&prepared_type.spec)?;
        image.extend_from_slice(&code.to_le_bytes());
        image.extend_from_slice(&flags.to_le_bytes());
        image.extend_from_slice(&type_aux_start[index].to_le_bytes());
        image.extend_from_slice(&type_aux_count[index].to_le_bytes());
    }
    pad(image);

    // --- aux -----------------------------------------------------------
    let aux_count = tables.aux.len() + prepared.types.iter().map(|t| t.aux.len()).sum::<usize>();
    set_span(&mut header, image.as_slice(), Section::Aux, aux_count)?;
    for (tag, value) in &tables.aux {
        image.extend_from_slice(&tag.to_le_bytes());
        image.extend_from_slice(&value.to_le_bytes());
    }
    for prepared_type in &prepared.types {
        for (tag, value) in &prepared_type.aux {
            image.extend_from_slice(&tag.to_le_bytes());
            image.extend_from_slice(&value.to_le_bytes());
        }
    }
    pad(image);

    // --- numbers -------------------------------------------------------
    set_span(
        &mut header,
        image.as_slice(),
        Section::Numbers,
        prepared.numbers.len(),
    )?;
    for value in &prepared.numbers {
        image.extend_from_slice(&value.to_le_bytes());
    }
    pad(image);

    // --- secrets -------------------------------------------------------
    header.span_mut(Section::Secrets).offset = image.len() as u32;
    header.span_mut(Section::Secrets).count = prepared.secret_count() as u32;
    let mut secret_heap = 0u32;
    for secret in prepared.secret_bytes() {
        // INF-L06: checked, as in the strings and blobs heaps. One
        // conversion serves both uses — the entry length and the heap
        // accumulation — so they cannot disagree.
        let len = u32::try_from(secret.len()).map_err(|_| Error::TooLarge)?;
        image.extend_from_slice(&secret_heap.to_le_bytes());
        image.extend_from_slice(&len.to_le_bytes());
        secret_heap = secret_heap.checked_add(len).ok_or(Error::TooLarge)?;
    }
    for secret in prepared.secret_bytes() {
        image.extend_from_slice(secret);
    }
    pad(image);

    // --- hashes --------------------------------------------------------
    set_span(
        &mut header,
        image.as_slice(),
        Section::Hashes,
        prepared.hashes.len(),
    )?;
    for hash in &prepared.hashes {
        image.extend_from_slice(hash);
    }
    pad(image);

    // --- bindings ------------------------------------------------------
    header.span_mut(Section::Bindings).offset = image.len() as u32;
    header.span_mut(Section::Bindings).count = prepared.bindings.len() as u32 + 1;
    image.extend_from_slice(
        &prepared
            .root
            .map(|root| root.0)
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    image.extend_from_slice(&0u32.to_le_bytes());
    for (name, id) in &prepared.bindings {
        let sid = *prepared
            .string_index
            .get(name)
            .ok_or(Error::Encode("binding name missing from heap"))?;
        image.extend_from_slice(&sid.to_le_bytes());
        image.extend_from_slice(&id.0.to_le_bytes());
    }
    pad(image);

    // The header describes every section with a u32 offset, so the whole image has
    // to fit that space; a heap can push past it even when each span was written
    // while still below the limit.
    u32::try_from(image.len()).map_err(|_| Error::TooLarge)?;
    header.total_size = image.len() as u64;
    header.write(image);

    if opts.write_hash {
        let hash = hash_image(image.as_slice())?;
        image[16..48].copy_from_slice(&hash);
        let _ = hash;
    }
    Ok(())
}

fn set_span(header: &mut Header, image: &[u8], section: Section, count: usize) -> Result<()> {
    // An image past the u32 offset space cannot be described by the header; it
    // used to wrap and produce overlapping sections that still hashed.
    let offset = u32::try_from(image.len()).map_err(|_| Error::TooLarge)?;
    let count = u32::try_from(count).map_err(|_| Error::TooLarge)?;
    header.span_mut(section).offset = offset;
    header.span_mut(section).count = count;
    Ok(())
}

fn pad(image: &mut Vec<u8>) {
    while image.len() % 8 != 0 {
        image.push(0);
    }
}

/// Compute the Blake3-256 content hash of an image, treating the hash field as
/// zero.
pub fn hash_image(image: &[u8]) -> Result<[u8; 32]> {
    if image.len() < HEADER_SIZE {
        return Err(Error::HeaderTruncated);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(&image[..16]);
    hasher.update(&[0u8; 32]);
    hasher.update(&image[48..]);
    Ok(*hasher.finalize().as_bytes())
}

fn build_node_tables(prepared: &Prepared) -> Result<NodeTables> {
    let mut tables = NodeTables {
        records: Vec::with_capacity(prepared.nodes.len()),
        children: Vec::new(),
        fields: Vec::new(),
        parts: Vec::new(),
        aux: Vec::new(),
    };
    let mut secret_cursor = 0u32;
    for node in &prepared.nodes {
        let string = |text: &str| -> Result<u32> {
            prepared
                .string_index
                .get(text)
                .copied()
                .ok_or(Error::Encode("string missing from heap"))
        };
        let record = match node {
            Inode::Null => NodeRec {
                kind: 0,
                ..NodeRec::default()
            },
            Inode::Bool(value) => NodeRec {
                kind: 1,
                a: u64::from(*value),
                ..NodeRec::default()
            },
            Inode::Int(value) => NodeRec {
                kind: 2,
                a: *value as u64,
                ..NodeRec::default()
            },
            Inode::Float(value) => NodeRec {
                kind: 3,
                a: crate::layout::canonical_f64(*value).to_bits(),
                ..NodeRec::default()
            },
            Inode::Str(text) => NodeRec {
                kind: 4,
                aux: string(text)?,
                ..NodeRec::default()
            },
            Inode::DurationMs(ms) => NodeRec {
                kind: 5,
                a: *ms,
                ..NodeRec::default()
            },
            Inode::Quantity { value, unit } => NodeRec {
                kind: 6,
                aux: value.0,
                a: *prepared
                    .unit_index
                    .get(unit)
                    .ok_or(Error::Encode("unit missing from table"))? as u64,
                ..NodeRec::default()
            },
            Inode::Array { elements } => {
                let start = tables.children.len() as u32;
                tables.children.extend(elements.iter().map(|id| id.0));
                NodeRec {
                    kind: 7,
                    a: u64::from(start),
                    b: elements.len() as u64,
                    ..NodeRec::default()
                }
            }
            Inode::Table { fields } => {
                let start = tables.fields.len() as u32;
                for (name, id) in fields {
                    tables.fields.push((string(name)?, id.0));
                }
                NodeRec {
                    kind: 8,
                    a: u64::from(start),
                    b: fields.len() as u64,
                    ..NodeRec::default()
                }
            }
            Inode::Secret(_) => {
                let index = secret_cursor;
                secret_cursor = secret_cursor.checked_add(1).ok_or(Error::TooLarge)?;
                NodeRec {
                    kind: 9,
                    a: u64::from(index),
                    ..NodeRec::default()
                }
            }
            Inode::SecretRef { locator } => NodeRec {
                kind: 10,
                a: u64::from(locator.0),
                ..NodeRec::default()
            },
            Inode::Ref(id) => NodeRec {
                kind: 11,
                a: u64::from(id.0),
                ..NodeRec::default()
            },
            Inode::Env { name, default } => NodeRec {
                kind: 12,
                aux: string(name)?,
                a: default.map(|id| id.0 as u64).unwrap_or(u32::MAX as u64),
                ..NodeRec::default()
            },
            Inode::Ident(name) => NodeRec {
                kind: 13,
                aux: string(name)?,
                ..NodeRec::default()
            },
            Inode::Interpolate { parts } => {
                let start = tables.parts.len() as u32;
                for part in parts {
                    match part {
                        InterpPart::Literal(text) => {
                            tables.parts.push((PART_LITERAL, string(text)?));
                        }
                        InterpPart::Expr(id) => {
                            tables.parts.push((PART_EXPR, id.0));
                        }
                    }
                }
                NodeRec {
                    kind: 14,
                    a: u64::from(start),
                    b: parts.len() as u64,
                    ..NodeRec::default()
                }
            }
            Inode::Binary { op, lhs, rhs } => NodeRec {
                kind: 15,
                aux: op.code(),
                a: u64::from(lhs.0),
                b: u64::from(rhs.0),
                ..NodeRec::default()
            },
            Inode::Unary { op, expr } => NodeRec {
                kind: 16,
                aux: op.code(),
                a: u64::from(expr.0),
                ..NodeRec::default()
            },
            Inode::Constrained { target, constraint } => {
                let start = tables.aux.len() as u32;
                let kind = match constraint {
                    Constraint::MinMax { min, max } => {
                        if let Some(min) = min {
                            tables.aux.push((
                                AUX_CONSTRAINT_MIN,
                                *prepared
                                    .number_index
                                    .get(min)
                                    .ok_or(Error::Encode("constraint min missing"))?,
                            ));
                        }
                        if let Some(max) = max {
                            tables.aux.push((
                                AUX_CONSTRAINT_MAX,
                                *prepared
                                    .number_index
                                    .get(max)
                                    .ok_or(Error::Encode("constraint max missing"))?,
                            ));
                        }
                        CONSTRAINT_KIND_MIN_MAX
                    }
                    Constraint::Enum(items) => {
                        // Sorted, so an enum constraint has one canonical encoding
                        // regardless of the order the author listed its values.
                        let mut ordered: Vec<&String> = items.iter().collect();
                        ordered.sort();
                        for item in ordered {
                            tables.aux.push((AUX_CONSTRAINT_ENUM_ITEM, string(item)?));
                        }
                        CONSTRAINT_KIND_ENUM
                    }
                    Constraint::Pattern(pattern) => {
                        tables.aux.push((AUX_CONSTRAINT_PATTERN, string(pattern)?));
                        CONSTRAINT_KIND_PATTERN
                    }
                    Constraint::Odd => CONSTRAINT_KIND_ODD,
                    Constraint::Custom(text) => {
                        tables.aux.push((AUX_CONSTRAINT_CUSTOM, string(text)?));
                        CONSTRAINT_KIND_CUSTOM
                    }
                };
                NodeRec {
                    kind: 17,
                    aux: kind,
                    a: u64::from(target.0),
                    b: u64::from(start),
                    c: (tables.aux.len() as u32 - start) as u64,
                    ..NodeRec::default()
                }
            }
            Inode::Patch(op) => {
                let start = tables.aux.len() as u32;
                let kind = match op {
                    PatchOp::Set { path, value } => {
                        tables.aux.push((AUX_PATCH_PATH, string(path)?));
                        tables.aux.push((AUX_PATCH_VALUE, value.0));
                        PATCH_KIND_SET
                    }
                    PatchOp::Remove { path } => {
                        tables.aux.push((AUX_PATCH_PATH, string(path)?));
                        PATCH_KIND_REMOVE
                    }
                    PatchOp::Rename { from, to } => {
                        tables.aux.push((AUX_PATCH_PATH, string(from)?));
                        tables.aux.push((AUX_PATCH_RENAME_TO, string(to)?));
                        PATCH_KIND_RENAME
                    }
                };
                NodeRec {
                    kind: 18,
                    aux: kind,
                    b: u64::from(start),
                    c: (tables.aux.len() as u32 - start) as u64,
                    ..NodeRec::default()
                }
            }
            Inode::SchemaField(spec) => {
                let (code, payload) = type_payload(&spec.typ, prepared)?;
                let type_id = *prepared
                    .type_index
                    .get(&(code, payload))
                    .ok_or(Error::Encode("schema type missing from table"))?;
                let start = tables.aux.len() as u32;
                for (tag, node) in [
                    (AUX_SCHEMA_MIN, spec.min),
                    (AUX_SCHEMA_MAX, spec.max),
                    (AUX_SCHEMA_MIN_LEN, spec.min_len),
                    (AUX_SCHEMA_MAX_LEN, spec.max_len),
                    (AUX_SCHEMA_PATTERN, spec.pattern),
                    (AUX_SCHEMA_DEFAULT, spec.default),
                ] {
                    if let Some(id) = node {
                        tables.aux.push((tag, id.0));
                    }
                }
                if let Some(deprecated) = &spec.deprecated {
                    tables
                        .aux
                        .push((AUX_SCHEMA_DEPRECATED, string(deprecated)?));
                }
                NodeRec {
                    kind: 19,
                    aux: type_id,
                    b: u64::from(start),
                    c: (tables.aux.len() as u32 - start) as u64,
                    ..NodeRec::default()
                }
            }
            Inode::SchemaTable { fields, closed } => {
                let start = tables.fields.len() as u32;
                for (name, id) in fields {
                    tables.fields.push((string(name)?, id.0));
                }
                NodeRec {
                    kind: 20,
                    flags: if *closed { NODE_FLAG_0 } else { 0 },
                    a: u64::from(start),
                    b: fields.len() as u64,
                    ..NodeRec::default()
                }
            }
            Inode::SchemaArray { element } => NodeRec {
                kind: 21,
                a: u64::from(element.0),
                ..NodeRec::default()
            },
            Inode::Semantic { tag, inner } => NodeRec {
                kind: 22,
                aux: tag.code(),
                a: u64::from(inner.0),
                ..NodeRec::default()
            },
            Inode::Blob {
                hash,
                size,
                tainted,
                media_type,
                payload,
            } => {
                // The key is (hash, size, payload presence) — the payload
                // bytes themselves are never cloned into the key (INF-11).
                // The presence rule must match `prepare()` exactly:
                // tainted never carries a payload, and an empty payload
                // is the same entry class as a detached blob.
                let has_payload =
                    !*tainted && payload.as_ref().is_some_and(|bytes| !bytes.is_empty());
                let key = (*hash, *size, has_payload);
                let index = *prepared
                    .blob_index
                    .get(&key)
                    .ok_or(Error::Encode("blob missing from table"))?;
                let mut flags = 0u8;
                if *tainted {
                    flags |= NODE_FLAG_0;
                }
                if payload.is_some() {
                    flags |= NODE_FLAG_1;
                }
                NodeRec {
                    kind: 23,
                    flags,
                    aux: string(media_type)?,
                    a: u64::from(index),
                    b: *size,
                    ..NodeRec::default()
                }
            }
            Inode::ContentAddressed { media_type, data } => NodeRec {
                kind: 24,
                a: u64::from(media_type.0),
                b: u64::from(data.0),
                ..NodeRec::default()
            },
        };
        tables.records.push(record);
    }
    Ok(tables)
}

fn type_payload(spec: &TypeSpec, prepared: &Prepared) -> Result<(u32, Vec<(u32, u32)>)> {
    let string = |text: &str| -> Result<u32> {
        prepared
            .string_index
            .get(text)
            .copied()
            .ok_or(Error::Encode("type string missing from heap"))
    };
    let mut aux = Vec::new();
    match spec {
        TypeSpec::Enum(items) => {
            let mut ordered: Vec<&String> = items.iter().collect();
            ordered.sort();
            for item in ordered {
                aux.push((AUX_TYPE_ENUM_ITEM, string(item)?));
            }
        }
        TypeSpec::Table { closed } => aux.push((AUX_TYPE_TABLE, u32::from(*closed))),
        _ => {}
    }
    Ok((spec.code(), aux))
}

fn type_code(spec: &TypeSpec) -> Result<(u32, u32)> {
    let flags = match spec {
        TypeSpec::Table { closed } => u32::from(*closed),
        _ => 0,
    };
    Ok((spec.code(), flags))
}

fn derive_edges(prepared: &Prepared) -> Vec<(u32, u32)> {
    let mut edges = Vec::new();
    for (index, node) in prepared.nodes.iter().enumerate() {
        let dependent = index as u32;
        for child in node.children() {
            edges.push((child.0, dependent));
        }
    }
    edges.sort_unstable();
    edges.dedup();
    edges
}

fn encode_provenance(prov: &Provenance, prepared: &Prepared) -> Result<Vec<u8>> {
    let mut block = vec![0u8; PROV_HEADER_SIZE];
    block[0..4].copy_from_slice(&1u32.to_le_bytes());
    block[4..8].copy_from_slice(&(prov.entries.len() as u32).to_le_bytes());
    block[8..16].copy_from_slice(&prov.timestamp_ms.to_le_bytes());
    let sid = |text: &Option<String>| -> Result<u32> {
        match text {
            Some(text) => Ok(*prepared
                .string_index
                .get(text)
                .ok_or(Error::Encode("provenance string missing"))?),
            None => Ok(u32::MAX),
        }
    };
    block[16..20].copy_from_slice(&sid(&prov.producer)?.to_le_bytes());
    block[20..24].copy_from_slice(&sid(&prov.model)?.to_le_bytes());
    block[24..28].copy_from_slice(&sid(&prov.tool)?.to_le_bytes());
    let mut flags = 0u32;
    if prov.parent.is_some() {
        flags |= 1;
    }
    block[28..32].copy_from_slice(&flags.to_le_bytes());
    if let Some(parent) = prov.parent {
        block[32..64].copy_from_slice(&parent);
    }
    for entry in &prov.entries {
        let key = *prepared
            .string_index
            .get(&entry.key)
            .ok_or(Error::Encode("provenance key missing"))?;
        let (kind, a) = match &entry.value {
            ProvValue::Text(text) => (
                0u32,
                *prepared
                    .string_index
                    .get(text)
                    .ok_or(Error::Encode("provenance text missing"))?,
            ),
            ProvValue::Int(value) => (
                1u32,
                *prepared
                    .number_index
                    .get(value)
                    .ok_or(Error::Encode("provenance int missing"))?,
            ),
            ProvValue::Flag(flag) => (2u32, u32::from(*flag)),
            ProvValue::Hash(hash) => (
                3u32,
                *prepared
                    .hash_index
                    .get(hash)
                    .ok_or(Error::Encode("provenance hash missing"))?,
            ),
        };
        block.extend_from_slice(&kind.to_le_bytes());
        block.extend_from_slice(&key.to_le_bytes());
        block.extend_from_slice(&a.to_le_bytes());
        block.extend_from_slice(&0u32.to_le_bytes());
    }
    Ok(block)
}

fn encode_extensions(
    extensions: &[(u64, Vec<u8>)],
    start: usize,
    image: &mut Vec<u8>,
) -> Result<()> {
    if extensions.is_empty() {
        return Ok(());
    }
    let dir_size = EXT_DIR_SIZE
        .checked_mul(extensions.len())
        .ok_or(Error::TooLarge)?;
    let mut payload_offset = start + dir_size;
    let mut directory = Vec::with_capacity(dir_size);
    for (tag, payload) in extensions {
        directory.extend_from_slice(&tag.to_le_bytes());
        directory.extend_from_slice(
            &u32::try_from(payload_offset)
                .map_err(|_| Error::TooLarge)?
                .to_le_bytes(),
        );
        directory.extend_from_slice(
            &u32::try_from(payload.len())
                .map_err(|_| Error::TooLarge)?
                .to_le_bytes(),
        );
        payload_offset = align8(payload_offset as u64 + payload.len() as u64) as usize;
    }
    image.extend_from_slice(&directory);
    for (_, payload) in extensions {
        image.extend_from_slice(payload);
        pad(image);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ProvEntry, ProvValue, Provenance, SchemaFieldSpec, SecretBytes, TypeSpec};
    use crate::unit::UnitTag;

    /// Estimated size of `module` through the same path `encode` takes:
    /// prepare, build the node tables, derive the edges, exact-size.
    fn estimated_len(module: &InfinityModule) -> u64 {
        let prepared = prepare(module).expect("test module must prepare");
        let tables = build_node_tables(&prepared).expect("test module must build tables");
        let edges = derive_edges(&prepared);
        exact_image_size(&prepared, &tables, &edges).expect("test module must fit")
    }

    /// Assert the estimate equals the emitted image length, and that the
    /// image's own header total agrees with both.
    fn assert_estimate_is_exact(module: &InfinityModule) {
        let image = encode(module).expect("test module must encode");
        let estimated = estimated_len(module);
        assert_eq!(
            estimated,
            image.len() as u64,
            "exact size {estimated} != emitted image length {}",
            image.len()
        );
        let header = Header::parse(&image).expect("encoded image must parse");
        assert_eq!(
            header.total_size,
            image.len() as u64,
            "header total_size {} != emitted image length {}",
            header.total_size,
            image.len()
        );
    }

    /// A module that exercises every section the encoder emits, with odd
    /// counts/lengths wherever a section can carry alignment padding, so a
    /// missed pad term shows up as an exactness failure: 19 children
    /// (76 bytes + 4 pad), 3 table fields, 3 interpolation parts, 5
    /// constrained + 3 patch nodes (aux), 3 annotations, a 4-entry
    /// provenance block, extensions of length 1/7/8/9 (align8), a
    /// payload blob plus a detached blob, a 7-byte secret (pad), a named
    /// unit, an enum type (type aux), 2 bindings plus the root entry.
    fn kitchen_sink_module() -> InfinityModule {
        let mut module = InfinityModule::new();
        let int_a = module.push(Inode::Int(7));
        let int_b = module.push(Inode::Int(-3));
        let float = module.push(Inode::Float(1.5));
        let boolean = module.push(Inode::Bool(true));
        let duration = module.push(Inode::DurationMs(1_234));
        let str_a = module.push(Inode::Str("a".into()));
        let str_b = module.push(Inode::Str("ab".into()));
        let str_c = module.push(Inode::Str("abcde".into()));
        let table = module.push(Inode::Table {
            fields: vec![
                ("one".into(), int_a),
                ("two".into(), str_a),
                ("three".into(), int_b),
            ],
        });
        let schema_field = module.push(Inode::SchemaField(SchemaFieldSpec {
            typ: TypeSpec::Enum(vec!["red".into(), "blue".into()]),
            min: Some(int_a),
            max: Some(int_b),
            min_len: Some(int_a),
            max_len: Some(int_b),
            pattern: Some(str_b),
            default: Some(int_a),
            deprecated: Some("use the new field".into()),
        }));
        let schema_table = module.push(Inode::SchemaTable {
            fields: vec![("field".into(), schema_field), ("other".into(), int_a)],
            closed: true,
        });
        let interp = module.push(Inode::Interpolate {
            parts: vec![
                InterpPart::Literal("pre-".into()),
                InterpPart::Expr(int_a),
                InterpPart::Literal("-post".into()),
            ],
        });
        let constrained_min_max = module.push(Inode::Constrained {
            target: int_a,
            constraint: Constraint::MinMax {
                min: Some(-10),
                max: Some(10),
            },
        });
        let constrained_enum = module.push(Inode::Constrained {
            target: int_a,
            constraint: Constraint::Enum(vec!["x".into(), "y".into(), "z".into()]),
        });
        let constrained_pattern = module.push(Inode::Constrained {
            target: str_a,
            constraint: Constraint::Pattern("[a-z]+".into()),
        });
        let constrained_custom = module.push(Inode::Constrained {
            target: int_a,
            constraint: Constraint::Custom("is-prime".into()),
        });
        let constrained_odd = module.push(Inode::Constrained {
            target: int_a,
            constraint: Constraint::Odd,
        });
        let patch_set = module.push(Inode::Patch(PatchOp::Set {
            path: "a.b".into(),
            value: int_a,
        }));
        let patch_remove = module.push(Inode::Patch(PatchOp::Remove { path: "a.c".into() }));
        let patch_rename = module.push(Inode::Patch(PatchOp::Rename {
            from: "a.d".into(),
            to: "a.e".into(),
        }));
        let payload_hash = *blake3::hash(b"abc").as_bytes();
        let blob_with_payload = module.push(Inode::Blob {
            hash: payload_hash,
            size: 3,
            tainted: false,
            media_type: "text/plain".into(),
            payload: Some(b"abc".to_vec()),
        });
        let blob_detached = module.push(Inode::Blob {
            hash: [7u8; 32],
            size: 1000,
            tainted: false,
            media_type: String::new(),
            payload: None,
        });
        let secret = module.push(Inode::Secret(SecretBytes::new(b"s3cr3t!".to_vec())));
        let quantity = module.push(Inode::Quantity {
            value: int_a,
            unit: UnitTag::Named("metre".into()),
        });
        module.annotate(table, AnnotationKind::Intent("table intent".into()));
        module.annotate(
            table,
            AnnotationKind::Constraint {
                source: "x > 0".into(),
                expr: int_a,
            },
        );
        module.annotate(interp, AnnotationKind::AiImmutable(true));
        module.set_provenance(Some(Provenance {
            producer: Some("inf-l05-test".into()),
            timestamp_ms: 1_700_000_000_000,
            model: Some("test-model".into()),
            tool: Some("test-tool".into()),
            parent: Some([9u8; 32]),
            entries: vec![
                ProvEntry {
                    key: "a-text".into(),
                    value: ProvValue::Text("hello".into()),
                },
                ProvEntry {
                    key: "b-int".into(),
                    value: ProvValue::Int(-42),
                },
                ProvEntry {
                    key: "c-flag".into(),
                    value: ProvValue::Flag(true),
                },
                ProvEntry {
                    key: "d-hash".into(),
                    value: ProvValue::Hash([3u8; 32]),
                },
            ],
        }));
        module.add_extension(1, b"x".to_vec());
        module.add_extension(2, b"1234567".to_vec());
        module.add_extension(3, b"12345678".to_vec());
        module.add_extension(4, b"123456789".to_vec());
        module.bind("first", int_a);
        module.bind("second", table);
        // 19 elements: 19 * 4 = 76 bytes of children, plus a 4-byte pad.
        let root = module.push(Inode::Array {
            elements: vec![
                table,
                schema_table,
                interp,
                constrained_min_max,
                constrained_enum,
                constrained_pattern,
                constrained_custom,
                constrained_odd,
                patch_set,
                patch_remove,
                patch_rename,
                blob_with_payload,
                blob_detached,
                secret,
                quantity,
                float,
                boolean,
                duration,
                str_c,
            ],
        });
        module.set_root(Some(root));
        module
    }

    #[test]
    fn estimate_is_exact_for_a_module_using_every_section() {
        assert_estimate_is_exact(&kitchen_sink_module());
    }

    #[test]
    fn estimate_is_exact_for_small_modules() {
        // A single Int root: no bindings, no strings, no children — the
        // wire still writes the root binding entry, so the bindings term
        // is `(0 + 1) * 8`, not `0`.
        let mut module = InfinityModule::new();
        let root = module.push(Inode::Int(0));
        module.set_root(Some(root));
        assert_estimate_is_exact(&module);

        // One string root: the strings section is one offset plus the
        // trailing heap length plus the bytes, plus its pad.
        let mut module = InfinityModule::new();
        let root = module.push(Inode::Str("hello".into()));
        module.set_root(Some(root));
        assert_estimate_is_exact(&module);

        // One binding, no root: the bindings section is the root entry plus
        // the one binding.
        let mut module = InfinityModule::new();
        let node = module.push(Inode::Int(1));
        module.bind("only", node);
        assert_estimate_is_exact(&module);

        // One child: 4 bytes of children plus a 4-byte pad.
        let mut module = InfinityModule::new();
        let child = module.push(Inode::Int(1));
        let root = module.push(Inode::Array {
            elements: vec![child],
        });
        module.set_root(Some(root));
        assert_estimate_is_exact(&module);

        // Two children: 8 bytes, no pad.
        let mut module = InfinityModule::new();
        let first = module.push(Inode::Int(1));
        let second = module.push(Inode::Int(2));
        let root = module.push(Inode::Array {
            elements: vec![first, second],
        });
        module.set_root(Some(root));
        assert_estimate_is_exact(&module);

        // An empty array root: zero children, zero pad.
        let mut module = InfinityModule::new();
        let root = module.push(Inode::Array { elements: vec![] });
        module.set_root(Some(root));
        assert_estimate_is_exact(&module);

        // A lone secret: 8-byte entry plus the bytes, plus its pad.
        let mut module = InfinityModule::new();
        let secret = module.push(Inode::Secret(SecretBytes::new(b"pw".to_vec())));
        module.set_root(Some(secret));
        assert_estimate_is_exact(&module);

        // Provenance with no entries: the 96-byte block alone.
        let mut module = InfinityModule::new();
        let root = module.push(Inode::Int(1));
        module.set_root(Some(root));
        module.set_provenance(Some(Provenance {
            producer: None,
            timestamp_ms: 0,
            model: None,
            tool: None,
            parent: None,
            entries: vec![],
        }));
        assert_estimate_is_exact(&module);

        // One extension with an empty payload: directory entry only.
        let mut module = InfinityModule::new();
        let root = module.push(Inode::Int(1));
        module.set_root(Some(root));
        module.add_extension(1, Vec::new());
        assert_estimate_is_exact(&module);
    }

    #[test]
    fn estimate_rejects_each_omitted_table_past_4gib() {
        // One witness per table the old estimate omitted: the old formula
        // returns `Ok` for all of these (its total is 288 — header plus two
        // node records — because it never reads the omitted table), while
        // the exact size is past `u32::MAX`. The old totals were computed
        // from the HEAD formula; see the INF-L05 record §3.2.
        let base = ImageSizeCounts {
            nodes: 2,
            ..ImageSizeCounts::default()
        };
        for (name, counts) in [
            (
                "children",
                ImageSizeCounts {
                    children: 1 << 30,
                    edges: 1,
                    ..base
                },
            ),
            (
                "fields",
                ImageSizeCounts {
                    fields: 1 << 28,
                    ..base
                },
            ),
            (
                "parts",
                ImageSizeCounts {
                    parts: 1 << 29,
                    ..base
                },
            ),
            (
                "edges",
                ImageSizeCounts {
                    edges: 1 << 29,
                    ..base
                },
            ),
            (
                "annotations",
                ImageSizeCounts {
                    annotations: 1 << 28,
                    ..base
                },
            ),
            (
                "aux",
                ImageSizeCounts {
                    aux: 1 << 29,
                    ..base
                },
            ),
            (
                "provenance",
                ImageSizeCounts {
                    provenance_bytes: 1 << 32,
                    ..base
                },
            ),
        ] {
            assert!(
                matches!(image_size_from_counts(&counts), Err(Error::TooLarge)),
                "{name} past 4 GiB must be refused"
            );
        }
    }

    #[test]
    fn estimate_accepts_the_largest_attainable_size() {
        assert_eq!(size_pad(0), 0);
        assert_eq!(size_pad(1), 7);
        assert_eq!(size_pad(4), 4);
        assert_eq!(size_pad(8), 0);
        assert_eq!(size_pad(9), 7);
        // Totals are always a multiple of 8 (every section is padded to
        // alignment), so the largest size that fits is `u32::MAX - 7` =
        // 4_294_967_288, and 8 bytes more is refused.
        let base = ImageSizeCounts {
            nodes: 2,
            edges: 1,
            ..ImageSizeCounts::default()
        };
        let fitting = ImageSizeCounts {
            children: 1_073_741_746,
            ..base
        };
        assert_eq!(image_size_from_counts(&fitting), Ok(4_294_967_288));
        let too_big = ImageSizeCounts {
            children: 1_073_741_748,
            ..base
        };
        assert!(
            matches!(image_size_from_counts(&too_big), Err(Error::TooLarge)),
            "8 bytes past the largest attainable size must be refused"
        );
    }
}
