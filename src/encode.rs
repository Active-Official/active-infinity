//! Encoder: canonical module → `AINF` bytes.
//!
//! The encoder is a pure function of the canonical prepared module, so
//! two logically equal modules always produce byte-identical images. Emission
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
    align8, dialect_hash, EncodeOpts, Header, Section, SectionSpan, ANN_KIND_AI_IMMUTABLE,
    ANN_KIND_CONSTRAINT, ANN_KIND_INTENT, AUX_CONSTRAINT_CUSTOM, AUX_CONSTRAINT_ENUM_ITEM,
    AUX_CONSTRAINT_MAX, AUX_CONSTRAINT_MIN, AUX_CONSTRAINT_PATTERN, AUX_PATCH_PATH,
    AUX_PATCH_RENAME_TO, AUX_PATCH_VALUE, AUX_SCHEMA_DEFAULT, AUX_SCHEMA_DEPRECATED,
    AUX_SCHEMA_MAX, AUX_SCHEMA_MAX_LEN, AUX_SCHEMA_MIN, AUX_SCHEMA_MIN_LEN, AUX_SCHEMA_PATTERN,
    AUX_TYPE_ENUM_ITEM, AUX_TYPE_TABLE, CONSTRAINT_KIND_CUSTOM, CONSTRAINT_KIND_ENUM,
    CONSTRAINT_KIND_MIN_MAX, CONSTRAINT_KIND_ODD, CONSTRAINT_KIND_PATTERN, EXT_DIR_SIZE,
    FLAG_ANNOTATIONS, FLAG_CANONICAL, FLAG_EXTENSIONS, FLAG_PROVENANCE, FLAG_SECRETS,
    FLAG_STREAMED, FORMAT_MAJOR, FORMAT_MINOR, HEADER_SIZE, NODE_FLAG_0, NODE_FLAG_1,
    NODE_RECORD_SIZE, PART_EXPR, PART_LITERAL, PATCH_KIND_REMOVE, PATCH_KIND_RENAME,
    PATCH_KIND_SET, PROV_HEADER_SIZE,
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
/// image; the bytes are identical to [`encode`].
pub fn encode_into(module: &InfinityModule, out: &mut Vec<u8>) -> Result<()> {
    encode_into_with(module, out, EncodeOpts::default())
}

/// Encode into an existing buffer with explicit options.
pub fn encode_into_with(
    module: &InfinityModule,
    out: &mut Vec<u8>,
    opts: EncodeOpts,
) -> Result<()> {
    let prepared = prepare(module)?;
    encode_prepared_into(&prepared, opts, out)
}

/// Encode a batch, reusing the capacity of every output buffer.
///
/// `out` is resized to the batch length; existing buffers keep their capacity.
/// This is the batch path a server uses to encode many modules per tick
/// without an allocation per image.
pub fn encode_many<'a, I>(modules: I, out: &mut Vec<Vec<u8>>) -> Result<()>
where
    I: IntoIterator<Item = &'a InfinityModule>,
{
    let modules: Vec<&InfinityModule> = modules.into_iter().collect();
    out.resize_with(modules.len(), Vec::new);
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
    if !prepared.secrets.is_empty() {
        header.flags |= FLAG_SECRETS;
    }

    let tables = build_node_tables(prepared)?;

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
    );
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
    );
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
    );
    for (tag, value) in &tables.parts {
        image.extend_from_slice(&tag.to_le_bytes());
        image.extend_from_slice(&value.to_le_bytes());
    }
    pad(image);

    // --- edges (derived) ----------------------------------------------
    let edges = derive_edges(prepared);
    set_span(&mut header, image.as_slice(), Section::Edges, edges.len());
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
            heap_len = heap_len
                .checked_add(string.len() as u32)
                .ok_or(Error::TooLarge)?;
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
        let len = blob.payload.as_ref().map(|p| p.len()).unwrap_or(0) as u32;
        image.extend_from_slice(&blob.hash);
        image.extend_from_slice(&blob_heap_len.to_le_bytes());
        image.extend_from_slice(&len.to_le_bytes());
        blob_heap_len = blob_heap_len.checked_add(len).ok_or(Error::TooLarge)?;
    }
    for blob in &prepared.blobs {
        if let Some(payload) = &blob.payload {
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
    );
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
    );
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
    );
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
    set_span(&mut header, image.as_slice(), Section::Aux, aux_count);
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
    );
    for value in &prepared.numbers {
        image.extend_from_slice(&value.to_le_bytes());
    }
    pad(image);

    // --- secrets -------------------------------------------------------
    header.span_mut(Section::Secrets).offset = image.len() as u32;
    header.span_mut(Section::Secrets).count = prepared.secrets.len() as u32;
    let mut secret_heap = 0u32;
    for secret in &prepared.secrets {
        image.extend_from_slice(&secret_heap.to_le_bytes());
        image.extend_from_slice(&(secret.len() as u32).to_le_bytes());
        secret_heap = secret_heap
            .checked_add(secret.len() as u32)
            .ok_or(Error::TooLarge)?;
    }
    for secret in &prepared.secrets {
        image.extend_from_slice(secret);
    }
    pad(image);

    // --- hashes --------------------------------------------------------
    set_span(
        &mut header,
        image.as_slice(),
        Section::Hashes,
        prepared.hashes.len(),
    );
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

    header.total_size = image.len() as u64;
    header.write(image);

    if opts.write_hash {
        let hash = hash_image(image.as_slice())?;
        image[16..48].copy_from_slice(&hash);
        let _ = hash;
    }
    Ok(())
}

fn set_span(header: &mut Header, image: &[u8], section: Section, count: usize) {
    header.span_mut(section).offset = image.len() as u32;
    header.span_mut(section).count = count as u32;
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
                secret_cursor += 1;
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
                let key = (*hash, *size, if *tainted { None } else { payload.clone() });
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
    let dir_size = EXT_DIR_SIZE * extensions.len();
    let mut payload_offset = start + dir_size;
    let mut directory = Vec::with_capacity(dir_size);
    for (tag, payload) in extensions {
        directory.extend_from_slice(&tag.to_le_bytes());
        directory.extend_from_slice(&(payload_offset as u32).to_le_bytes());
        directory.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        payload_offset = align8(payload_offset as u64 + payload.len() as u64) as usize;
    }
    image.extend_from_slice(&directory);
    for (_, payload) in extensions {
        image.extend_from_slice(payload);
        pad(image);
    }
    Ok(())
}
