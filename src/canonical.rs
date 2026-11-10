//! Canonicalization: the deterministic normal form of a module.
//!
//! Two modules that are logically equal must produce identical bytes and an
//! identical content hash, no matter how they were built. Canonicalization
//! therefore does all of the following, in one pass, before a single byte is
//! written:
//!
//! 1. drops nodes unreachable from the module roots (root, bindings,
//!    annotation subjects and their constraint expressions) — an image can
//!    never hide data in an unreferenced node. `prepare` itself still drops
//!    them; the fail-closed rule lives at the `encode` boundary, which
//!    refuses an unreachable node unless `EncodeOpts::drop_unreachable` is
//!    set (stream deltas, merge — INF-04);
//! 2. numbers nodes in pre-order from the roots, visiting table fields in
//!    key order, so arena construction order is irrelevant;
//! 3. sorts table fields, strings, units, types, blobs, hashes, numbers,
//!    annotations, provenance entries, extension blocks and edges;
//! 4. normalizes floats (`-0.0` → `+0.0`, NaN → one quiet NaN);
//! 5. deduplicates strings, units, types, blobs, hashes, numbers and edges.
//!
//! Secret literals are ordered by node order and never deduplicated: two
//! identical secrets still occupy two table entries so that table length and
//! layout cannot become an equality oracle.

// Module-level: item docs for this layer live in docs/spec/layout.md and
// docs/spec/streaming.md; the crate root keeps deny(missing_docs) for the
// hand-written public surface.
#![allow(missing_docs)]

use std::collections::{HashMap, HashSet};

use crate::error::{Error, Result};
use crate::ir::{
    Annotation, AnnotationKind, Constraint, InfinityModule, Inode, InterpPart, NodeId, PatchOp,
    ProvValue, Provenance, SchemaFieldSpec, TypeSpec,
};
use crate::layout::{canonical_f64, Limits};
use crate::unit::UnitTag;

/// Deduplication key for a type table entry: code plus its aux payload.
pub(crate) type TypeKey = (u32, Vec<(u32, u32)>);

/// Deduplication key for a blob entry: identity plus payload presence.
///
/// The key is `(hash, size, has_payload)` — the payload bytes themselves
/// are never part of the key (INF-11). A materialised payload must
/// Blake3-hash to its entry hash (checked in `prepare`), so two payloads
/// under one key are byte-equal up to a Blake3 collision — exactly the
/// same collision assumption the format already makes for content
/// addressing. The bytes are still compared on a key hit in `prepare`
/// (memcmp, no clone); a mismatch that still hashes to the key is a
/// genuine Blake3 collision, and encode refuses rather than silently
/// addressing two payloads by one key.
pub(crate) type BlobKey = ([u8; 32], u64, bool);

/// A blob payload prepared for the content-addressed heap.
///
/// The payload bytes are NOT stored here (INF-11): they live in the
/// `Prepared::nodes` entry named by `source`, and this struct borrows
/// them by index instead of cloning them. A module with N `Blob` nodes
/// sharing one payload used to pay N full payload clones into this
/// table (plus one more per node for the `blob_index` key and one more
/// per node in `encode.rs`); now the table holds one small record per
/// distinct blob and the bytes are written to the heap straight from
/// the representative node.
#[derive(Debug, Clone, Eq)]
pub(crate) struct BlobPayload {
    pub hash: [u8; 32],
    pub size: u64,
    /// True when a materialised, non-empty payload exists for this entry.
    /// An empty payload and a detached blob both map to `false`: they
    /// encode to the same `(hash, offset, 0)` record, and keying them
    /// apart would emit two duplicate records the validator refuses.
    pub has_payload: bool,
    /// Length of the materialised payload; 0 when `has_payload` is false.
    /// Always equal to `size` when `has_payload` is true (`prepare`
    /// verifies the length); kept as its own field so the heap writer
    /// and the size estimate do not have to re-derive it from the
    /// presence bit.
    pub payload_len: u64,
    /// Index into `Prepared::nodes` of the first node carrying this
    /// entry's payload; `None` when `has_payload` is false. The index
    /// is a prepare-internal representative choice, not canonical
    /// content — it is deliberately excluded from `PartialEq`.
    pub source: Option<usize>,
}

impl BlobPayload {
    /// The payload bytes for this entry, borrowed from the prepared
    /// nodes through `source`. `None` when the entry carries no bytes
    /// — or when the index does not resolve, which cannot happen for
    /// entries `prepare` built (the index comes from the same `nodes`
    /// vec, which is never reordered after the blob pass) but is
    /// reported as "no payload" rather than panicking.
    pub(crate) fn payload_in<'a>(&self, nodes: &'a [Inode]) -> Option<&'a [u8]> {
        let index = self.source?;
        match nodes.get(index)? {
            Inode::Blob { payload, .. } => payload.as_deref(),
            _ => None,
        }
    }
}

impl PartialEq for BlobPayload {
    /// Canonical comparison only: hash, size, presence, length. The
    /// `source` index is excluded — two prepared modules built from
    /// the same logical module in different arena order choose
    /// different representatives for the same payload. Payload *bytes*
    /// are still compared, through `Prepared::nodes` via `node_eq`
    /// (`prepared_eq` in `ir.rs`), and both payloads were verified to
    /// hash to `hash` in `prepare`, so this is as strong as comparing
    /// the bytes here up to the Blake3 assumption the format already
    /// makes.
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && self.size == other.size
            && self.has_payload == other.has_payload
            && self.payload_len == other.payload_len
    }
}

/// One prepared type-table entry with its aux payload (enum members).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PreparedType {
    pub spec: TypeSpec,
    pub aux: Vec<(u32, u32)>,
}

/// Fully canonical, index-resolved module ready for byte emission.
///
/// Deliberately no `Debug`: the struct holds secret bytes and blob payloads, and
/// a derived impl would print them. Deliberately no `Clone` either (INF-08):
/// cloning a prepared module would duplicate every secret it holds, so a
/// caller that needs a second copy prepares again from the module.
#[derive(Default)]
pub(crate) struct Prepared {
    pub nodes: Vec<Inode>,
    pub root: Option<NodeId>,
    pub bindings: Vec<(String, NodeId)>,
    pub annotations: Vec<Annotation>,
    pub provenance: Option<Provenance>,
    pub strings: Vec<String>,
    pub units: Vec<UnitTag>,
    pub types: Vec<PreparedType>,
    pub blobs: Vec<BlobPayload>,
    pub hashes: Vec<[u8; 32]>,
    pub numbers: Vec<i64>,
    pub extensions: Vec<(u64, Vec<u8>)>,
    pub string_index: HashMap<String, u32>,
    pub unit_index: HashMap<UnitTag, u32>,
    pub type_index: HashMap<TypeKey, u32>,
    pub blob_index: HashMap<BlobKey, u32>,
    pub hash_index: HashMap<[u8; 32], u32>,
    pub number_index: HashMap<i64, u32>,
}

impl Prepared {
    /// Secret bytes in node order, borrowed from [`Self::nodes`] (INF-08).
    ///
    /// There is no separate secrets table: the bytes live only in the
    /// `Inode::Secret` values, and the encoder and the size estimate read
    /// them here. An earlier form of this struct kept a second transcription
    /// (`secrets: Vec<Vec<u8>>`, built by `secret.expose().to_vec()` in
    /// `prepare()` and zeroized in `Drop`); it was removed because the nodes
    /// already carry the bytes in exactly the order the secret heap needs
    /// (node order, never deduplicated), so the copy bought nothing and
    /// doubled the live copies during every encode.
    pub(crate) fn secret_bytes(&self) -> impl Iterator<Item = &[u8]> + '_ {
        secret_slices(&self.nodes)
    }

    /// Number of secret nodes, i.e. the secret-heap entry count.
    pub(crate) fn secret_count(&self) -> usize {
        self.secret_bytes().count()
    }
}

/// Borrowed secret bytes of `nodes`, in node order (INF-08).
fn secret_slices(nodes: &[Inode]) -> impl Iterator<Item = &[u8]> + '_ {
    nodes.iter().filter_map(|node| match node {
        Inode::Secret(secret) => Some(secret.expose()),
        _ => None,
    })
}

/// True when `value` is the one NaN bit pattern the format permits.
pub(crate) fn is_canonical_nan(value: f64) -> bool {
    value.to_bits() == crate::layout::CANONICAL_NAN_BITS
}

/// Canonicalize `module` into an index-resolved [`Prepared`] module.
pub(crate) fn prepare(module: &InfinityModule) -> Result<Prepared> {
    // The depth ceiling is the decoder's default ceiling (INF-09): a `0`
    // here used to mean "no ceiling", so encode accepted modules deeper
    // than `Limits::default().max_depth` that the default decoder then
    // refused. Encode now refuses them first, with `infinity/depth`.
    module.validate_structure(u32::MAX as u64, Limits::default().max_depth)?;

    // 1. Normalize node contents in place (field order, float bits).
    let canonical_nodes: Vec<Inode> = module.nodes().iter().map(normalize).collect();

    // Secret material that must not survive inside free text metadata. Read it
    // *before* promotion, and take whole secrets only: an interpolated locator
    // contributes fragments (`"S"`, `"hunter-"`), and rewriting every occurrence
    // of such a fragment in prose would destroy the annotation. A fragment that
    // is a substring of `***SECRET***` would refuse the module outright. The
    // fragments stay in the export redaction set (`interop::secret_texts`), so
    // no projection or text export publishes them.
    let secret_literals = storage_secret_texts(&canonical_nodes);

    // 1b. Promote secret locators out of the public string heap.
    //
    // `active-core` models `secret("literal")` as a `Secret { locator }` node
    // whose locator is an ordinary string literal. Left alone, that literal
    // would land in the string heap and a naive `strings module.ainf` would
    // read it back. Every literal a secret locator reaches — a plain string, an
    // interpolated part, or either one inside an expression such as
    // `secret(pw + "-suffix")` — is re-encoded as a structural secret (or a
    // `Secret` reference from an interpolation): the bytes move to the secret
    // heap, which no projection enumerates.
    let (mut canonical_nodes, fragments) = promote_secret_locators(canonical_nodes, module);
    // A promoted fragment is not a stored-metadata redaction target: rewriting
    // every occurrence of a one-byte fragment would destroy the prose. It must
    // therefore not occur in the metadata at all. If it did, the image would not
    // be a fixed point: a decoded fragment is an ordinary secret on the next
    // pass, so `encode(decode(image))` would differ (or refuse). Fail loud.
    // The fragment check runs after the metadata redaction below, on the text
    // that is actually stored: inserting the marker can create a fragment at a
    // boundary, and a fragment inside the marker would otherwise slip through.

    // One cumulative redaction budget for the whole metadata block: a
    // per-string ceiling multiplies by the number of annotations and entries.
    let redaction = std::cell::Cell::new(MAX_REDACTION_SCAN_BYTES);

    // A deprecation note is stored prose, exactly like an annotation. Redact it
    // **before** the node order is derived: `content_key` renders the note when a
    // schema field is an annotation subject, so ordering by the unredacted text
    // and storing the redacted one makes the image a different fixed point (two
    // subjects can swap places). It must also run before the string heap is
    // collected, because `Inode::strings` interns the note.
    for node in &mut canonical_nodes {
        if let Inode::SchemaField(spec) = node {
            if let Some(text) = &mut spec.deprecated {
                *text = try_redact_text_with(text, &secret_literals, &redaction)?;
            }
        }
    }

    // 1c. Redact the annotation prose **before** the order is derived: the
    // tie-break reads it to tell two subjects that render identically apart, and
    // ordering by the raw text while storing the redacted one would make the
    // image a different fixed point (the same rule as the deprecation note
    // above).
    let redacted_annotations: Vec<Annotation> = module
        .annotations()
        .iter()
        .map(|annotation| {
            let kind: Result<AnnotationKind> =
                match &annotation.kind {
                    AnnotationKind::Intent(text) => Ok(AnnotationKind::Intent(
                        try_redact_text_with(text, &secret_literals, &redaction)?,
                    )),
                    AnnotationKind::Constraint { source, expr } => Ok(AnnotationKind::Constraint {
                        source: try_redact_text_with(source, &secret_literals, &redaction)?,
                        expr: *expr,
                    }),
                    AnnotationKind::AiImmutable(flag) => Ok(AnnotationKind::AiImmutable(*flag)),
                };
            Ok(Annotation {
                node: annotation.node,
                kind: kind?,
            })
        })
        .collect::<Result<Vec<Annotation>>>()?;

    // 2. Pre-order numbering from the roots.
    let order = canonical_order(&canonical_nodes, module, &redacted_annotations)?;
    let mut remap = vec![NodeId::NONE; canonical_nodes.len()];
    for (new_index, old) in order.iter().enumerate() {
        remap[old.index()] = NodeId(new_index as u32);
    }

    // 3. Rebuild nodes in canonical order with remapped references.
    //
    // The canonical nodes are consumed rather than cloned: an owned slot vector
    // lets each node move into its final position and have its references
    // rewritten in place. For a 10k-field table this removes one full clone of
    // every field name (see `docs/spec/performance.md`, batch encode).
    let mut slots: Vec<Option<Inode>> = canonical_nodes.into_iter().map(Some).collect();
    let mut nodes: Vec<Inode> = Vec::with_capacity(slots.len());
    for old in &order {
        let mut node = slots[old.index()]
            .take()
            .ok_or(Error::EncodeDangling(old.0))?;
        remap_node_in_place(&mut node, &remap)?;
        nodes.push(node);
    }

    let root = module.root().map(|id| remap[id.index()]);
    let mut bindings: Vec<(String, NodeId)> = module
        .bindings()
        .iter()
        .map(|(name, id)| (name.clone(), remap[id.index()]))
        .collect();
    bindings.sort_by(|a, b| a.0.cmp(&b.0));

    // One cumulative redaction budget for the whole metadata block: a
    // per-string ceiling multiplies by the number of annotations and entries.
    let annotations: Vec<Annotation> = redacted_annotations
        .iter()
        .map(|annotation| {
            let node = remap[annotation.node.index()];
            let kind = match &annotation.kind {
                AnnotationKind::Intent(text) => AnnotationKind::Intent(text.clone()),
                AnnotationKind::Constraint { source, expr } => AnnotationKind::Constraint {
                    source: source.clone(),
                    expr: remap[expr.index()],
                },
                AnnotationKind::AiImmutable(flag) => AnnotationKind::AiImmutable(*flag),
            };
            Annotation { node, kind }
        })
        .collect();

    // 4. Collect and sort every symbol table.
    let mut strings = Vec::new();
    for node in &nodes {
        node.strings(&mut strings);
    }
    // Named (custom) units carry their name in the string heap.
    for node in &nodes {
        if let Inode::Quantity {
            unit: UnitTag::Named(name),
            ..
        } = node
        {
            strings.push(name.clone());
        }
    }
    for (name, _) in &bindings {
        strings.push(name.clone());
    }
    for annotation in &annotations {
        match &annotation.kind {
            AnnotationKind::Intent(text) => strings.push(text.clone()),
            AnnotationKind::Constraint { source, .. } => strings.push(source.clone()),
            AnnotationKind::AiImmutable(_) => {}
        }
    }
    let provenance = module
        .provenance()
        .cloned()
        .map(|prov| redact_provenance(prov, &secret_literals, &redaction))
        .transpose()?;
    if !fragments.is_empty() {
        reject_fragments_in_annotations(&annotations, &fragments)?;
        reject_fragments_in_provenance(provenance.as_ref(), &fragments)?;
        reject_fragments_in_labels(&nodes, &bindings, &annotations, &fragments)?;
    }
    if let Some(prov) = &provenance {
        if let Some(producer) = &prov.producer {
            strings.push(producer.clone());
        }
        if let Some(model) = &prov.model {
            strings.push(model.clone());
        }
        if let Some(tool) = &prov.tool {
            strings.push(tool.clone());
        }
        for entry in &prov.entries {
            strings.push(entry.key.clone());
            if let ProvValue::Text(text) = &entry.value {
                strings.push(text.clone());
            }
        }
    }
    strings.sort();
    strings.dedup();
    let string_index: HashMap<String, u32> = strings
        .iter()
        .enumerate()
        .map(|(index, value)| (value.clone(), index as u32))
        .collect();

    let mut units: Vec<UnitTag> = Vec::new();
    for node in &nodes {
        if let Inode::Quantity { unit, .. } = node {
            units.push(unit.clone());
        }
    }
    units.sort_by(|a, b| (a.discriminant(), a.name()).cmp(&(b.discriminant(), b.name())));
    units.dedup();
    let unit_index: HashMap<UnitTag, u32> = units
        .iter()
        .enumerate()
        .map(|(index, unit)| (unit.clone(), index as u32))
        .collect();

    // Types are deduplicated by (discriminant, enum members) and sorted.
    let mut type_payloads: Vec<(u32, Vec<(u32, u32)>)> = Vec::new();
    for node in &nodes {
        if let Inode::SchemaField(spec) = node {
            type_payloads.push(type_payload(spec, &string_index)?);
        }
    }
    type_payloads.sort();
    type_payloads.dedup();
    let mut types = Vec::with_capacity(type_payloads.len());
    let mut type_index = HashMap::new();
    for (index, (code, aux)) in type_payloads.iter().enumerate() {
        // The prepared payload came from this module, so a miss here is an
        // encoder fault (a dangling reference), not a reader's string-ref fault.
        let spec = type_from_prepared(*code, aux, &strings)
            .map_err(|_| Error::Encode("schema type references an uninterned string"))?;
        types.push(PreparedType {
            spec,
            aux: aux.clone(),
        });
        type_index.insert((*code, aux.clone()), index as u32);
    }

    // Blobs: deduplicate by (hash, size, payload presence), ordered by hash then size.
    //
    // The payload bytes are never cloned here (INF-11). Each distinct
    // payload is verified once — the first occurrence runs the Blake3
    // check, later occurrences are memcmp'd against the representative's
    // bytes (no clone, no second hash) — and the table holds one small
    // record per distinct blob, borrowing its bytes from the first node
    // that carries them (`BlobPayload::source`, an index into `nodes`).
    // `blob_seen` is the dedup: `blobs` is already duplicate-free when
    // the loop ends, so there is no `dedup()` pass; the stable sort by
    // (hash, size) then orders first occurrences exactly as the old
    // sort-plus-dedup ordered the survivors. `nodes` is not reordered
    // after this point, so the `source` indices stay valid in `Prepared`.
    let mut blobs: Vec<BlobPayload> = Vec::new();
    let mut blob_seen: HashMap<BlobKey, usize> = HashMap::new();
    for (node_index, node) in nodes.iter().enumerate() {
        if let Inode::Blob {
            hash,
            size,
            tainted,
            payload,
            ..
        } = node
        {
            if *tainted && payload.is_some() {
                return Err(Error::Encode("a tainted blob must not carry a payload"));
            }
            // An empty payload and a detached blob encode to the same
            // (hash, offset, 0) record; keying them apart would emit two
            // duplicate records the validator refuses.
            let has_payload = !*tainted && payload.as_ref().is_some_and(|bytes| !bytes.is_empty());
            if let Some(bytes) = payload {
                // The image is validated on the way in, so an inconsistent blob
                // has to fail here: emitting it would produce bytes the crate
                // refuses to read back.
                if bytes.len() as u64 != *size {
                    return Err(Error::Encode("blob payload length disagrees with size"));
                }
                if !has_payload {
                    // Empty payload: hashing zero bytes is O(1), and the
                    // validator holds a flagged empty node to blake3("")
                    // (its node arm checks `size == 0` against the empty
                    // hash), so every empty node is verified individually,
                    // exactly as before. A detached node carries no bytes
                    // and needs no check: it may declare any hash.
                    if blake3::hash(bytes).as_bytes() != hash {
                        return Err(Error::Encode("blob payload hash mismatch"));
                    }
                }
            }
            let key: BlobKey = (*hash, *size, has_payload);
            if let Some(&representative) = blob_seen.get(&key) {
                if has_payload {
                    // A later node for the same key: the payloads must be
                    // byte-equal (both hash to `hash`, verified below on
                    // mismatch). Compare, don't clone and don't re-hash.
                    let representative_bytes = match &nodes[representative] {
                        Inode::Blob {
                            payload: Some(bytes),
                            ..
                        } => bytes,
                        _ => {
                            return Err(Error::Encode(
                                "blob representative missing from prepared module",
                            ));
                        }
                    };
                    let bytes = payload
                        .as_ref()
                        .expect("has_payload implies a payload is present");
                    if bytes.as_slice() != representative_bytes.as_slice() {
                        // The bytes differ, so at most one of them hashes
                        // to `hash`. Re-hash this one: a mismatch is the
                        // same refusal as before; a match means two
                        // distinct payloads share a Blake3 hash and size,
                        // and one key cannot address both — refuse
                        // (fail closed) instead of silently aliasing
                        // them.
                        if blake3::hash(bytes).as_bytes() != hash {
                            return Err(Error::Encode("blob payload hash mismatch"));
                        }
                        return Err(Error::Encode(
                            "blob payload hash collision: two distinct payloads share a hash and size",
                        ));
                    }
                }
                continue;
            }
            if has_payload {
                // First occurrence of this key: verify the payload
                // hashes to its entry hash (the one Blake3 per distinct
                // payload; later nodes with the same key are memcmp'd
                // against this representative instead).
                let bytes = payload
                    .as_ref()
                    .expect("has_payload implies a payload is present");
                if blake3::hash(bytes).as_bytes() != hash {
                    return Err(Error::Encode("blob payload hash mismatch"));
                }
            }
            blob_seen.insert(key, node_index);
            blobs.push(BlobPayload {
                hash: *hash,
                size: *size,
                has_payload,
                payload_len: if has_payload {
                    payload
                        .as_ref()
                        .expect("has_payload implies a payload is present")
                        .len() as u64
                } else {
                    0
                },
                source: if has_payload { Some(node_index) } else { None },
            });
        }
    }
    blobs.sort_by_key(|blob| (blob.hash, blob.size));
    let blob_index: HashMap<BlobKey, u32> = blobs
        .iter()
        .enumerate()
        .map(|(index, blob)| ((blob.hash, blob.size, blob.has_payload), index as u32))
        .collect();

    // Hashes: provenance hash values.
    let mut hashes: Vec<[u8; 32]> = Vec::new();
    if let Some(prov) = &provenance {
        if let Some(parent) = prov.parent {
            hashes.push(parent);
        }
        for entry in &prov.entries {
            if let ProvValue::Hash(hash) = &entry.value {
                hashes.push(*hash);
            }
        }
    }
    hashes.sort();
    hashes.dedup();
    let hash_index: HashMap<[u8; 32], u32> = hashes
        .iter()
        .enumerate()
        .map(|(index, hash)| (*hash, index as u32))
        .collect();

    // Numbers: constraint bounds and integer provenance values.
    let mut numbers: Vec<i64> = Vec::new();
    for node in &nodes {
        if let Inode::Constrained {
            constraint: Constraint::MinMax { min, max },
            ..
        } = node
        {
            numbers.extend(min.iter().copied());
            numbers.extend(max.iter().copied());
        }
    }
    if let Some(prov) = &provenance {
        for entry in &prov.entries {
            if let ProvValue::Int(value) = &entry.value {
                numbers.push(*value);
            }
        }
    }
    numbers.sort_unstable();
    numbers.dedup();
    let number_index: HashMap<i64, u32> = numbers
        .iter()
        .enumerate()
        .map(|(index, value)| (*value, index as u32))
        .collect();

    // Secrets are read from the nodes, never copied (INF-08): the borrowed
    // slices below are all `reject_secret_copies` needs, and the encoder
    // reads the same bytes through `Prepared::secret_bytes()`.
    let secret_refs: Vec<&[u8]> = secret_slices(&nodes).collect();

    // Extensions: sorted by tag, unique tags, payloads preserved verbatim.
    let mut extensions: Vec<(u64, Vec<u8>)> = module.extensions().to_vec();
    extensions.sort_by_key(|(tag, _)| *tag);
    for window in extensions.windows(2) {
        if window[0].0 == window[1].0 {
            return Err(Error::Encode("duplicate extension tag"));
        }
    }

    // A secret copied into a binary surface cannot be redacted: there is no
    // marker that fits a 32-byte hash and no way to rewrite an opaque payload
    // without corrupting it. Refuse the encode instead of storing the copy.
    reject_secret_copies(
        module,
        &nodes,
        provenance.as_ref(),
        &extensions,
        &blobs,
        &secret_refs,
    )?;

    let prepared = Prepared {
        nodes,
        root,
        bindings,
        annotations: sorted_annotations(annotations, &string_index),
        provenance: provenance.map(sorted_provenance).transpose()?,
        strings,
        units,
        types,
        blobs,
        hashes,
        numbers,
        extensions,
        string_index,
        unit_index,
        type_index,
        blob_index,
        hash_index,
        number_index,
    };
    Ok(prepared)
}

fn normalize(node: &Inode) -> Inode {
    match node {
        Inode::Float(value) => Inode::Float(canonical_f64(*value)),
        Inode::Table { fields } => {
            let mut fields = fields.clone();
            fields.sort_by(|a, b| a.0.cmp(&b.0));
            Inode::Table { fields }
        }
        Inode::SchemaTable { fields, closed } => {
            let mut fields = fields.clone();
            fields.sort_by(|a, b| a.0.cmp(&b.0));
            Inode::SchemaTable {
                fields,
                closed: *closed,
            }
        }
        Inode::SchemaField(spec) => Inode::SchemaField(SchemaFieldSpec {
            typ: normalize_type(&spec.typ),
            ..spec.clone()
        }),
        Inode::Constrained {
            target,
            constraint: Constraint::Enum(items),
        } => {
            let mut items = items.clone();
            items.sort();
            Inode::Constrained {
                target: *target,
                constraint: Constraint::Enum(items),
            }
        }
        other => other.clone(),
    }
}

/// Marker substituted for secret material in every projection and in metadata
/// that is copied verbatim into exports.
pub const SECRET_MARKER: &str = "***SECRET***";

/// Replace secret material inside free text (annotations, provenance, model
/// names).
///
/// Every non-empty secret is replaced wherever it appears, at any length: a copy
/// that survives canonicalization is stored in the image, and the projections
/// would then have to hide bytes the image itself carries.
///
/// One rule keeps the result a fixpoint: when any secret also occurs inside
/// [`SECRET_MARKER`] (`S`, `*`, `SECRET`), inserting the marker would reintroduce
/// that secret, and a second canonicalization pass would then change the text
/// again. In that case the whole text collapses to the marker, which is the one
/// value the rule maps to itself.
/// Redact free text for an image, refusing the one case the marker cannot
/// represent.
///
/// When a secret is a substring of [`SECRET_MARKER`], inserting the marker would
/// publish that secret as part of the text the image stores. There is no safe
/// substitution, so the encode fails instead of writing it.
/// [`try_redact_text`] drawing on one cumulative budget.
///
/// The per-call ceiling alone lets N metadata strings multiply it; `prepare`
/// shares one budget across annotations and provenance.
pub(crate) fn try_redact_text_with(
    text: &str,
    secrets: &[String],
    budget: &std::cell::Cell<usize>,
) -> Result<String> {
    // Every pass scans each secret once; a module with a million secrets and a
    // megabyte of prose would otherwise spend hours inside the encoder. The
    // estimate is charged before the first scan.
    let cost = redaction_cost(text, secrets);
    let remaining = budget.get();
    if cost > remaining {
        return Err(Error::Limit {
            kind: "redaction scan bytes",
            limit: MAX_REDACTION_SCAN_BYTES as u64,
        });
    }
    budget.set(remaining - cost);
    let marker_tainted = secrets
        .iter()
        .any(|secret| !secret.is_empty() && SECRET_MARKER.contains(secret.as_str()));
    if marker_tainted
        && secrets
            .iter()
            .any(|secret| !secret.is_empty() && text.contains(secret.as_str()))
    {
        return Err(Error::Encode("a secret occurs inside the redaction marker"));
    }
    Ok(redact_text(text, secrets))
}

/// Largest `secrets x text x passes` product one redaction may scan.
pub(crate) const MAX_REDACTION_SCAN_BYTES: usize = 64 << 20;

/// Upper bound on the comparisons one redaction performs.
///
/// The length is floored at one: an empty string still costs one `contains` per
/// secret per pass, and charging zero let a module with many empty annotations
/// and a large secret table spend unbounded CPU for free.
pub(crate) fn redaction_cost(text: &str, secrets: &[String]) -> usize {
    const PASSES: usize = 8;
    secrets
        .len()
        .saturating_mul(text.len().max(1))
        .saturating_mul(PASSES)
}

pub(crate) fn redact_text(text: &str, secrets: &[String]) -> String {
    // The infallible form is used by projections: when the scan would be
    // unbounded, redact the whole value instead of scanning it.
    let marker_tainted = secrets
        .iter()
        .any(|secret| !secret.is_empty() && SECRET_MARKER.contains(secret.as_str()));
    if redaction_cost(text, secrets) > MAX_REDACTION_SCAN_BYTES {
        // Over budget, the whole value collapses to the placeholder. When the
        // marker itself contains a secret, that placeholder is the empty string.
        return if marker_tainted {
            String::new()
        } else {
            SECRET_MARKER.to_string()
        };
    }
    // The intermediate buffer holds the text *before* every replacement, which
    // is exactly where a secret still sits: each pass allocates a new string and
    // drops the old one, so wrap it and let `Zeroizing` overwrite the freed
    // block instead of leaving it for the next allocation.
    let mut out = zeroize::Zeroizing::new(text.to_string());
    // A replacement can create a new secret by joining the text around it
    // (`hid` + `***SECRET***` + `den` is a secret again), so a pass repeats
    // until the text is clean. Every pass either removes an occurrence, collapses
    // to the marker, or is bounded by the loop; the final fallback is the marker,
    // which no rule can make dirty again when the marker itself is clean.
    for _ in 0..8 {
        let mut matched: Vec<&String> = secrets
            .iter()
            .filter(|secret| !secret.is_empty() && out.contains(secret.as_str()))
            .collect();
        if matched.is_empty() {
            return out.to_string();
        }
        if marker_tainted {
            // The marker itself contains a secret, so inserting it would publish
            // that secret. The only replacement that never contains one is the
            // empty string; the fallible encoder path refuses instead.
            return String::new();
        }
        // Longest first, then lexicographic: the result does not depend on the
        // order of the secret table.
        matched.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        for secret in matched {
            out = zeroize::Zeroizing::new(out.replace(secret.as_str(), SECRET_MARKER));
        }
    }
    SECRET_MARKER.to_string()
}

fn redact_provenance(
    mut prov: Provenance,
    secrets: &[String],
    budget: &std::cell::Cell<usize>,
) -> Result<Provenance> {
    // The validator refuses an empty producer; the encoder must not emit one.
    if prov.producer.as_deref() == Some("") {
        return Err(Error::Encode("empty provenance producer"));
    }
    if secrets.is_empty() {
        return Ok(prov);
    }
    prov.producer = prov
        .producer
        .map(|text| try_redact_text_with(&text, secrets, budget))
        .transpose()?;
    prov.model = prov
        .model
        .map(|text| try_redact_text_with(&text, secrets, budget))
        .transpose()?;
    prov.tool = prov
        .tool
        .map(|text| try_redact_text_with(&text, secrets, budget))
        .transpose()?;
    for entry in &mut prov.entries {
        // Keys live in the string heap too: a copy there would be stored in the
        // image even though the projections hide it.
        entry.key = try_redact_text_with(&entry.key, secrets, budget)?;
        if let ProvValue::Text(text) = &entry.value {
            entry.value = ProvValue::Text(try_redact_text_with(text, secrets, budget)?);
        }
    }
    Ok(prov)
}

/// Largest amount of extension-payload scanning one encode may do, in bytes
/// compared. A producer with many secrets and many large payloads is refused
/// rather than allowed to turn the encode into a quadratic job.
pub(crate) const MAX_SECRET_SCAN_BYTES: usize = 64 << 20;

/// Refuse a provenance hash or extension payload that carries a secret literal.
///
/// Provenance text is redacted by [`redact_provenance`]; a hash value and an
/// opaque extension are binary, so redaction cannot apply. The encoder refuses
/// them, which keeps the invariant "a secret is not published" true for the
/// stored image as well as for every projection.
fn reject_secret_copies(
    module: &InfinityModule,
    nodes: &[Inode],
    provenance: Option<&Provenance>,
    extensions: &[(u64, Vec<u8>)],
    blobs: &[BlobPayload],
    secrets: &[&[u8]],
) -> Result<()> {
    if secrets.is_empty() {
        return Ok(());
    }
    let hash_secrets: std::collections::BTreeSet<&[u8]> = secrets
        .iter()
        .filter(|secret| secret.len() == 32)
        .copied()
        .collect();
    // A blob hash is published verbatim by every projection. A hash that
    // copies a 32-byte secret would publish it there, exactly like a
    // provenance hash, so it is refused at the source.
    for node in module.nodes() {
        if let Inode::Blob { hash, .. } = node {
            if hash_secrets.contains(hash.as_slice()) {
                return Err(Error::Encode("blob hash equals a secret"));
            }
        }
    }
    if let Some(provenance) = provenance {
        if let Some(parent) = provenance.parent {
            if hash_secrets.contains(parent.as_slice()) {
                return Err(Error::Encode("provenance parent equals a secret"));
            }
        }
        for entry in &provenance.entries {
            if let ProvValue::Hash(hash) = &entry.value {
                if hash_secrets.contains(hash.as_slice()) {
                    return Err(Error::Encode("provenance hash equals a secret"));
                }
            }
        }
    }
    let mut work = 0usize;
    // An extension is opaque bytes; a materialised blob payload is the same kind
    // of surface (a tainted blob stores no payload, so it is skipped). The
    // diagnostic names the surface the caller can act on.
    for (_, payload) in extensions {
        scan_payload(
            payload,
            secrets,
            &mut work,
            "extension payload carries a secret literal",
        )?;
    }
    // The scan runs over the deduplicated table, not over the nodes:
    // a payload shared by N nodes is scanned once, so the charge
    // (`MAX_SECRET_SCAN_BYTES`) is per distinct payload, as before.
    // A `has_payload` entry whose bytes do not resolve is an encoder
    // fault, not a scan to skip: skipping it would publish a payload
    // that was never checked for secret copies.
    for blob in blobs {
        if blob.has_payload {
            let payload = blob
                .payload_in(nodes)
                .ok_or(Error::Encode("blob payload missing from prepared module"))?;
            scan_payload(
                payload,
                secrets,
                &mut work,
                "blob payload carries a secret literal",
            )?;
        }
    }
    Ok(())
}

/// One opaque payload against every secret, charged by bytes compared.
fn scan_payload(
    payload: &[u8],
    secrets: &[&[u8]],
    work: &mut usize,
    reason: &'static str,
) -> Result<()> {
    for &secret in secrets {
        if secret.is_empty() || secret.len() > payload.len() {
            continue;
        }
        // One pass costs the payload length (first-byte filter), plus a full
        // compare at each candidate position. Charging both is the real work: a
        // worst-case `windows()` sweep is m times this, and charging only the
        // pass let a 64 KiB prefix-matching secret burn 61 GB of comparisons.
        *work = work.saturating_add(payload.len());
        if *work > MAX_SECRET_SCAN_BYTES {
            return Err(Error::Limit {
                kind: "secret copy scan bytes",
                limit: MAX_SECRET_SCAN_BYTES as u64,
            });
        }
        let first = secret[0];
        let mut at = 0usize;
        while at + secret.len() <= payload.len() {
            if payload[at] == first {
                *work = work.saturating_add(secret.len());
                if *work > MAX_SECRET_SCAN_BYTES {
                    return Err(Error::Limit {
                        kind: "secret copy scan bytes",
                        limit: MAX_SECRET_SCAN_BYTES as u64,
                    });
                }
                if &payload[at..at + secret.len()] == secret {
                    return Err(Error::Encode(reason));
                }
            }
            at += 1;
        }
    }
    Ok(())
}

fn normalize_type(typ: &TypeSpec) -> TypeSpec {
    match typ {
        // An enum is a set: sort once here so every later pass (the annotation
        // key, the type table) sees one order.
        TypeSpec::Enum(members) => {
            let mut members = members.clone();
            members.sort();
            TypeSpec::Enum(members)
        }
        other => other.clone(),
    }
}

/// Whole secrets that stored metadata prose is redacted against.
///
/// A `Secret` node's bytes, plus a `SecretRef` whose locator resolves to one
/// `Str`/`Ident`. An interpolated locator contributes fragments of the secret
/// expression; those are hidden from the string heap by promotion and from
/// every export by `interop`, but they are not stored-metadata redaction
/// targets: a one-byte fragment would rewrite any prose that contains that
/// byte, and a fragment inside `***SECRET***` would refuse the module.
fn storage_secret_texts(nodes: &[Inode]) -> Vec<String> {
    let count = nodes.len();
    let mut out: Vec<String> = nodes
        .iter()
        .filter_map(|node| match node {
            Inode::Secret(secret) => Some(String::from_utf8_lossy(secret.expose()).into_owned()),
            _ => None,
        })
        .collect();
    // Mirror promotion exactly: every `Str`/`Ident` in locator material is
    // secret material, including one inside an expression. `InterpPart::Literal`
    // is excluded here (it is handled by the fragment refusal), because a
    // fragment must not rewrite prose. One visited set keeps this linear; the
    // previous per-ref `resolve_locator` missed expression literals and was
    // quadratic in a long chain.
    let mut visited = vec![false; count];
    let mut stack: Vec<NodeId> = nodes
        .iter()
        .filter_map(|node| match node {
            Inode::SecretRef { locator } => Some(*locator),
            _ => None,
        })
        .collect();
    while let Some(id) = stack.pop() {
        if id.index() >= count || visited[id.index()] {
            continue;
        }
        visited[id.index()] = true;
        match &nodes[id.index()] {
            Inode::Str(text) | Inode::Ident(text) => out.push(text.clone()),
            _ => {}
        }
        stack.extend(nodes[id.index()].children());
    }
    out.sort();
    out.dedup();
    out
}

/// Whether `text` contains any promoted locator fragment.
fn contains_fragment(text: &str, fragments: &[String]) -> bool {
    fragments
        .iter()
        .any(|fragment| !fragment.is_empty() && text.contains(fragment.as_str()))
}

/// Refuse a *redacted* annotation that still contains a locator fragment.
///
/// Fragments are not stored-metadata redaction targets: rewriting a one-byte
/// fragment would destroy the prose, and a decoded fragment is an ordinary
/// secret on the next pass, so a stored copy breaks the canonical fixed point.
fn reject_fragments_in_annotations(annotations: &[Annotation], fragments: &[String]) -> Result<()> {
    for annotation in annotations {
        let hit = match &annotation.kind {
            AnnotationKind::Intent(text) => contains_fragment(text, fragments),
            AnnotationKind::Constraint { source, .. } => contains_fragment(source, fragments),
            AnnotationKind::AiImmutable(_) => false,
        };
        if hit {
            return Err(Error::Encode("a secret fragment occurs in an annotation"));
        }
    }
    Ok(())
}

fn reject_fragments_in_provenance(
    provenance: Option<&Provenance>,
    fragments: &[String],
) -> Result<()> {
    let Some(provenance) = provenance else {
        return Ok(());
    };
    for text in [
        provenance.producer.as_deref(),
        provenance.model.as_deref(),
        provenance.tool.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if contains_fragment(text, fragments) {
            return Err(Error::Encode("a secret fragment occurs in provenance"));
        }
    }
    for entry in &provenance.entries {
        let hit = contains_fragment(&entry.key, fragments)
            || matches!(&entry.value, ProvValue::Text(text) if contains_fragment(text, fragments));
        if hit {
            return Err(Error::Encode("a secret fragment occurs in provenance"));
        }
    }
    Ok(())
}

/// Structural and expression text is stored verbatim, so a fragment in one
/// would sit in the public string heap; refuse it instead of publishing it.
///
/// Runs on the *canonical* node set, so a label on a dropped node cannot refuse
/// an encode. Covers every textual surface `Inode::strings` interns (and the
/// strings of annotation expression subtrees, which are metadata here).
fn reject_fragments_in_labels(
    nodes: &[Inode],
    bindings: &[(String, NodeId)],
    annotations: &[Annotation],
    fragments: &[String],
) -> Result<()> {
    let mut hit = bindings
        .iter()
        .any(|(name, _)| contains_fragment(name, fragments));
    for node in nodes {
        if hit {
            break;
        }
        hit = match node {
            Inode::Table { fields } | Inode::SchemaTable { fields, .. } => fields
                .iter()
                .any(|(name, _)| contains_fragment(name, fragments)),
            Inode::Env { name, .. } => contains_fragment(name, fragments),
            Inode::Quantity {
                unit: UnitTag::Named(name),
                ..
            } => contains_fragment(name, fragments),
            Inode::Blob { media_type, .. } => contains_fragment(media_type, fragments),
            Inode::Ident(text) => contains_fragment(text, fragments),
            Inode::Constrained { constraint, .. } => match constraint {
                Constraint::Enum(members) => members
                    .iter()
                    .any(|member| contains_fragment(member, fragments)),
                Constraint::Pattern(text) | Constraint::Custom(text) => {
                    contains_fragment(text, fragments)
                }
                Constraint::MinMax { .. } | Constraint::Odd => false,
            },
            Inode::Patch(op) => match op {
                PatchOp::Set { path, .. } | PatchOp::Remove { path } => {
                    contains_fragment(path, fragments)
                }
                PatchOp::Rename { from, to } => {
                    contains_fragment(from, fragments) || contains_fragment(to, fragments)
                }
            },
            Inode::SchemaField(spec) => {
                let enum_hit = matches!(&spec.typ, TypeSpec::Enum(items) if items.iter().any(|item| contains_fragment(item, fragments)));
                enum_hit
                    || spec
                        .deprecated
                        .as_deref()
                        .is_some_and(|text| contains_fragment(text, fragments))
            }
            Inode::Interpolate { parts } => parts.iter().any(|part| match part {
                InterpPart::Literal(text) => contains_fragment(text, fragments),
                InterpPart::Expr(_) => false,
            }),
            _ => false,
        };
    }
    // A constraint expression subtree is metadata: its strings are stored too.
    // The expression ids come from the *remapped* annotations, so they index the
    // canonical `nodes`; using the original arena ids here read unrelated nodes
    // and silently missed the fragment.
    if !hit {
        let mut stack: Vec<NodeId> = annotations
            .iter()
            .filter_map(|annotation| match &annotation.kind {
                AnnotationKind::Constraint { expr, .. } => Some(*expr),
                _ => None,
            })
            .collect();
        let mut visited = vec![false; nodes.len()];
        while let Some(id) = stack.pop() {
            if id.index() >= nodes.len() || visited[id.index()] {
                continue;
            }
            visited[id.index()] = true;
            match &nodes[id.index()] {
                Inode::Str(text) | Inode::Ident(text) => {
                    if contains_fragment(text, fragments) {
                        hit = true;
                        break;
                    }
                }
                Inode::Interpolate { parts } => {
                    hit = parts.iter().any(|part| match part {
                        InterpPart::Literal(text) => contains_fragment(text, fragments),
                        InterpPart::Expr(_) => false,
                    });
                    if hit {
                        break;
                    }
                }
                _ => {}
            }
            stack.extend(nodes[id.index()].children());
        }
    }
    if hit {
        return Err(Error::Encode("a secret fragment occurs in stored text"));
    }
    Ok(())
}

/// Move secret-only string literals into the secret heap (see step 1b above).
///
/// Returns the rewritten nodes and the interpolation fragments that were
/// promoted: those are secret material for exports, but they must not appear in
/// stored metadata (see `reject_fragments_in_metadata`).
fn promote_secret_locators(
    mut nodes: Vec<Inode>,
    module: &InfinityModule,
) -> (Vec<Inode>, Vec<String>) {
    if nodes.is_empty() {
        return (nodes, Vec::new());
    }
    let count = nodes.len();
    // Public nodes are the ones a root reaches without passing through a secret.
    // A secret node is a barrier: what it references is locator material (the
    // fallback of an env lookup, an interpolated literal), not public data.
    let public = reachable(&nodes, module.roots(), count);
    // Reachability from the module root alone. A binding is a name, not a
    // publication of locator material: `let pw = "..."` plus `secret(pw)` makes
    // the literal appear public only through the binding, and leaving it there
    // would store the secret's bytes in the public string heap.
    let public_from_root = reachable(&nodes, module.root(), count);

    // Every node a `SecretRef` locator reaches is locator material: a `Str`
    // literal, an `Interpolate`, and everything inside a `Binary`/`Unary`/...
    // expression that builds the locator. Resolving only the endpoint missed
    // `secret(pw + "-canary-${name}")`, whose `Str` and interpolation are
    // children of a `Binary`. One shared visited set keeps the walk linear when
    // many refs share a chain.
    let mut locator_material = vec![false; count];
    let mut visited = vec![false; count];
    let mut stack: Vec<NodeId> = nodes
        .iter()
        .filter_map(|node| match node {
            Inode::SecretRef { locator } => Some(*locator),
            _ => None,
        })
        .collect();
    while let Some(id) = stack.pop() {
        if id.index() >= count || visited[id.index()] {
            continue;
        }
        visited[id.index()] = true;
        locator_material[id.index()] = true;
        stack.extend(nodes[id.index()].children());
    }

    let mut referenced = vec![false; count];
    for node in &nodes {
        for child in node.children() {
            if let Some(slot) = referenced.get_mut(child.index()) {
                *slot = true;
            }
        }
    }
    for (index, node) in nodes.iter_mut().enumerate() {
        if !referenced[index] {
            continue;
        }
        // A locator literal counts as public only when the module root itself
        // reaches it (a shared literal), never merely because a binding names it.
        let is_public = public[index] && !(locator_material[index] && !public_from_root[index]);
        if is_public {
            continue;
        }
        match node {
            // An `Ident` in a locator is the secret's text, not a symbol: it
            // lands in the public string heap exactly like a `Str`.
            Inode::Str(text) | Inode::Ident(text) => {
                // Only promote when the literal is reachable solely through
                // secrets; promotion moves its bytes from the public string heap
                // into the secret heap, so a shared or public string is never
                // moved.
                *node = Inode::Secret(crate::ir::SecretBytes::from(text.clone()));
            }
            _ => {}
        }
    }

    // An interpolated locator (`secret("prefix-${name}")`) keeps its literal
    // parts in the public string heap. Move each part into a `Secret` node and
    // reference it from the interpolation, so those bytes leave the public heap
    // exactly as a plain locator's do.
    let mut rewrites: Vec<(usize, Vec<(usize, String)>)> = Vec::new();
    for (index, node) in nodes.iter().enumerate() {
        if !locator_material[index] || public_from_root[index] {
            continue;
        }
        if let Inode::Interpolate { parts } = node {
            let literals: Vec<(usize, String)> = parts
                .iter()
                .enumerate()
                .filter_map(|(part, value)| match value {
                    InterpPart::Literal(text) => Some((part, text.clone())),
                    InterpPart::Expr(_) => None,
                })
                .collect();
            if !literals.is_empty() {
                rewrites.push((index, literals));
            }
        }
    }
    let mut fragments = Vec::new();
    for (index, literals) in rewrites {
        for (part, text) in literals {
            let id = NodeId(nodes.len() as u32);
            fragments.push(text.clone());
            nodes.push(Inode::Secret(crate::ir::SecretBytes::from(text)));
            if let Inode::Interpolate { parts } = &mut nodes[index] {
                parts[part] = InterpPart::Expr(id);
            }
        }
    }
    (nodes, fragments)
}

/// Nodes reachable from `roots` without passing through a secret.
fn reachable(nodes: &[Inode], roots: impl IntoIterator<Item = NodeId>, count: usize) -> Vec<bool> {
    let mut public = vec![false; count];
    let mut queue: std::collections::VecDeque<NodeId> = roots
        .into_iter()
        .filter(|id| !id.is_none() && id.index() < count)
        .collect();
    while let Some(id) = queue.pop_front() {
        if public[id.index()] {
            continue;
        }
        public[id.index()] = true;
        if nodes[id.index()].is_secret() {
            continue;
        }
        for child in nodes[id.index()].children() {
            if child.index() < count && !public[child.index()] {
                queue.push_back(child);
            }
        }
    }
    public
}

/// Rewrite every node reference in `node` through `remap`.
///
/// `remap` is indexed by the old node id and holds `NodeId::NONE` for nodes that
/// are not part of the destination arena; a reference to one of those fails with
/// [`Error::EncodeDangling`]. The match is exhaustive over [`Inode`], so a new
/// child-bearing variant cannot be forgotten by a caller that projects a module
/// into a smaller arena.
///
/// Canonicalization uses this internally; it is public because building a
/// sub-arena (a subgraph, a pruned view) is a legitimate consumer operation and
/// duplicating this match outside the codec is how dangling references happen.
pub fn remap_node(node: &Inode, remap: &[NodeId]) -> Result<Inode> {
    let map = |id: NodeId| -> Result<NodeId> {
        remap
            .get(id.index())
            .copied()
            .filter(|mapped| !mapped.is_none())
            .ok_or(Error::EncodeDangling(id.0))
    };
    let opt = |id: Option<NodeId>| -> Result<Option<NodeId>> {
        match id {
            Some(id) => Ok(Some(map(id)?)),
            None => Ok(None),
        }
    };
    let out = match node {
        Inode::Quantity { value, unit } => Inode::Quantity {
            value: map(*value)?,
            unit: unit.clone(),
        },
        Inode::Array { elements } => Inode::Array {
            elements: elements.iter().map(|id| map(*id)).collect::<Result<_>>()?,
        },
        Inode::Table { fields } => Inode::Table {
            fields: fields
                .iter()
                .map(|(name, id)| Ok((name.clone(), map(*id)?)))
                .collect::<Result<_>>()?,
        },
        Inode::SecretRef { locator } => Inode::SecretRef {
            locator: map(*locator)?,
        },
        Inode::Ref(id) => Inode::Ref(map(*id)?),
        Inode::Env { name, default } => Inode::Env {
            name: name.clone(),
            default: opt(*default)?,
        },
        Inode::Interpolate { parts } => Inode::Interpolate {
            parts: parts
                .iter()
                .map(|part| match part {
                    InterpPart::Literal(text) => Ok(InterpPart::Literal(text.clone())),
                    InterpPart::Expr(id) => Ok(InterpPart::Expr(map(*id)?)),
                })
                .collect::<Result<_>>()?,
        },
        Inode::Binary { op, lhs, rhs } => Inode::Binary {
            op: *op,
            lhs: map(*lhs)?,
            rhs: map(*rhs)?,
        },
        Inode::Unary { op, expr } => Inode::Unary {
            op: *op,
            expr: map(*expr)?,
        },
        Inode::Constrained { target, constraint } => Inode::Constrained {
            target: map(*target)?,
            constraint: constraint.clone(),
        },
        Inode::Patch(op) => Inode::Patch(match op {
            PatchOp::Set { path, value } => PatchOp::Set {
                path: path.clone(),
                value: map(*value)?,
            },
            PatchOp::Remove { path } => PatchOp::Remove { path: path.clone() },
            PatchOp::Rename { from, to } => PatchOp::Rename {
                from: from.clone(),
                to: to.clone(),
            },
        }),
        Inode::SchemaField(spec) => Inode::SchemaField(SchemaFieldSpec {
            typ: spec.typ.clone(),
            min: opt(spec.min)?,
            max: opt(spec.max)?,
            min_len: opt(spec.min_len)?,
            max_len: opt(spec.max_len)?,
            pattern: opt(spec.pattern)?,
            default: opt(spec.default)?,
            deprecated: spec.deprecated.clone(),
        }),
        Inode::SchemaTable { fields, closed } => Inode::SchemaTable {
            fields: fields
                .iter()
                .map(|(name, id)| Ok((name.clone(), map(*id)?)))
                .collect::<Result<_>>()?,
            closed: *closed,
        },
        Inode::SchemaArray { element } => Inode::SchemaArray {
            element: map(*element)?,
        },
        Inode::Semantic { tag, inner } => Inode::Semantic {
            tag: *tag,
            inner: map(*inner)?,
        },
        Inode::ContentAddressed { media_type, data } => Inode::ContentAddressed {
            media_type: map(*media_type)?,
            data: map(*data)?,
        },
        // Leaf variants: no node references. Listed explicitly so a new
        // child-bearing variant fails to compile instead of being cloned with
        // its old ids.
        Inode::Null
        | Inode::Bool(_)
        | Inode::Int(_)
        | Inode::Float(_)
        | Inode::Str(_)
        | Inode::DurationMs(_)
        | Inode::Secret(_)
        | Inode::Ident(_)
        | Inode::Blob { .. } => node.clone(),
    };
    Ok(out)
}

/// Rewrite every node reference in place, consuming no clones.
///
/// Mirrors [`remap_node`], which returns a new node. Canonicalization uses this
/// form when it already owns the node; the bytes it produces are identical.
fn remap_node_in_place(node: &mut Inode, remap: &[NodeId]) -> Result<()> {
    fn map(id: &mut NodeId, remap: &[NodeId]) -> Result<()> {
        let mapped = remap
            .get(id.index())
            .copied()
            .filter(|mapped| !mapped.is_none())
            .ok_or(Error::EncodeDangling(id.0))?;
        *id = mapped;
        Ok(())
    }
    fn opt(id: &mut Option<NodeId>, remap: &[NodeId]) -> Result<()> {
        if let Some(id) = id {
            map(id, remap)?;
        }
        Ok(())
    }
    match node {
        Inode::Quantity { value, .. } => map(value, remap)?,
        Inode::Array { elements } => {
            for id in elements {
                map(id, remap)?;
            }
        }
        Inode::Table { fields } => {
            for (_, id) in fields {
                map(id, remap)?;
            }
        }
        Inode::SecretRef { locator } => map(locator, remap)?,
        Inode::Ref(id) => map(id, remap)?,
        Inode::Env { default, .. } => opt(default, remap)?,
        Inode::Interpolate { parts } => {
            for part in parts {
                if let InterpPart::Expr(id) = part {
                    map(id, remap)?;
                }
            }
        }
        Inode::Binary { lhs, rhs, .. } => {
            map(lhs, remap)?;
            map(rhs, remap)?;
        }
        Inode::Unary { expr, .. } => map(expr, remap)?,
        Inode::Constrained { target, .. } => map(target, remap)?,
        Inode::Patch(PatchOp::Set { value, .. }) => map(value, remap)?,
        Inode::SchemaField(spec) => {
            opt(&mut spec.min, remap)?;
            opt(&mut spec.max, remap)?;
            opt(&mut spec.min_len, remap)?;
            opt(&mut spec.max_len, remap)?;
            opt(&mut spec.pattern, remap)?;
            opt(&mut spec.default, remap)?;
        }
        Inode::SchemaTable { fields, .. } => {
            for (_, id) in fields {
                map(id, remap)?;
            }
        }
        Inode::SchemaArray { element } => map(element, remap)?,
        Inode::Semantic { inner, .. } => map(inner, remap)?,
        Inode::ContentAddressed { media_type, data } => {
            map(media_type, remap)?;
            map(data, remap)?;
        }
        // Leaf variants and the path-only patch ops: no node references.
        // Listed explicitly so a new child-bearing variant fails to compile.
        Inode::Null
        | Inode::Bool(_)
        | Inode::Int(_)
        | Inode::Float(_)
        | Inode::Str(_)
        | Inode::DurationMs(_)
        | Inode::Secret(_)
        | Inode::Ident(_)
        | Inode::Blob { .. }
        | Inode::Patch(PatchOp::Remove { .. } | PatchOp::Rename { .. }) => {}
    }
    Ok(())
}

/// Total bytes of ordering keys one module may hold.
///
/// Every annotation subject and constraint expression needs a key, and a key is
/// a render of its subtree — exact up to 1 MiB, a digest beyond it
/// (INF-10). The per-key ceiling bounds one key; this bound covers all of
/// them, so a module with tens of thousands of large subjects is refused
/// (`infinity/limit`) instead of driving peak memory to the sum.
pub(crate) const MAX_ANNOTATION_KEY_BYTES: usize = 64 << 20;

/// Render a subject's content key once and remember its position.
///
/// Keys are kept in one `Vec` and referenced by index, so a subject annotated
/// many times shares one allocation instead of one per annotation.
fn key_index(
    nodes: &[crate::ir::Inode],
    id: NodeId,
    keys: &mut Vec<String>,
    index: &mut HashMap<NodeId, usize>,
    total: &mut usize,
) -> Result<usize> {
    if let Some(found) = index.get(&id) {
        return Ok(*found);
    }
    let key = content_key(nodes, id)?;
    *total = total.saturating_add(key.len());
    if *total > MAX_ANNOTATION_KEY_BYTES {
        return Err(Error::Limit {
            kind: "annotation key bytes",
            limit: MAX_ANNOTATION_KEY_BYTES as u64,
        });
    }
    let position = keys.len();
    keys.push(key);
    index.insert(id, position);
    Ok(position)
}

/// A content-defined key for a subtree, independent of arena ids.
///
/// Used only to order the annotation roots: an annotation subject can be a node
/// that nothing else reaches, so numbering it in stored order would let the order
/// of `annotate` calls leak into the image. The render walks children in their
/// (already canonical) order and writes every non-reference payload; references
/// are followed, never printed as ids. Secrets contribute a fixed marker, never
/// their bytes.
///
/// The key is the exact render while it fits in [`KEY_BYTES`] (1 MiB) — so
/// every module the old key accepted keeps its bytes — and a Blake3 digest
/// of the same content past it (INF-10). The old key refused a subtree
/// past the byte budget or deeper than 256, although the wire allows
/// strings to 64 MiB and depth to 4096: a legal module could not be
/// encoded at all once it was annotated. A digest bounds the key without
/// bounding the module, and the key keeps its injectivity (up to a Blake3
/// collision, the same assumption the format already makes for content
/// addressing).
///
/// There is no depth cap on the key any more. Depth is bounded upstream
/// by `prepare()`, which validates the module at
/// `Limits::default().max_depth` (4096, INF-09) before the order is
/// derived, so the key never sees a deeper subtree — and the render is
/// iterative (an explicit action stack, `render_key_exact`), because a
/// recursive render aborted the process with a stack overflow in debug
/// on chains deeper than ~150 (INF-15) and a legal 4096-deep chain must
/// render without touching the call stack. Making the render iterative
/// also removes INF-15's abort mechanism; INF-15 stays open in the
/// registry until its own worker verifies and closes it.
///
/// The digest is a tree hash (`subtree_digest`), not a hash of the flat
/// render: the flat render of a shared subtree can be exponential in
/// its depth (a doubling DAG of 60 nodes renders ~2^60 bytes), so
/// hashing the flat render would hang where the old key refused fast.
/// The tree hash memoises by node id — a shared subtree is hashed once
/// — and therefore costs O(subtree nodes + payload bytes). It mirrors
/// the render's distinctions exactly (same payload, same framed-only
/// parts, secrets folded to the same constant), so a subtree's digest
/// and its exact render agree on what counts as different content.
///
/// The hashed form sorts before every exact render (it starts with a
/// NUL byte, which no render's first byte can be), and the 64 MiB total
/// (`MAX_ANNOTATION_KEY_BYTES`) still bounds all keys together: a module
/// with tens of thousands of near-1 MiB subjects is still refused
/// instead of driving peak memory to the sum.
fn content_key_with(nodes: &[crate::ir::Inode], id: NodeId, framed: bool) -> Result<String> {
    const KEY_BYTES: usize = 1 << 20;

    match render_key_exact(nodes, id, framed, KEY_BYTES)? {
        Some(key) => Ok(key),
        None => Ok(hashed_key(&subtree_digest(nodes, id, framed)?, framed)),
    }
}

/// The hashed form of an over-budget ordering key.
///
/// The leading NUL byte is the point: no exact render starts with one
/// (every render starts with a node tag, and even a framed secret
/// renders as `6:SECRET`), so a hashed key can never equal — or sort
/// among — the exact renders, and two hashed keys order by their digest
/// alone. The mode letter keeps the framed and unframed digests
/// visibly apart (they are computed from different content: the framed
/// render carries length prefixes, named-unit names and schema-field
/// slot markers the unframed one does not).
fn hashed_key(digest: &[u8; 32], framed: bool) -> String {
    let mut key = String::with_capacity(72);
    key.push('\0');
    key.push('H');
    key.push(if framed { 'f' } else { 'u' });
    key.push(':');
    key.push_str(&crate::ir::hash_hex(digest));
    key
}

/// A sink for the exact key render: it accumulates the render while it
/// fits in the budget and records the moment it runs past it, instead
/// of materialising a key that would then be thrown away.
struct KeySink {
    buf: String,
    total: usize,
    budget: usize,
    over: bool,
}

impl KeySink {
    fn new(budget: usize) -> Self {
        Self {
            buf: String::new(),
            total: 0,
            budget,
            over: false,
        }
    }

    fn push_str(&mut self, value: &str) {
        if self.over {
            return;
        }
        self.total = self.total.saturating_add(value.len());
        if self.total > self.budget {
            self.over = true;
            return;
        }
        self.buf.push_str(value);
    }

    fn push_char(&mut self, value: char) {
        if self.over {
            return;
        }
        self.total = self.total.saturating_add(value.len_utf8());
        if self.total > self.budget {
            self.over = true;
            return;
        }
        self.buf.push(value);
    }

    /// Write `value` exactly as the recursive render's `text()` did:
    /// length-prefixed when `framed` (a name may contain the separators
    /// the renderer uses, so an unframed key is not injective), bare
    /// otherwise. The prefix bytes count toward the budget like any
    /// other byte.
    fn push_text(&mut self, framed: bool, value: &str) {
        if framed {
            self.push_str(&format!("{}:", value.len()));
        }
        self.push_str(value);
    }
}

/// One pending step of the iterative key render.
///
/// The render is a depth-first walk with per-node prefix text, so a
/// flat action stack replaces the recursion: `Visit` expands one node
/// (prefix text inline, children pushed below), `Seq` resumes a
/// sequence node at its next item (item text inline, the child's visit
/// pushed above it), and `Comma` writes the `,` that follows one
/// Array/Table item after its subtree has rendered. At most ~2 entries
/// sit on the stack per level of depth, so the stack stays O(depth)
/// — a wide node never materialises its items up front.
enum RenderAction<'a> {
    Visit(NodeId),
    Comma,
    Seq(&'a crate::ir::Inode, usize),
}

/// Render a subject's content key exactly, or report that it runs past
/// `budget` bytes.
///
/// Returns `Ok(Some(key))` when the render fits, `Ok(None)` when it
/// runs past the budget (the caller then takes the digest path), and
/// `Err` for a dangling reference. The render aborts the moment the
/// budget is passed, so the attempt costs O(budget) work: every node
/// emits at least one byte, and a shared subtree is re-walked only
/// until the budget trips.
fn render_key_exact(
    nodes: &[crate::ir::Inode],
    id: NodeId,
    framed: bool,
    budget: usize,
) -> Result<Option<String>> {
    // Defence-in-depth: a cycle cannot reach here (`prepare()`
    // validates acyclicity before the order is derived), but a cyclic
    // graph would push forever — the valve turns that into an error
    // instead of an unbounded stack. A valid render holds ~2 entries
    // per level of depth (a sequence driver plus a pending comma), and
    // depth is capped at 4096 by validate, so this is 8x headroom over
    // the largest valid stack.
    const MAX_RENDER_STACK: usize = 65_536;

    let mut sink = KeySink::new(budget);
    let mut stack: Vec<RenderAction<'_>> = Vec::new();
    stack.push(RenderAction::Visit(id));
    while let Some(action) = stack.pop() {
        if stack.len() > MAX_RENDER_STACK {
            return Err(Error::Encode(
                "annotation key render exceeded the work limit",
            ));
        }
        match action {
            RenderAction::Visit(node_id) => {
                let Some(node) = nodes.get(node_id.index()) else {
                    return Err(Error::EncodeDangling(node_id.0));
                };
                render_key_prefix(node, framed, &mut sink, &mut stack);
            }
            RenderAction::Comma => sink.push_char(','),
            RenderAction::Seq(node, index) => {
                render_key_seq_item(node, index, framed, &mut sink, &mut stack);
            }
        }
        if sink.over {
            return Ok(None);
        }
    }
    Ok(Some(sink.buf))
}

/// Write one node's prefix text and push its children, in render
/// order. This is the old recursive `render()`'s per-node arm with the
/// recursive calls replaced by pushes: children are pushed in reverse
/// execution order, so the first child is on top.
fn render_key_prefix<'a>(
    node: &'a crate::ir::Inode,
    framed: bool,
    sink: &mut KeySink,
    stack: &mut Vec<RenderAction<'a>>,
) {
    use crate::ir::Inode as I;
    match node {
        I::Null => sink.push_char('n'),
        I::Bool(value) => sink.push_char(if *value { 't' } else { 'f' }),
        I::Int(value) => {
            sink.push_char('i');
            sink.push_text(framed, &value.to_string());
        }
        I::Float(value) => {
            sink.push_char('d');
            sink.push_text(framed, &value.to_bits().to_string());
        }
        I::Str(value) => {
            sink.push_char('s');
            sink.push_text(framed, &value.len().to_string());
            sink.push_char(':');
            sink.push_text(framed, value);
        }
        I::DurationMs(ms) => {
            sink.push_char('m');
            sink.push_text(framed, &ms.to_string());
        }
        I::Quantity { value, unit } => {
            sink.push_char('q');
            sink.push_text(framed, &unit.discriminant().to_string());
            if framed {
                // Every named unit shares one discriminant; without the
                // name two units render identically.
                if let UnitTag::Named(name) = unit {
                    sink.push_char('n');
                    sink.push_text(framed, name);
                }
            }
            sink.push_char(':');
            stack.push(RenderAction::Visit(*value));
        }
        I::Array { .. } => {
            sink.push_char('[');
            stack.push(RenderAction::Seq(node, 0));
        }
        I::Table { .. } => {
            sink.push_char('{');
            stack.push(RenderAction::Seq(node, 0));
        }
        // A secret's content is never part of any key.
        I::Secret(_) => sink.push_text(framed, "SECRET"),
        I::SecretRef { locator } => {
            sink.push_char('S');
            stack.push(RenderAction::Visit(*locator));
        }
        I::Ref(target) => {
            sink.push_char('R');
            stack.push(RenderAction::Visit(*target));
        }
        I::Env { name, default } => {
            sink.push_char('E');
            sink.push_text(framed, name);
            sink.push_char(':');
            if let Some(default) = default {
                stack.push(RenderAction::Visit(*default));
            }
        }
        I::Ident(name) => {
            sink.push_char('I');
            sink.push_text(framed, name);
        }
        I::Interpolate { .. } => {
            sink.push_char('T');
            stack.push(RenderAction::Seq(node, 0));
        }
        I::Binary { op, lhs, rhs } => {
            sink.push_char('b');
            sink.push_text(framed, op.as_str());
            sink.push_char(':');
            stack.push(RenderAction::Visit(*rhs));
            stack.push(RenderAction::Visit(*lhs));
        }
        I::Unary { op, expr } => {
            sink.push_char('u');
            sink.push_text(framed, op.as_str());
            sink.push_char(':');
            stack.push(RenderAction::Visit(*expr));
        }
        I::Constrained { target, constraint } => {
            sink.push_char('c');
            render_key_constraint(constraint, framed, sink);
            stack.push(RenderAction::Visit(*target));
        }
        I::Patch(op) => {
            sink.push_char('p');
            match op {
                crate::ir::PatchOp::Set { path, value } => {
                    sink.push_char('s');
                    sink.push_text(framed, path);
                    stack.push(RenderAction::Visit(*value));
                }
                crate::ir::PatchOp::Remove { path } => {
                    sink.push_char('r');
                    sink.push_text(framed, path);
                }
                crate::ir::PatchOp::Rename { from, to } => {
                    sink.push_char('n');
                    sink.push_text(framed, from);
                    sink.push_text(framed, to);
                }
            }
        }
        I::SchemaField(spec) => {
            sink.push_char('F');
            render_key_type_spec(&spec.typ, framed, sink);
            stack.push(RenderAction::Seq(node, 0));
        }
        I::SchemaTable { closed, .. } => {
            sink.push_char('G');
            sink.push_char(if *closed { '1' } else { '0' });
            stack.push(RenderAction::Seq(node, 0));
        }
        I::SchemaArray { element } => {
            sink.push_char('A');
            stack.push(RenderAction::Visit(*element));
        }
        I::Semantic { tag, inner } => {
            sink.push_char('y');
            sink.push_text(framed, tag.as_str());
            stack.push(RenderAction::Visit(*inner));
        }
        I::ContentAddressed { media_type, data } => {
            sink.push_char('C');
            stack.push(RenderAction::Visit(*data));
            stack.push(RenderAction::Visit(*media_type));
        }
        I::Blob {
            hash,
            size,
            tainted,
            media_type,
            payload,
        } => {
            sink.push_char('B');
            sink.push_text(framed, &crate::ir::hash_hex(hash));
            sink.push_text(framed, &size.to_string());
            sink.push_char(if *tainted { '1' } else { '0' });
            sink.push_text(framed, media_type);
            if let Some(payload) = payload {
                sink.push_text(framed, &payload.len().to_string());
            }
        }
    }
}

/// Write a constraint's payload, exactly as the old render did: the
/// `Constraint` `Debug` redacts enum members and pattern text to a
/// fixed marker, which would give two different constraints the same
/// ordering key, so the payload is rendered explicitly instead.
fn render_key_constraint(constraint: &crate::ir::Constraint, framed: bool, sink: &mut KeySink) {
    use crate::ir::Constraint as C;
    match constraint {
        C::MinMax { min, max } => {
            sink.push_char('M');
            for bound in [min, max] {
                match bound {
                    Some(value) => {
                        sink.push_char('v');
                        sink.push_text(framed, &value.to_string());
                    }
                    None => sink.push_char('-'),
                }
            }
        }
        C::Enum(items) => {
            sink.push_char('e');
            // The encoder sorts enum members; the key must too.
            let mut ordered: Vec<&String> = items.iter().collect();
            ordered.sort();
            for item in ordered {
                sink.push_text(framed, &item.len().to_string());
                sink.push_char(':');
                sink.push_text(framed, item);
            }
        }
        C::Pattern(pattern) => {
            sink.push_char('p');
            sink.push_text(framed, &pattern.len().to_string());
            sink.push_char(':');
            sink.push_text(framed, pattern);
        }
        C::Odd => sink.push_char('o'),
        C::Custom(value) => {
            sink.push_char('x');
            sink.push_text(framed, &value.len().to_string());
            sink.push_char(':');
            sink.push_text(framed, value);
        }
    }
}

/// Write a schema field's type payload, exactly as the old render did:
/// every id-bearing field is followed (as a child); only the type
/// itself and the textual fields are written here.
fn render_key_type_spec(spec: &crate::ir::TypeSpec, framed: bool, sink: &mut KeySink) {
    use crate::ir::TypeSpec as T;
    match spec {
        T::Enum(members) => {
            sink.push_char('E');
            // The encoder sorts members before interning, so the key
            // sorts them too: insertion order must not reach the hash.
            let mut ordered: Vec<&String> = members.iter().collect();
            ordered.sort();
            for member in ordered {
                sink.push_text(framed, &member.len().to_string());
                sink.push_char(':');
                sink.push_text(framed, member);
            }
        }
        T::Table { closed } => {
            sink.push_char('T');
            sink.push_char(if *closed { '1' } else { '0' });
        }
        other => sink.push_text(framed, &format!("{other:?}")),
    }
}

/// Render one item of a sequence node (`Array`, `Table`,
/// `Interpolate`, `SchemaField`, `SchemaTable`), or the node's
/// closing text when the items run out.
///
/// The item's pre-child text is written inline; the child's visit is
/// pushed above the re-pushed driver, so the child renders before the
/// next item starts — and a `,` (Array/Table only) is pushed between
/// them, so it is written after the child's subtree, as the render did.
fn render_key_seq_item<'a>(
    node: &'a crate::ir::Inode,
    index: usize,
    framed: bool,
    sink: &mut KeySink,
    stack: &mut Vec<RenderAction<'a>>,
) {
    use crate::ir::Inode as I;
    match node {
        I::Array { elements } => {
            let Some(element) = elements.get(index) else {
                sink.push_char(']');
                return;
            };
            stack.push(RenderAction::Seq(node, index + 1));
            stack.push(RenderAction::Comma);
            stack.push(RenderAction::Visit(*element));
        }
        I::Table { fields } => {
            let Some((name, value)) = fields.get(index) else {
                sink.push_char('}');
                return;
            };
            sink.push_text(framed, &name.len().to_string());
            sink.push_char(':');
            sink.push_text(framed, name);
            sink.push_char('=');
            stack.push(RenderAction::Seq(node, index + 1));
            stack.push(RenderAction::Comma);
            stack.push(RenderAction::Visit(*value));
        }
        I::Interpolate { parts } => {
            let Some(part) = parts.get(index) else {
                sink.push_char('t');
                return;
            };
            match part {
                crate::ir::InterpPart::Literal(literal) => {
                    sink.push_char('l');
                    sink.push_text(framed, &literal.len().to_string());
                    sink.push_char(':');
                    sink.push_text(framed, literal);
                    stack.push(RenderAction::Seq(node, index + 1));
                }
                crate::ir::InterpPart::Expr(expr) => {
                    sink.push_char('e');
                    stack.push(RenderAction::Seq(node, index + 1));
                    stack.push(RenderAction::Visit(*expr));
                }
            }
        }
        I::SchemaField(spec) => {
            // The slots in order; only the present ones are items.
            let mut seen = 0;
            let mut found: Option<(usize, NodeId)> = None;
            for (slot, node) in [
                spec.min,
                spec.max,
                spec.min_len,
                spec.max_len,
                spec.pattern,
                spec.default,
            ]
            .into_iter()
            .enumerate()
            {
                if let Some(node) = node {
                    if seen == index {
                        found = Some((slot, node));
                        break;
                    }
                    seen += 1;
                }
            }
            let Some((slot, child)) = found else {
                if let Some(spec_text) = &spec.deprecated {
                    sink.push_char('!');
                    sink.push_text(framed, spec_text);
                }
                return;
            };
            if framed {
                // `min` and `max` both pointing at the same node used to
                // render identically.
                sink.push_char(char::from(b'a' + slot as u8));
            }
            stack.push(RenderAction::Seq(node, index + 1));
            stack.push(RenderAction::Visit(child));
        }
        I::SchemaTable { fields, .. } => {
            let Some((name, value)) = fields.get(index) else {
                return;
            };
            sink.push_text(framed, name);
            sink.push_char('=');
            stack.push(RenderAction::Seq(node, index + 1));
            stack.push(RenderAction::Visit(*value));
        }
        // `Seq` is only ever pushed for a sequence node.
        _ => unreachable!("a sequence driver holds a sequence node"),
    }
}

/// One frame of the iterative subtree digest: a node whose own payload
/// is already in its hasher and whose children are being folded in,
/// in order.
struct DigestFrame {
    id: NodeId,
    hasher: blake3::Hasher,
    children: Vec<NodeId>,
    next: usize,
}

impl DigestFrame {
    fn new(id: NodeId, node: &crate::ir::Inode, framed: bool) -> Self {
        let mut hasher = blake3::Hasher::new();
        digest_own(&mut hasher, node, framed);
        Self {
            id,
            hasher,
            children: node.children(),
            next: 0,
        }
    }
}

/// A content digest for a subtree, used as the ordering key when the
/// exact render runs past 1 MiB.
///
/// The digest is a Blake3 tree hash: each node's digest covers a
/// length-prefixed encoding of the node's own payload — exactly the
/// content the exact render writes, including the framed-only parts
/// (named-unit names, schema-field slot markers) — followed by the
/// 32-byte digests of its children in order. Two subtrees with
/// different renders have different digests unless Blake3 collides
/// (the same assumption the format already makes for content
/// addressing); two with equal renders have equal digests.
///
/// The walk is iterative (an explicit stack of frames holding a
/// running hasher each) and memoised by node id, so a shared subtree
/// is hashed once: a doubling DAG costs O(subtree nodes + payload
/// bytes), never O(render bytes).
fn subtree_digest(nodes: &[crate::ir::Inode], root: NodeId, framed: bool) -> Result<[u8; 32]> {
    let Some(root_node) = nodes.get(root.index()) else {
        return Err(Error::EncodeDangling(root.0));
    };
    // Memoised by node id: a shared subtree is hashed once. Worst case
    // the memo holds one 32-byte digest per node of the subject — a
    // pathological 4M-node single subject costs ~200 MB transient — but
    // that only ever happens for a subject the old key refused outright,
    // and the module itself is already that large.
    let mut memo: HashMap<NodeId, [u8; 32]> = HashMap::new();
    // Defence-in-depth: a cycle cannot reach here (`prepare()`
    // validates acyclicity before the order is derived), but without
    // this set a cyclic graph would push frames forever.
    let mut in_progress: HashSet<NodeId> = HashSet::new();
    in_progress.insert(root);
    let mut stack = vec![DigestFrame::new(root, root_node, framed)];
    while !stack.is_empty() {
        // Short borrows only: the frame is never held across a push or
        // a pop of the stack itself.
        let next_child = {
            let frame = stack
                .last()
                .expect("the loop only runs on a non-empty stack");
            if frame.next < frame.children.len() {
                Some(frame.children[frame.next])
            } else {
                None
            }
        };
        if let Some(child) = next_child {
            {
                let frame = stack
                    .last_mut()
                    .expect("the loop only runs on a non-empty stack");
                frame.next += 1;
            }
            if let Some(digest) = memo.get(&child) {
                let frame = stack
                    .last_mut()
                    .expect("the loop only runs on a non-empty stack");
                frame.hasher.update(digest);
                continue;
            }
            if !in_progress.insert(child) {
                return Err(Error::Cycle { node: child.0 });
            }
            let Some(node) = nodes.get(child.index()) else {
                return Err(Error::EncodeDangling(child.0));
            };
            stack.push(DigestFrame::new(child, node, framed));
            continue;
        }
        let frame = stack
            .pop()
            .expect("the loop only runs on a non-empty stack");
        let digest = *frame.hasher.finalize().as_bytes();
        in_progress.remove(&frame.id);
        memo.insert(frame.id, digest);
        if let Some(parent) = stack.last_mut() {
            parent.hasher.update(&digest);
        } else {
            return Ok(digest);
        }
    }
    unreachable!("the stack starts non-empty and only empties by returning the root digest");
}

/// Feed one length-prefixed byte string into a digest hasher: the
/// length makes the encoding unambiguous, so `"ab" + "c"` and `"a" +
/// "bc"` can never hash alike.
fn digest_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn digest_str(hasher: &mut blake3::Hasher, value: &str) {
    digest_bytes(hasher, value.as_bytes());
}

fn digest_u64(hasher: &mut blake3::Hasher, value: u64) {
    hasher.update(&value.to_le_bytes());
}

fn digest_bool(hasher: &mut blake3::Hasher, value: bool) {
    hasher.update(&[u8::from(value)]);
}

/// Feed one node's own payload into its digest hasher: the variant
/// tag, every scalar and string the exact render writes for this node
/// (including the framed-only parts — named-unit names and
/// schema-field slot markers), and the structure that says where the
/// children go (counts, field names, part kinds, slot presence). The
/// children themselves are folded in by the caller, as their 32-byte
/// digests, in `children()` order.
///
/// This mirrors the exact render's distinctions exactly, and nothing
/// else: secrets contribute the same fixed marker (never their bytes),
/// blob payloads contribute only their length, and no arena id is ever
/// fed — so equal renders give equal digests, different renders give
/// different digests (up to a Blake3 collision), and the digest can
/// stand in for the render as the ordering key.
fn digest_own(hasher: &mut blake3::Hasher, node: &crate::ir::Inode, framed: bool) {
    use crate::ir::Inode as I;
    match node {
        // One distinct tag byte per variant; the tags are internal to
        // this hash and need no relation to the render's tag chars.
        I::Null => {
            hasher.update(&[0x01]);
        }
        I::Bool(value) => {
            hasher.update(&[0x02]);
            digest_bool(hasher, *value);
        }
        I::Int(value) => {
            hasher.update(&[0x03]);
            hasher.update(&value.to_le_bytes());
        }
        I::Float(value) => {
            hasher.update(&[0x04]);
            hasher.update(&value.to_bits().to_le_bytes());
        }
        I::Str(value) => {
            hasher.update(&[0x05]);
            digest_str(hasher, value);
        }
        I::DurationMs(ms) => {
            hasher.update(&[0x06]);
            digest_u64(hasher, *ms);
        }
        I::Quantity { unit, .. } => {
            hasher.update(&[0x07]);
            hasher.update(&unit.discriminant().to_le_bytes());
            if framed {
                if let UnitTag::Named(name) = unit {
                    digest_str(hasher, name);
                }
            }
        }
        I::Array { elements } => {
            hasher.update(&[0x08]);
            digest_u64(hasher, elements.len() as u64);
        }
        I::Table { fields } => {
            hasher.update(&[0x09]);
            digest_u64(hasher, fields.len() as u64);
            for (name, _) in fields {
                digest_str(hasher, name);
            }
        }
        // A secret's content is never part of any key.
        I::Secret(_) => {
            hasher.update(&[0x0a]);
            digest_str(hasher, "SECRET");
        }
        I::SecretRef { .. } => {
            hasher.update(&[0x0b]);
        }
        I::Ref(_) => {
            hasher.update(&[0x0c]);
        }
        I::Env { name, default } => {
            hasher.update(&[0x0d]);
            digest_str(hasher, name);
            digest_bool(hasher, default.is_some());
        }
        I::Ident(name) => {
            hasher.update(&[0x0e]);
            digest_str(hasher, name);
        }
        I::Interpolate { parts } => {
            hasher.update(&[0x0f]);
            digest_u64(hasher, parts.len() as u64);
            for part in parts {
                match part {
                    crate::ir::InterpPart::Literal(literal) => {
                        hasher.update(b"l");
                        digest_str(hasher, literal);
                    }
                    crate::ir::InterpPart::Expr(_) => {
                        hasher.update(b"e");
                    }
                }
            }
        }
        I::Binary { op, .. } => {
            hasher.update(&[0x10]);
            digest_str(hasher, op.as_str());
        }
        I::Unary { op, .. } => {
            hasher.update(&[0x11]);
            digest_str(hasher, op.as_str());
        }
        I::Constrained { constraint, .. } => {
            hasher.update(&[0x12]);
            digest_constraint(hasher, constraint);
        }
        I::Patch(op) => {
            hasher.update(&[0x13]);
            match op {
                crate::ir::PatchOp::Set { path, .. } => {
                    hasher.update(b"s");
                    digest_str(hasher, path);
                }
                crate::ir::PatchOp::Remove { path } => {
                    hasher.update(b"r");
                    digest_str(hasher, path);
                }
                crate::ir::PatchOp::Rename { from, to } => {
                    hasher.update(b"n");
                    digest_str(hasher, from);
                    digest_str(hasher, to);
                }
            }
        }
        I::SchemaField(spec) => {
            hasher.update(&[0x14]);
            digest_type_spec(hasher, &spec.typ);
            // Which slots hold a child — the children are folded in
            // in slot order, so the presence pattern says which slots
            // the digests belong to.
            for node in [
                spec.min,
                spec.max,
                spec.min_len,
                spec.max_len,
                spec.pattern,
                spec.default,
            ] {
                digest_bool(hasher, node.is_some());
            }
            if framed {
                // `min` and `max` both pointing at the same node used to
                // render identically.
                for (slot, node) in [
                    spec.min,
                    spec.max,
                    spec.min_len,
                    spec.max_len,
                    spec.pattern,
                    spec.default,
                ]
                .into_iter()
                .enumerate()
                {
                    if node.is_some() {
                        hasher.update(&[b'a' + slot as u8]);
                    }
                }
            }
            match &spec.deprecated {
                Some(text) => {
                    digest_bool(hasher, true);
                    digest_str(hasher, text);
                }
                None => digest_bool(hasher, false),
            }
        }
        I::SchemaTable { fields, closed } => {
            hasher.update(&[0x15]);
            digest_bool(hasher, *closed);
            digest_u64(hasher, fields.len() as u64);
            for (name, _) in fields {
                digest_str(hasher, name);
            }
        }
        I::SchemaArray { .. } => {
            hasher.update(&[0x16]);
        }
        I::Semantic { tag, .. } => {
            hasher.update(&[0x17]);
            digest_str(hasher, tag.as_str());
        }
        I::ContentAddressed { .. } => {
            hasher.update(&[0x18]);
        }
        I::Blob {
            hash,
            size,
            tainted,
            media_type,
            payload,
        } => {
            hasher.update(&[0x19]);
            hasher.update(hash);
            digest_u64(hasher, *size);
            digest_bool(hasher, *tainted);
            digest_str(hasher, media_type);
            match payload {
                Some(bytes) => {
                    digest_bool(hasher, true);
                    digest_u64(hasher, bytes.len() as u64);
                }
                None => digest_bool(hasher, false),
            }
        }
    }
}

/// Feed a constraint's payload into a digest hasher, mirroring
/// `render_key_constraint`: the payload is rendered explicitly (not
/// through `Debug`, which redacts enum members and pattern text).
fn digest_constraint(hasher: &mut blake3::Hasher, constraint: &crate::ir::Constraint) {
    use crate::ir::Constraint as C;
    match constraint {
        C::MinMax { min, max } => {
            hasher.update(b"M");
            for bound in [min, max] {
                match bound {
                    Some(value) => {
                        hasher.update(b"v");
                        hasher.update(&value.to_le_bytes());
                    }
                    None => {
                        hasher.update(b"-");
                    }
                }
            }
        }
        C::Enum(items) => {
            hasher.update(b"e");
            let mut ordered: Vec<&String> = items.iter().collect();
            ordered.sort();
            digest_u64(hasher, ordered.len() as u64);
            for item in ordered {
                digest_str(hasher, item);
            }
        }
        C::Pattern(pattern) => {
            hasher.update(b"p");
            digest_str(hasher, pattern);
        }
        C::Odd => {
            hasher.update(b"o");
        }
        C::Custom(value) => {
            hasher.update(b"x");
            digest_str(hasher, value);
        }
    }
}

/// Feed a schema field's type payload into a digest hasher, mirroring
/// `render_key_type_spec`.
fn digest_type_spec(hasher: &mut blake3::Hasher, spec: &crate::ir::TypeSpec) {
    use crate::ir::TypeSpec as T;
    match spec {
        T::Enum(members) => {
            hasher.update(b"E");
            let mut ordered: Vec<&String> = members.iter().collect();
            ordered.sort();
            digest_u64(hasher, ordered.len() as u64);
            for member in ordered {
                digest_str(hasher, member);
            }
        }
        T::Table { closed } => {
            hasher.update(b"T");
            digest_bool(hasher, *closed);
        }
        other => digest_str(hasher, &format!("{other:?}")),
    }
}

/// The primary ordering key. Kept byte-identical to the pre-tie-break form so
/// existing canonical images keep their bytes.
fn content_key(nodes: &[crate::ir::Inode], id: NodeId) -> Result<String> {
    content_key_with(nodes, id, false)
}

/// An injective render, used only to break ties between equal primary keys.
fn content_key_framed(nodes: &[crate::ir::Inode], id: NodeId) -> Result<String> {
    content_key_with(nodes, id, true)
}

/// Break ties between entries whose primary keys are equal.
///
/// The primary key is not injective (a field name can contain the separators the
/// renderer uses), so ordering tied subjects by arena id would let construction
/// order leak into the canonical bytes. The framed render is injective; the id
/// then only orders subtrees that render identically, which are interchangeable.
fn break_key_ties(
    nodes: &[crate::ir::Inode],
    keys: &[String],
    annotations: &[Annotation],
    entries: &mut [(usize, NodeId)],
    total: &mut usize,
) -> Result<()> {
    let mut start = 0;
    while start < entries.len() {
        let mut end = start + 1;
        while end < entries.len() && keys[entries[end].0] == keys[entries[start].0] {
            end += 1;
        }
        if end - start > 1 {
            // One render per *distinct* subject, not per annotation: a subject
            // annotated a million times is one tie, not a million renders.
            let mut seen = std::collections::HashSet::new();
            let mut framed: std::collections::HashMap<NodeId, String> =
                std::collections::HashMap::new();
            for entry in &entries[start..end] {
                if !seen.insert(entry.1) {
                    continue;
                }
                let mut key = content_key_framed(nodes, entry.1)?;
                // The render is not injective: it folds every secret to one
                // constant, and two subjects that differ only in their
                // annotations render the same. Ordering those by arena id let
                // construction order reach the canonical bytes and the hash
                // (cross-cutting pass 1, #1). The signature adds the redacted
                // annotation multiset and a digest of every secret in the
                // subtree; a digest is order-revealing, not the bytes.
                // Length-prefixed parts: the rendered annotation text can
                // contain any separator, so an unframed join made
                // `Intent("a|i:b")` collide with `Intent("a") + Intent("b")`
                // and the tie fell back to the arena id (pass 2, #2).
                key.push('#');
                for part in annotation_signature(nodes, annotations, entry.1, total)? {
                    key.push_str(&part.len().to_string());
                    key.push(':');
                    key.push_str(&part);
                }
                key.push('#');
                let digests = secret_digests(nodes, entry.1, total)?;
                for digest in digests {
                    key.push_str(&crate::ir::hash_hex(&digest));
                }
                *total = total.saturating_add(key.len());
                if *total > MAX_ANNOTATION_KEY_BYTES {
                    return Err(Error::Limit {
                        kind: "annotation key bytes",
                        limit: MAX_ANNOTATION_KEY_BYTES as u64,
                    });
                }
                framed.insert(entry.1, key);
            }
            if framed.len() > 1 {
                entries[start..end]
                    .sort_by(|a, b| framed[&a.1].cmp(&framed[&b.1]).then_with(|| a.1.cmp(&b.1)));
            }
        }
        start = end;
    }
    Ok(())
}

/// The redacted annotations attached to one root, in a fixed order.
///
/// Two roots that render identically are interchangeable only if everything
/// stored about them is equal too; the annotations are stored per node, so they
/// are part of the identity of the root. A constraint's expression is rendered
/// by content, never by id: the id is remapped by the next encode, and an
/// id-bearing signature would order the same module differently on the second
/// pass (not a fixed point).
fn annotation_signature(
    nodes: &[crate::ir::Inode],
    annotations: &[Annotation],
    id: NodeId,
    total: &mut usize,
) -> Result<Vec<String>> {
    let mut parts: Vec<String> = Vec::new();
    for annotation in annotations
        .iter()
        .filter(|annotation| annotation.node == id)
    {
        let part = match &annotation.kind {
            AnnotationKind::Intent(text) => format!("i:{text}"),
            AnnotationKind::Constraint { source, expr } => {
                let rendered = content_key_framed(nodes, *expr)?;
                *total = total.saturating_add(rendered.len());
                if *total > MAX_ANNOTATION_KEY_BYTES {
                    return Err(Error::Limit {
                        kind: "annotation key bytes",
                        limit: MAX_ANNOTATION_KEY_BYTES as u64,
                    });
                }
                format!("c:{source}:{rendered}")
            }
            AnnotationKind::AiImmutable(flag) => format!("m:{flag}"),
        };
        parts.push(part);
    }
    parts.sort();
    Ok(parts)
}

/// BLAKE3 digests of every secret in a subtree, sorted.
///
/// The content key renders a secret as a constant, so two subjects holding
/// different secrets tie. The digest orders them without putting the bytes into
/// a `String` that would outlive the encoding.
fn secret_digests(
    nodes: &[crate::ir::Inode],
    root: NodeId,
    total: &mut usize,
) -> Result<Vec<[u8; 32]>> {
    let mut out = Vec::new();
    if root.index() >= nodes.len() {
        return Ok(out);
    }
    let mut seen = vec![false; nodes.len()];
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if id.index() >= nodes.len() || seen[id.index()] {
            continue;
        }
        seen[id.index()] = true;
        // The walk and each hash are work too: a tie group of many large
        // subtrees would otherwise hash for free (pass 2, #5).
        *total = total.saturating_add(1);
        if let Inode::Secret(secret) = &nodes[id.index()] {
            *total = total.saturating_add(32);
            out.push(*blake3::hash(secret.expose()).as_bytes());
        }
        if *total > MAX_ANNOTATION_KEY_BYTES {
            return Err(Error::Limit {
                kind: "annotation key bytes",
                limit: MAX_ANNOTATION_KEY_BYTES as u64,
            });
        }
        stack.extend(nodes[id.index()].children());
    }
    out.sort();
    Ok(out)
}

/// Deterministic pre-order numbering over the reachable graph.
///
/// The roots are the module root, the bindings in name order, and the annotation
/// subjects and constraint expressions in content order. Ordering any of them by
/// numeric id (or by the order they were added) would let arena construction and
/// `annotate` call order leak into the canonical bytes: two modules with the same
/// content would hash differently.
fn canonical_order(
    nodes: &[Inode],
    module: &InfinityModule,
    annotations: &[Annotation],
) -> Result<Vec<NodeId>> {
    let mut roots: Vec<NodeId> = Vec::new();
    if let Some(root) = module.root() {
        roots.push(root);
    }
    let mut bindings: Vec<&(String, NodeId)> = module.bindings().iter().collect();
    bindings.sort_by(|a, b| a.0.cmp(&b.0));
    roots.extend(bindings.into_iter().map(|(_, id)| *id));
    // An annotation subject may be a node nothing else reaches, so its position
    // in the annotation list is the only thing that could order it. Order by the
    // subtree's content instead; equal keys mean interchangeable subtrees.
    let mut keys: Vec<String> = Vec::new();
    let mut index: HashMap<NodeId, usize> = HashMap::new();
    let mut total = 0usize;
    let mut subjects: Vec<(usize, NodeId)> = annotations
        .iter()
        .map(|annotation| {
            Ok((
                key_index(nodes, annotation.node, &mut keys, &mut index, &mut total)?,
                annotation.node,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    // Same order as sorting the `(key, id)` pairs: key bytes, then the id.
    subjects.sort_by(|a, b| keys[a.0].cmp(&keys[b.0]).then_with(|| a.1.cmp(&b.1)));
    break_key_ties(nodes, &keys, annotations, &mut subjects, &mut total)?;
    roots.extend(subjects.into_iter().map(|(_, id)| id));
    let mut exprs: Vec<(usize, NodeId)> = annotations
        .iter()
        .filter_map(|annotation| match &annotation.kind {
            AnnotationKind::Constraint { expr, .. } => Some(*expr),
            _ => None,
        })
        .map(|expr| {
            Ok((
                key_index(nodes, expr, &mut keys, &mut index, &mut total)?,
                expr,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    exprs.sort_by(|a, b| keys[a.0].cmp(&keys[b.0]).then_with(|| a.1.cmp(&b.1)));
    break_key_ties(nodes, &keys, annotations, &mut exprs, &mut total)?;
    roots.extend(exprs.into_iter().map(|(_, id)| id));

    let mut order = Vec::with_capacity(nodes.len());
    let mut seen = vec![false; nodes.len()];
    for root in roots {
        if root.index() >= nodes.len() {
            return Err(Error::EncodeDangling(root.0));
        }
        // Iterative pre-order: push children reversed so the first child is
        // visited first.
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if seen[id.index()] {
                continue;
            }
            seen[id.index()] = true;
            order.push(id);
            let children = nodes[id.index()].children();
            for child in children.into_iter().rev() {
                if child.index() >= nodes.len() {
                    return Err(Error::EncodeDangling(child.0));
                }
                if !seen[child.index()] {
                    stack.push(child);
                }
            }
        }
    }
    Ok(order)
}

fn type_payload(
    spec: &SchemaFieldSpec,
    strings: &HashMap<String, u32>,
) -> Result<(u32, Vec<(u32, u32)>)> {
    let lookup = |text: &str| -> Result<u32> {
        strings
            .get(text)
            .copied()
            .ok_or(Error::Encode("schema type references an uninterned string"))
    };
    let mut aux = Vec::new();
    match &spec.typ {
        TypeSpec::Enum(items) => {
            if items.is_empty() {
                return Err(Error::Encode("enum type without members"));
            }
            // An enum is a set of members: sort before interning so two modules
            // that differ only in member order produce one type table (and one
            // content hash). The IR keeps the author's order; the canonical form
            // does not.
            let mut ordered: Vec<&String> = items.iter().collect();
            ordered.sort();
            for item in ordered {
                aux.push((crate::layout::AUX_TYPE_ENUM_ITEM, lookup(item)?));
            }
        }
        TypeSpec::Table { closed } => {
            aux.push((crate::layout::AUX_TYPE_TABLE, u32::from(*closed)));
        }
        _ => {}
    }
    Ok((spec.typ.code(), aux))
}

fn type_from_prepared(code: u32, aux: &[(u32, u32)], strings: &[String]) -> Result<TypeSpec> {
    let string = |id: u32| -> Result<String> {
        strings
            .get(id as usize)
            .cloned()
            .ok_or(Error::StringRef(id))
    };
    let spec = match code {
        0 => TypeSpec::Null,
        1 => TypeSpec::Bool,
        2 => TypeSpec::Int,
        3 => TypeSpec::Float,
        4 => TypeSpec::String,
        5 => TypeSpec::Duration,
        6 => TypeSpec::Bytes,
        7 => {
            let closed = aux
                .iter()
                .find(|(tag, _)| *tag == crate::layout::AUX_TYPE_TABLE)
                .map(|(_, value)| *value != 0)
                .unwrap_or(false);
            TypeSpec::Table { closed }
        }
        8 => {
            let mut items = Vec::new();
            for (tag, value) in aux {
                if *tag == crate::layout::AUX_TYPE_ENUM_ITEM {
                    items.push(string(*value)?);
                }
            }
            TypeSpec::Enum(items)
        }
        9 => TypeSpec::Secret,
        10 => TypeSpec::Any,
        11 => TypeSpec::Blob,
        _ => return Err(Error::Encode("unknown type discriminant")),
    };
    Ok(spec)
}

fn sorted_annotations(
    mut annotations: Vec<Annotation>,
    strings: &HashMap<String, u32>,
) -> Vec<Annotation> {
    // Compare by reference: cloning the intent/source text per comparison made
    // the sort O(n log n x text) and was not bounded by any budget.
    fn rank(annotation: &Annotation) -> u8 {
        match &annotation.kind {
            AnnotationKind::Intent(_) => 0,
            AnnotationKind::Constraint { .. } => 1,
            AnnotationKind::AiImmutable(_) => 2,
        }
    }
    fn text_of(annotation: &Annotation) -> &str {
        match &annotation.kind {
            AnnotationKind::Intent(text) => text.as_str(),
            AnnotationKind::Constraint { source, .. } => source.as_str(),
            AnnotationKind::AiImmutable(_) => "",
        }
    }
    fn expr_of(annotation: &Annotation) -> u32 {
        match &annotation.kind {
            AnnotationKind::Constraint { expr, .. } => expr.0,
            AnnotationKind::AiImmutable(flag) => u32::from(*flag),
            AnnotationKind::Intent(_) => 0,
        }
    }
    annotations.sort_by(|a, b| {
        a.node
            .0
            .cmp(&b.node.0)
            .then_with(|| rank(a).cmp(&rank(b)))
            .then_with(|| text_of(a).cmp(text_of(b)))
            .then_with(|| expr_of(a).cmp(&expr_of(b)))
    });
    annotations.dedup_by(|a, b| {
        a.node == b.node
            && match (&a.kind, &b.kind) {
                (AnnotationKind::Intent(x), AnnotationKind::Intent(y)) => x == y,
                (
                    AnnotationKind::Constraint {
                        source: s1,
                        expr: e1,
                    },
                    AnnotationKind::Constraint {
                        source: s2,
                        expr: e2,
                    },
                ) => s1 == s2 && e1 == e2,
                (AnnotationKind::AiImmutable(x), AnnotationKind::AiImmutable(y)) => x == y,
                _ => false,
            }
    });
    let _ = strings;
    annotations
}

fn sorted_provenance(mut prov: Provenance) -> Result<Provenance> {
    prov.entries.sort_by(|a, b| {
        (a.key.as_str(), prov_kind_rank(&a.value)).cmp(&(b.key.as_str(), prov_kind_rank(&b.value)))
    });
    // Redaction can map two keys onto the marker. Provenance is a map, and the
    // validator refuses duplicate keys, so an image with two entries for one key
    // can never be valid: refuse instead of silently dropping one.
    for window in prov.entries.windows(2) {
        if window[0].key == window[1].key {
            return Err(crate::error::Error::Encode(
                "provenance keys collide after redaction; use distinct keys",
            ));
        }
    }
    Ok(prov)
}
fn prov_kind_rank(value: &ProvValue) -> u32 {
    match value {
        ProvValue::Text(_) => 0,
        ProvValue::Int(_) => 1,
        ProvValue::Flag(_) => 2,
        ProvValue::Hash(_) => 3,
    }
}

#[cfg(test)]
mod redaction_cost_tests {
    use super::{redaction_cost, MAX_REDACTION_SCAN_BYTES};

    /// An empty string is not free to scan: every redaction still walks the
    /// secret table once per pass. Charging zero let 10k empty annotations
    /// against 10k secrets spend eight seconds of release CPU in one encode.
    #[test]
    fn an_empty_text_is_charged_one_pass_per_secret() {
        let secrets: Vec<String> = (0..1_000).map(|index| format!("s{index}")).collect();
        let cost = redaction_cost("", &secrets);
        assert_eq!(cost, secrets.len() * 8);
        assert!(cost <= MAX_REDACTION_SCAN_BYTES);
    }
}
