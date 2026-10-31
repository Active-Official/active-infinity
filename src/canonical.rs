//! Canonicalization: the deterministic normal form of a module.
//!
//! Two modules that are logically equal must produce identical bytes and an
//! identical content hash, no matter how they were built. Canonicalization
//! therefore does all of the following, in one pass, before a single byte is
//! written:
//!
//! 1. drops nodes unreachable from the module roots (root, bindings,
//!    annotation subjects and their constraint expressions) — an image can
//!    never hide data in an unreferenced node;
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

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::ir::{
    Annotation, AnnotationKind, Constraint, InfinityModule, Inode, InterpPart, NodeId, PatchOp,
    ProvValue, Provenance, SchemaFieldSpec, TypeSpec,
};
use crate::layout::canonical_f64;
use crate::unit::UnitTag;

/// Deduplication key for a type table entry: code plus its aux payload.
pub(crate) type TypeKey = (u32, Vec<(u32, u32)>);

/// Deduplication key for a blob entry: identity plus payload.
pub(crate) type BlobKey = ([u8; 32], u64, Option<Vec<u8>>);

/// A blob payload prepared for the content-addressed heap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlobPayload {
    pub hash: [u8; 32],
    pub size: u64,
    pub payload: Option<Vec<u8>>,
}

/// One prepared type-table entry with its aux payload (enum members).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PreparedType {
    pub spec: TypeSpec,
    pub aux: Vec<(u32, u32)>,
}

/// Fully canonical, index-resolved module ready for byte emission.
#[derive(Debug, Clone, Default)]
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
    pub secrets: Vec<Vec<u8>>,
    pub extensions: Vec<(u64, Vec<u8>)>,
    pub string_index: HashMap<String, u32>,
    pub unit_index: HashMap<UnitTag, u32>,
    pub type_index: HashMap<TypeKey, u32>,
    pub blob_index: HashMap<BlobKey, u32>,
    pub hash_index: HashMap<[u8; 32], u32>,
    pub number_index: HashMap<i64, u32>,
}

/// True when `value` is the one NaN bit pattern the format permits.
pub(crate) fn is_canonical_nan(value: f64) -> bool {
    value.to_bits() == crate::layout::CANONICAL_NAN_BITS
}

/// Canonicalize `module` into an index-resolved [`Prepared`] module.
pub(crate) fn prepare(module: &InfinityModule) -> Result<Prepared> {
    module.validate_structure(u32::MAX as u64, 0)?;

    // 1. Normalize node contents in place (field order, float bits).
    let canonical_nodes: Vec<Inode> = module.nodes().iter().map(normalize).collect();

    // 1b. Promote secret locators out of the public string heap.
    //
    // `active-core` models `secret("literal")` as a `Secret { locator }` node
    // whose locator is an ordinary string literal. Left alone, that literal
    // would land in the string heap and a naive `strings module.ainf` would
    // read it back. A literal string that is referenced *only* by secret nodes
    // and not exposed as a root is therefore re-encoded as a structural secret:
    // the bytes move to the secret heap, which no projection enumerates.
    let canonical_nodes = promote_secret_locators(canonical_nodes, module);

    // Secret material that must not survive inside free text metadata. Read it
    // before the nodes are consumed by the renumbering pass below.
    let secret_literals: Vec<String> = canonical_nodes
        .iter()
        .filter_map(|node| match node {
            Inode::Secret(secret) => Some(String::from_utf8_lossy(secret.expose()).into_owned()),
            _ => None,
        })
        .collect();

    // 2. Pre-order numbering from the roots.
    let order = canonical_order(&canonical_nodes, module)?;
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
    let nodes = nodes;

    let root = module.root().map(|id| remap[id.index()]);
    let mut bindings: Vec<(String, NodeId)> = module
        .bindings()
        .iter()
        .map(|(name, id)| (name.clone(), remap[id.index()]))
        .collect();
    bindings.sort_by(|a, b| a.0.cmp(&b.0));

    let annotations: Vec<Annotation> = module
        .annotations()
        .iter()
        .map(|annotation| {
            let node = remap[annotation.node.index()];
            let kind = match &annotation.kind {
                AnnotationKind::Intent(text) => {
                    AnnotationKind::Intent(redact_text(text, &secret_literals))
                }
                AnnotationKind::Constraint { source, expr } => AnnotationKind::Constraint {
                    source: redact_text(source, &secret_literals),
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
        .map(|prov| redact_provenance(prov, &secret_literals))
        .transpose()?;
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
        let spec = type_from_prepared(*code, aux, &strings)?;
        types.push(PreparedType {
            spec,
            aux: aux.clone(),
        });
        type_index.insert((*code, aux.clone()), index as u32);
    }

    // Blobs: deduplicate by identity+payload, ordered by hash then size.
    let mut blobs: Vec<BlobPayload> = Vec::new();
    for node in &nodes {
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
            blobs.push(BlobPayload {
                hash: *hash,
                size: *size,
                payload: if *tainted { None } else { payload.clone() },
            });
        }
    }
    blobs.sort_by_key(|blob| (blob.hash, blob.size));
    blobs.dedup();
    let blob_index: HashMap<BlobKey, u32> = blobs
        .iter()
        .enumerate()
        .map(|(index, blob)| ((blob.hash, blob.size, blob.payload.clone()), index as u32))
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

    // Secrets: node order, never deduplicated.
    let secrets: Vec<Vec<u8>> = nodes
        .iter()
        .filter_map(|node| match node {
            Inode::Secret(secret) => Some(secret.expose().to_vec()),
            _ => None,
        })
        .collect();

    // Extensions: sorted by tag, unique tags, payloads preserved verbatim.
    let mut extensions: Vec<(u64, Vec<u8>)> = module.extensions().to_vec();
    extensions.sort_by_key(|(tag, _)| *tag);
    for window in extensions.windows(2) {
        if window[0].0 == window[1].0 {
            return Err(Error::Encode("duplicate extension tag"));
        }
    }

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
        secrets,
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
        } => Inode::Constrained {
            target: *target,
            constraint: Constraint::Enum(items.clone()),
        },
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
pub(crate) fn redact_text(text: &str, secrets: &[String]) -> String {
    let marker_tainted = secrets
        .iter()
        .any(|secret| !secret.is_empty() && SECRET_MARKER.contains(secret.as_str()));
    let mut out = text.to_string();
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
            return out;
        }
        if marker_tainted {
            return SECRET_MARKER.to_string();
        }
        // Longest first, then lexicographic: the result does not depend on the
        // order of the secret table.
        matched.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        for secret in matched {
            out = out.replace(secret.as_str(), SECRET_MARKER);
        }
    }
    SECRET_MARKER.to_string()
}

fn redact_provenance(mut prov: Provenance, secrets: &[String]) -> Result<Provenance> {
    if secrets.is_empty() {
        return Ok(prov);
    }
    prov.producer = prov.producer.map(|text| redact_text(&text, secrets));
    prov.model = prov.model.map(|text| redact_text(&text, secrets));
    prov.tool = prov.tool.map(|text| redact_text(&text, secrets));
    for entry in &mut prov.entries {
        // Keys live in the string heap too: a copy there would be stored in the
        // image even though the projections hide it.
        entry.key = redact_text(&entry.key, secrets);
        if let ProvValue::Text(text) = &entry.value {
            entry.value = ProvValue::Text(redact_text(text, secrets));
        }
    }
    Ok(prov)
}

fn normalize_type(typ: &TypeSpec) -> TypeSpec {
    typ.clone()
}

/// Move secret-only string literals into the secret heap (see step 1b above).
fn promote_secret_locators(mut nodes: Vec<Inode>, module: &InfinityModule) -> Vec<Inode> {
    if nodes.is_empty() {
        return nodes;
    }
    let mut exposed = vec![false; nodes.len()];
    let mut mark = |id: NodeId| {
        if let Some(slot) = exposed.get_mut(id.index()) {
            *slot = true;
        }
    };
    if let Some(root) = module.root() {
        mark(root);
    }
    for (_, id) in module.bindings() {
        mark(*id);
    }
    for annotation in module.annotations() {
        mark(annotation.node);
        if let AnnotationKind::Constraint { expr, .. } = &annotation.kind {
            mark(*expr);
        }
    }
    // A string is secret-only when every one of its dependents is a secret
    // node and it is not itself a root.
    let mut secret_only = vec![true; nodes.len()];
    let mut referenced = vec![false; nodes.len()];
    for node in &nodes {
        for child in node.children() {
            let Some(slot) = secret_only.get_mut(child.index()) else {
                continue;
            };
            referenced[child.index()] = true;
            if !node.is_secret() {
                *slot = false;
            }
        }
    }
    for (index, node) in nodes.iter_mut().enumerate() {
        let eligible = referenced[index] && secret_only[index] && !exposed[index];
        if !eligible {
            continue;
        }
        if let Inode::Str(text) = node {
            // Only promote when the literal actually looks like secret
            // material; a secret node pointing at an empty or trivially short
            // literal is still promoted, because structure is the signal.
            *node = Inode::Secret(crate::ir::SecretBytes::from(text.clone()));
        }
    }
    nodes
}

pub(crate) fn remap_node(node: &Inode, remap: &[NodeId]) -> Result<Inode> {
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
        other => other.clone(),
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
        _ => {}
    }
    Ok(())
}

/// Deterministic pre-order numbering over the reachable graph.
fn canonical_order(nodes: &[Inode], module: &InfinityModule) -> Result<Vec<NodeId>> {
    let mut roots = Vec::new();
    if let Some(root) = module.root() {
        roots.push(root);
    }
    let mut bindings: Vec<NodeId> = module.bindings().iter().map(|(_, id)| *id).collect();
    bindings.sort_by_key(|id| id.0);
    roots.extend(bindings);
    let mut subjects: Vec<NodeId> = module.annotations().iter().map(|a| a.node).collect();
    subjects.sort_by_key(|id| id.0);
    roots.extend(subjects);
    let mut exprs: Vec<NodeId> = module
        .annotations()
        .iter()
        .filter_map(|a| match &a.kind {
            AnnotationKind::Constraint { expr, .. } => Some(*expr),
            _ => None,
        })
        .collect();
    exprs.sort_by_key(|id| id.0);
    roots.extend(exprs);

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
            for item in items {
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
    annotations.sort_by(|a, b| {
        let key = |annotation: &Annotation| -> (u32, u32, String, u32) {
            match &annotation.kind {
                AnnotationKind::Intent(text) => (annotation.node.0, 0, text.clone(), 0),
                AnnotationKind::Constraint { source, expr } => {
                    (annotation.node.0, 1, source.clone(), expr.0)
                }
                AnnotationKind::AiImmutable(flag) => {
                    (annotation.node.0, 2, String::new(), u32::from(*flag))
                }
            }
        };
        key(a).cmp(&key(b))
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
