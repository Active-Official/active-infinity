//! Decoder: `AINF` bytes → canonical [`InfinityModule`].
//!
//! Decoding never runs on unvalidated bytes: [`decode`] validates first and
//! returns a [`crate::validate::Validated`] internally, so a decoded module is
//! guaranteed to satisfy every structural invariant (bounds, sorted tables,
//! acyclicity, reachability, hash). Materialisation is a straightforward
//! translation of validated records into the owned IR; the zero-copy path
//! lives in [`crate::view`] for callers that do not need ownership.

// Module-level: item docs for this layer live in docs/spec/layout.md and
// docs/spec/streaming.md; the crate root keeps deny(missing_docs) for the
// hand-written public surface.
#![allow(missing_docs)]

use crate::error::{Error, Result};
use crate::ir::{
    Annotation, AnnotationKind, Constraint, InfinityModule, Inode, InterpPart, NodeId, PatchOp,
    ProvEntry, ProvValue, Provenance, SchemaFieldSpec, TypeSpec,
};
use crate::layout::{DecodeOpts, ANN_KIND_AI_IMMUTABLE, ANN_KIND_CONSTRAINT, ANN_KIND_INTENT};
use crate::validate::Validated;

/// Decode with default options (hash verified, canonical form proved --
/// INF-02). Use `decode_with(bytes, DecodeOpts { verify_canonical: false,
/// ..Default::default() })` for the lenient path on trusted or migration
/// input: the hash is still verified, only the canonical-form proof is
/// skipped.
pub fn decode(bytes: &[u8]) -> Result<InfinityModule> {
    decode_with(bytes, DecodeOpts::default())
}

/// Decode with explicit options.
pub fn decode_with(bytes: &[u8], opts: DecodeOpts) -> Result<InfinityModule> {
    let validated = Validated::new(bytes, opts)?;
    decode_validated(&validated)
}

/// Materialise an already validated image.
pub fn decode_validated(validated: &Validated<'_>) -> Result<InfinityModule> {
    check_decoded_budget(validated)?;
    let count = validated.node_count();
    let mut nodes = Vec::with_capacity(count as usize);
    for index in 0..count {
        nodes.push(decode_node(validated, NodeId(index))?);
    }
    let root = validated.root()?;
    let bindings: Vec<(String, NodeId)> = validated
        .bindings()?
        .into_iter()
        .map(|(name, id)| (name.to_string(), id))
        .collect();

    let mut annotations =
        Vec::with_capacity(validated.span(crate::layout::Section::Annotations).count as usize);
    for index in 0..validated.span(crate::layout::Section::Annotations).count {
        let (node, kind, a, b) = validated.annotation(index)?;
        let kind = match kind {
            ANN_KIND_INTENT => AnnotationKind::Intent(validated.string(a)?.to_string()),
            ANN_KIND_CONSTRAINT => AnnotationKind::Constraint {
                source: validated.string(a)?.to_string(),
                expr: NodeId(b),
            },
            ANN_KIND_AI_IMMUTABLE => AnnotationKind::AiImmutable(a == 1),
            _ => {
                return Err(Error::Annotation {
                    id: index,
                    reason: "unknown annotation kind",
                })
            }
        };
        annotations.push(Annotation {
            node: NodeId(node),
            kind,
        });
    }

    let provenance = validated.provenance()?;
    let mut module = InfinityModule::from_parts(nodes, root, bindings, annotations, provenance);
    module.set_extensions(decode_extensions(validated)?);
    // Keep the depth budget the wire pass enforced: passing 0 here would let a
    // deep materialised module escape the ceiling downstream.
    module.validate_structure(
        validated.limits_snapshot().max_nodes as u64,
        validated.limits_snapshot().max_depth,
    )?;
    Ok(module)
}

/// Refuse an image whose decoded form would exceed
/// `Limits::max_decoded_bytes` (INF-01, R2-INF-DEC-01).
///
/// Every byte `decode_validated` is about to clone as owned data is charged
/// here, per use, before any cloning happens: a string referenced by N nodes
/// is charged N times, a blob payload once per `Blob` node that carries it,
/// a named unit once per `Quantity` node, a type-enum member once per
/// `SchemaField` that names the type (the type table is an indirection the
/// per-string count cannot see — the member string is directly referenced
/// exactly once, by the interned type entry, while decode clones it once
/// per referencing node). Annotation strings, binding names, extension
/// payloads and provenance strings are charged the same way. The running
/// total uses checked `u64` arithmetic and trips the budget the moment it
/// exceeds it, so the pre-pass itself allocates nothing but the per-type
/// member table (bounded by `max_types` entries) and refuses before the
/// clone loop runs. An image that passes has decoded output bounded by the
/// ceiling plus the node arena (`max_nodes` entries); `validate()` and the
/// zero-copy `view` path do not call this and are unaffected.
fn check_decoded_budget(validated: &Validated<'_>) -> Result<()> {
    let budget = validated.limits_snapshot().max_decoded_bytes;
    let mut total: u64 = 0;
    let charge = |total: &mut u64, bytes: u64| -> Result<()> {
        *total = total.checked_add(bytes).ok_or(Error::Limit {
            kind: "decoded bytes",
            limit: budget,
        })?;
        if *total > budget {
            return Err(Error::Limit {
                kind: "decoded bytes",
                limit: budget,
            });
        }
        Ok(())
    };
    // Materialised bytes of each type entry's enum members, computed once
    // per type (not once per referencing node): only code 8 (`Enum`) clones
    // strings, and only its `AUX_TYPE_ENUM_ITEM` aux records do. The sum is
    // saturated, not budget-checked, here: it is only a per-type figure, and
    // the budget trips when a `SchemaField` actually charges it below.
    let type_count = validated.span(crate::layout::Section::Types).count as usize;
    let mut type_cost: Vec<u64> = Vec::with_capacity(type_count);
    for index in 0..type_count {
        let (code, _flags, start, len) = validated.type_entry(index as u32)?;
        let mut cost: u64 = 0;
        if code == 8 {
            for offset in start..start + len {
                let (tag, value) = validated.aux(offset)?;
                if tag == crate::layout::AUX_TYPE_ENUM_ITEM {
                    cost = cost.saturating_add(validated.string(value)?.len() as u64);
                }
            }
        }
        type_cost.push(cost);
    }
    let count = validated.node_count();
    for index in 0..count {
        let id = NodeId(index);
        let rec = validated.node(id)?;
        match rec.kind {
            4 => charge(&mut total, validated.string(rec.aux)?.len() as u64)?,
            6 => charge(&mut total, validated.unit_name_len(rec.a as u32)?)?,
            8 | 20 => {
                for offset in rec.a..rec.a + rec.b {
                    let (name, _node) = validated.field(offset as u32)?;
                    charge(&mut total, validated.string(name)?.len() as u64)?;
                }
            }
            9 => charge(&mut total, validated.secret(rec.a as u32)?.len() as u64)?,
            12 | 13 => charge(&mut total, validated.string(rec.aux)?.len() as u64)?,
            14 => {
                for offset in rec.a..rec.a + rec.b {
                    let (tag, value) = validated.part(offset as u32)?;
                    if tag == crate::layout::PART_LITERAL {
                        charge(&mut total, validated.string(value)?.len() as u64)?;
                    }
                }
            }
            17 => {
                for offset in rec.b as u32..rec.b as u32 + rec.c as u32 {
                    let (tag, value) = validated.aux(offset)?;
                    if tag == crate::layout::AUX_CONSTRAINT_ENUM_ITEM
                        || tag == crate::layout::AUX_CONSTRAINT_PATTERN
                        || tag == crate::layout::AUX_CONSTRAINT_CUSTOM
                    {
                        charge(&mut total, validated.string(value)?.len() as u64)?;
                    }
                }
            }
            18 => {
                for offset in rec.b as u32..rec.b as u32 + rec.c as u32 {
                    let (tag, value) = validated.aux(offset)?;
                    if tag == crate::layout::AUX_PATCH_PATH
                        || tag == crate::layout::AUX_PATCH_RENAME_TO
                    {
                        charge(&mut total, validated.string(value)?.len() as u64)?;
                    }
                }
            }
            19 => {
                charge(
                    &mut total,
                    type_cost.get(rec.aux as usize).copied().unwrap_or(0),
                )?;
                for offset in rec.b as u32..rec.b as u32 + rec.c as u32 {
                    let (tag, value) = validated.aux(offset)?;
                    if tag == crate::layout::AUX_SCHEMA_DEPRECATED {
                        charge(&mut total, validated.string(value)?.len() as u64)?;
                    }
                }
            }
            23 => {
                charge(&mut total, validated.string(rec.aux)?.len() as u64)?;
                if rec.flags & crate::layout::NODE_FLAG_1 != 0 {
                    charge(&mut total, validated.blob(rec.a as u32)?.len() as u64)?;
                }
            }
            _ => {}
        }
    }
    for index in 0..validated.span(crate::layout::Section::Annotations).count {
        let (_node, kind, a, _b) = validated.annotation(index)?;
        if kind == ANN_KIND_INTENT || kind == ANN_KIND_CONSTRAINT {
            charge(&mut total, validated.string(a)?.len() as u64)?;
        }
    }
    for (name, _id) in validated.bindings()? {
        charge(&mut total, name.len() as u64)?;
    }
    charge(&mut total, validated.provenance_string_bytes()?)?;
    for index in 0..validated.span(crate::layout::Section::Extensions).count {
        let (_tag, _offset, len) = validated.extension_entry(index)?;
        charge(&mut total, len as u64)?;
    }
    Ok(())
}

/// Read the extension directory and its payloads back into the module.
fn decode_extensions(validated: &Validated<'_>) -> Result<Vec<(u64, Vec<u8>)>> {
    let count = validated.span(crate::layout::Section::Extensions).count;
    let mut out = Vec::with_capacity(count as usize);
    for index in 0..count {
        let (tag, offset, len) = validated.extension_entry(index)?;
        out.push((tag, validated.extension_payload(offset, len)?.to_vec()));
    }
    Ok(out)
}

fn decode_node(validated: &Validated<'_>, id: NodeId) -> Result<Inode> {
    let rec = validated.node(id)?;
    let node = match rec.kind {
        0 => Inode::Null,
        1 => Inode::Bool(rec.a == 1),
        2 => Inode::Int(rec.a as i64),
        3 => Inode::Float(f64::from_bits(rec.a)),
        4 => Inode::Str(validated.string(rec.aux)?.to_string()),
        5 => Inode::DurationMs(rec.a),
        6 => Inode::Quantity {
            value: NodeId(rec.aux),
            unit: validated.unit(rec.a as u32)?,
        },
        7 => {
            let mut elements = Vec::with_capacity(rec.b as usize);
            for offset in rec.a..rec.a + rec.b {
                elements.push(NodeId(validated.child(offset as u32)?));
            }
            Inode::Array { elements }
        }
        8 => {
            let mut fields = Vec::with_capacity(rec.b as usize);
            for offset in rec.a..rec.a + rec.b {
                let (name, node) = validated.field(offset as u32)?;
                fields.push((validated.string(name)?.to_string(), node));
            }
            Inode::Table { fields }
        }
        9 => Inode::Secret(crate::ir::SecretBytes::new(
            validated.secret(rec.a as u32)?.to_vec(),
        )),
        10 => Inode::SecretRef {
            locator: NodeId(rec.a as u32),
        },
        11 => Inode::Ref(NodeId(rec.a as u32)),
        12 => Inode::Env {
            name: validated.string(rec.aux)?.to_string(),
            default: if rec.a == u32::MAX as u64 {
                None
            } else {
                Some(NodeId(rec.a as u32))
            },
        },
        13 => Inode::Ident(validated.string(rec.aux)?.to_string()),
        14 => {
            let mut parts = Vec::with_capacity(rec.b as usize);
            for offset in rec.a..rec.a + rec.b {
                let (tag, value) = validated.part(offset as u32)?;
                parts.push(match tag {
                    crate::layout::PART_LITERAL => {
                        InterpPart::Literal(validated.string(value)?.to_string())
                    }
                    _ => InterpPart::Expr(NodeId(value)),
                });
            }
            Inode::Interpolate { parts }
        }
        15 => Inode::Binary {
            op: crate::ir::BinOp::from_code(rec.aux).ok_or(Error::Node {
                id: id.0,
                reason: "unknown binary operator",
            })?,
            lhs: NodeId(rec.a as u32),
            rhs: NodeId(rec.b as u32),
        },
        16 => Inode::Unary {
            op: crate::ir::UnOp::from_code(rec.aux).ok_or(Error::Node {
                id: id.0,
                reason: "unknown unary operator",
            })?,
            expr: NodeId(rec.a as u32),
        },
        17 => Inode::Constrained {
            target: NodeId(rec.a as u32),
            constraint: decode_constraint(validated, id, rec.aux, rec.b as u32, rec.c as u32)?,
        },
        18 => Inode::Patch(decode_patch(
            validated,
            id,
            rec.aux,
            rec.b as u32,
            rec.c as u32,
        )?),
        19 => Inode::SchemaField(decode_schema_field(
            validated,
            id,
            rec.aux,
            rec.b as u32,
            rec.c as u32,
        )?),
        20 => {
            let mut fields = Vec::with_capacity(rec.b as usize);
            for offset in rec.a..rec.a + rec.b {
                let (name, node) = validated.field(offset as u32)?;
                fields.push((validated.string(name)?.to_string(), node));
            }
            Inode::SchemaTable {
                fields,
                closed: rec.flags & crate::layout::NODE_FLAG_0 != 0,
            }
        }
        21 => Inode::SchemaArray {
            element: NodeId(rec.a as u32),
        },
        22 => Inode::Semantic {
            tag: crate::ir::SemanticTag::from_code(rec.aux).ok_or(Error::Node {
                id: id.0,
                reason: "unknown semantic tag",
            })?,
            inner: NodeId(rec.a as u32),
        },
        23 => {
            let (hash, _, _) = validated.blob_entry(rec.a as u32)?;
            let payload = if rec.flags & crate::layout::NODE_FLAG_1 != 0 {
                Some(validated.blob(rec.a as u32)?.to_vec())
            } else {
                None
            };
            Inode::Blob {
                hash,
                size: rec.b,
                tainted: rec.flags & crate::layout::NODE_FLAG_0 != 0,
                media_type: validated.string(rec.aux)?.to_string(),
                payload,
            }
        }
        24 => Inode::ContentAddressed {
            media_type: NodeId(rec.a as u32),
            data: NodeId(rec.b as u32),
        },
        _ => {
            return Err(Error::Node {
                id: id.0,
                reason: "unknown node kind",
            })
        }
    };
    Ok(node)
}

fn decode_constraint(
    validated: &Validated<'_>,
    id: NodeId,
    kind: u32,
    start: u32,
    len: u32,
) -> Result<Constraint> {
    let mut min = None;
    let mut max = None;
    let mut items = Vec::new();
    let mut pattern = None;
    let mut custom = None;
    for offset in start..start + len {
        let (tag, value) = validated.aux(offset)?;
        match tag {
            crate::layout::AUX_CONSTRAINT_MIN => min = Some(validated.number(value)?),
            crate::layout::AUX_CONSTRAINT_MAX => max = Some(validated.number(value)?),
            crate::layout::AUX_CONSTRAINT_ENUM_ITEM => {
                items.push(validated.string(value)?.to_string())
            }
            crate::layout::AUX_CONSTRAINT_PATTERN => {
                pattern = Some(validated.string(value)?.to_string())
            }
            crate::layout::AUX_CONSTRAINT_CUSTOM => {
                custom = Some(validated.string(value)?.to_string())
            }
            _ => {
                return Err(Error::Node {
                    id: id.0,
                    reason: "unknown constraint aux tag",
                })
            }
        }
    }
    let constraint = match kind {
        crate::layout::CONSTRAINT_KIND_MIN_MAX => Constraint::MinMax { min, max },
        crate::layout::CONSTRAINT_KIND_ENUM => Constraint::Enum(items),
        crate::layout::CONSTRAINT_KIND_PATTERN => {
            Constraint::Pattern(pattern.ok_or(Error::Node {
                id: id.0,
                reason: "pattern constraint without a pattern",
            })?)
        }
        crate::layout::CONSTRAINT_KIND_ODD => Constraint::Odd,
        crate::layout::CONSTRAINT_KIND_CUSTOM => Constraint::Custom(custom.ok_or(Error::Node {
            id: id.0,
            reason: "custom constraint without a payload",
        })?),
        _ => {
            return Err(Error::Node {
                id: id.0,
                reason: "unknown constraint kind",
            })
        }
    };
    Ok(constraint)
}

fn decode_patch(
    validated: &Validated<'_>,
    id: NodeId,
    kind: u32,
    start: u32,
    len: u32,
) -> Result<PatchOp> {
    let mut path = None;
    let mut value = None;
    let mut to = None;
    for offset in start..start + len {
        let (tag, item) = validated.aux(offset)?;
        match tag {
            crate::layout::AUX_PATCH_PATH => path = Some(validated.string(item)?.to_string()),
            crate::layout::AUX_PATCH_VALUE => value = Some(NodeId(item)),
            crate::layout::AUX_PATCH_RENAME_TO => to = Some(validated.string(item)?.to_string()),
            _ => {
                return Err(Error::Node {
                    id: id.0,
                    reason: "unknown patch aux tag",
                })
            }
        }
    }
    let path = path.ok_or(Error::Node {
        id: id.0,
        reason: "patch without a path",
    })?;
    let op = match kind {
        crate::layout::PATCH_KIND_SET => PatchOp::Set {
            path,
            value: value.ok_or(Error::Node {
                id: id.0,
                reason: "set patch without a value",
            })?,
        },
        crate::layout::PATCH_KIND_REMOVE => PatchOp::Remove { path },
        crate::layout::PATCH_KIND_RENAME => PatchOp::Rename {
            from: path,
            to: to.ok_or(Error::Node {
                id: id.0,
                reason: "rename patch without a destination",
            })?,
        },
        _ => {
            return Err(Error::Node {
                id: id.0,
                reason: "unknown patch kind",
            })
        }
    };
    Ok(op)
}

fn decode_schema_field(
    validated: &Validated<'_>,
    id: NodeId,
    type_id: u32,
    start: u32,
    len: u32,
) -> Result<SchemaFieldSpec> {
    let typ = decode_type(validated, type_id)?;
    let mut spec = SchemaFieldSpec::bare(typ);
    for offset in start..start + len {
        let (tag, value) = validated.aux(offset)?;
        match tag {
            crate::layout::AUX_SCHEMA_MIN => spec.min = Some(NodeId(value)),
            crate::layout::AUX_SCHEMA_MAX => spec.max = Some(NodeId(value)),
            crate::layout::AUX_SCHEMA_MIN_LEN => spec.min_len = Some(NodeId(value)),
            crate::layout::AUX_SCHEMA_MAX_LEN => spec.max_len = Some(NodeId(value)),
            crate::layout::AUX_SCHEMA_PATTERN => spec.pattern = Some(NodeId(value)),
            crate::layout::AUX_SCHEMA_DEFAULT => spec.default = Some(NodeId(value)),
            crate::layout::AUX_SCHEMA_DEPRECATED => {
                spec.deprecated = Some(validated.string(value)?.to_string())
            }
            _ => {
                return Err(Error::Node {
                    id: id.0,
                    reason: "unknown schema aux tag",
                })
            }
        }
    }
    Ok(spec)
}

fn decode_type(validated: &Validated<'_>, index: u32) -> Result<TypeSpec> {
    let (code, flags, start, len) = validated.type_entry(index)?;
    let spec = match code {
        0 => TypeSpec::Null,
        1 => TypeSpec::Bool,
        2 => TypeSpec::Int,
        3 => TypeSpec::Float,
        4 => TypeSpec::String,
        5 => TypeSpec::Duration,
        6 => TypeSpec::Bytes,
        7 => TypeSpec::Table {
            closed: flags & 1 != 0,
        },
        8 => {
            let mut items = Vec::new();
            for offset in start..start + len {
                let (tag, value) = validated.aux(offset)?;
                if tag != crate::layout::AUX_TYPE_ENUM_ITEM {
                    return Err(Error::Type {
                        id: index,
                        reason: "unexpected aux record",
                    });
                }
                items.push(validated.string(value)?.to_string());
            }
            TypeSpec::Enum(items)
        }
        9 => TypeSpec::Secret,
        10 => TypeSpec::Any,
        11 => TypeSpec::Blob,
        _ => {
            return Err(Error::Type {
                id: index,
                reason: "unknown type code",
            })
        }
    };
    Ok(spec)
}

/// Decode only the provenance block (cheap metadata read).
pub fn decode_provenance(bytes: &[u8]) -> Result<Option<Provenance>> {
    // One validation pass: `Validated::new` already runs the full wire check, so a
    // preceding `validate` would double the work on untrusted bytes.
    let validated = Validated::new(bytes, DecodeOpts::default())?;
    validated.provenance()
}

/// Decode only the annotations (cheap metadata read).
pub fn decode_annotations(bytes: &[u8]) -> Result<Vec<Annotation>> {
    let validated = Validated::new(bytes, DecodeOpts::default())?;
    let mut out = Vec::new();
    for index in 0..validated.span(crate::layout::Section::Annotations).count {
        let (node, kind, a, b) = validated.annotation(index)?;
        let kind = match kind {
            ANN_KIND_INTENT => AnnotationKind::Intent(validated.string(a)?.to_string()),
            ANN_KIND_CONSTRAINT => AnnotationKind::Constraint {
                source: validated.string(a)?.to_string(),
                expr: NodeId(b),
            },
            // The validator accepts the immutable flag; the cheap accessor must
            // agree with the full decoder (`decode_validated` reads `a`).
            ANN_KIND_AI_IMMUTABLE => AnnotationKind::AiImmutable(a == 1),
            _ => {
                return Err(Error::Annotation {
                    id: index,
                    reason: "unknown annotation kind",
                })
            }
        };
        out.push(Annotation {
            node: NodeId(node),
            kind,
        });
    }
    Ok(out)
}

/// Decode provenance entries into a stable, sorted vector of owned pairs.
pub fn provenance_pairs(prov: &Provenance) -> Vec<(String, ProvValue)> {
    let mut pairs: Vec<(String, ProvValue)> = prov
        .entries
        .iter()
        .map(|entry: &ProvEntry| (entry.key.clone(), entry.value.clone()))
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs
}
