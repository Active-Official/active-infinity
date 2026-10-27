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
use crate::validate::{validate, Validated};

/// Decode with default options (hash verified, canonical form not re-proved).
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
    let module = InfinityModule::from_parts(nodes, root, bindings, annotations, provenance);
    module.validate_structure(u32::MAX as u64, 0)?;
    Ok(module)
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
    let meta = validate(bytes)?;
    let _ = meta;
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
            _ => AnnotationKind::AiImmutable(a == 1),
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
