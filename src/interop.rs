//! Interoperability with the Active text language and with legacy consumers.
//!
//! Three surfaces live here:
//!
//! 1. **`active-core` bridge** (`from_active_core` / `to_active_core`): parse
//!    text Active with `active_core`, hand the IR to Infinity, and bring it
//!    back for evaluation. The bridge is deliberately one-directional in what
//!    it guarantees: every `active-core` 1.4.0 node kind is representable in
//!    Infinity, while Infinity's blob identity has no `active-core` 1.4.0
//!    counterpart and is reported as an explicit error instead of being
//!    silently degraded (ADR-0002).
//! 2. **Redacted projections** (`to_redacted_json`): human and legacy
//!    consumption. Secrets are replaced by the marker at every depth, and any
//!    plain string equal to a secret literal is redacted too, so a copy of a
//!    secret cannot leave through the projection.
//! 3. **Agent graph queries** (`why`, `impact`, `dependents`, `dependencies`,
//!    `secret_tainted_paths`): the binary form of the questions agents ask,
//!    answered with labels only — never values.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::error::{Error, Result};
use crate::ir::{
    AnnotationKind, InfinityModule, Inode, InterpPart, NodeId, ProvEntry, ProvValue, Provenance,
};
#[cfg(feature = "active-core")]
use crate::ir::{BinOp, Constraint, PatchOp, SchemaFieldSpec, SemanticTag, TypeSpec, UnOp};
#[cfg(feature = "active-core")]
use crate::unit::UnitTag;

/// Marker substituted for secret material in every projection.
///
/// Re-exported from [`crate::canonical`] so the marker and the replacement rule
/// have one definition.
pub use crate::canonical::SECRET_MARKER;

/// Every secret literal in a module, as text.
///
/// Crate-internal on purpose: secret bytes are structural, and a public
/// accessor that returns them would be an unlock API. Redaction helpers consume
/// this; callers outside the crate get only redacted projections.
pub(crate) fn secret_texts(module: &InfinityModule) -> Vec<String> {
    module
        .nodes()
        .iter()
        .filter_map(|node| match node {
            Inode::Secret(secret) => Some(String::from_utf8_lossy(secret.expose()).into_owned()),
            _ => None,
        })
        .collect()
}

/// Every secret literal in a module, as raw bytes.
///
/// Crate-internal on purpose (see [`secret_texts`]): the only consumer is the
/// byte-level extension check in the Protobuf projection. Text redaction uses
/// the lossy UTF-8 view because it compares against UTF-8 text; a byte-level
/// surface must compare against the real bytes, or a secret that is not valid
/// UTF-8 would be lossily converted and never match its own copy.
pub(crate) fn secret_bytes(module: &InfinityModule) -> Vec<Vec<u8>> {
    module
        .nodes()
        .iter()
        .filter_map(|node| match node {
            Inode::Secret(secret) => Some(secret.expose().to_vec()),
            _ => None,
        })
        .collect()
}

/// Replace every occurrence of a secret in `text` with the marker.
///
/// The rule is unconditional, including for one- and two-byte secrets: a short
/// secret that survives inside a note would be stored in the canonical image and
/// then hidden only by the projections, so the copy has to go at the source.
/// It is the same implementation the canonicalizer uses, which is what makes a
/// second pass a fixpoint (see [`crate::canonical`]).
pub fn redact_text(text: &str, secrets: &[String]) -> String {
    crate::canonical::redact_text(text, secrets)
}

// ---------------------------------------------------------------------------
// active-core bridge
// ---------------------------------------------------------------------------

#[cfg(feature = "active-core")]
mod bridge {
    use super::*;
    use active_core::ir::{
        Annotation as CoreAnnotation, AnnotationKind as CoreAnnotationKind, Module as CoreModule,
        Node as CoreNode, Value as CoreValue,
    };
    use active_core::types::{
        ActiveType as CoreType, Constraint as CoreConstraint, Unit as CoreUnit,
    };

    /// Convert a parsed `active-core` module into an Infinity module.
    pub fn from_active_core(module: &CoreModule) -> Result<InfinityModule> {
        let mut out = InfinityModule::new();
        let mut map: HashMap<u32, NodeId> = HashMap::new();
        // Ids are allocated in arena order so the conversion is deterministic
        // and diagnostics that reference `n<id>` stay interpretable.
        for index in 0..module.arena.len() {
            let core_id = active_core::NodeId(index as u32);
            if module.get(core_id).is_none() {
                continue;
            }
            let node = lower_node(module, core_id, &mut out, &mut map)?;
            map.insert(core_id.0, node);
        }
        for (name, core_id) in &module.bindings {
            if let Some(id) = map.get(&core_id.0) {
                out.bind(name.clone(), *id);
            }
        }
        if let Some(root) = module.root {
            out.set_root(map.get(&root.0).copied());
        }
        let mut annotations: Vec<(NodeId, AnnotationKind)> = Vec::new();
        for (core_id, list) in &module.annotations {
            let Some(node) = map.get(&core_id.0).copied() else {
                continue;
            };
            for annotation in list {
                let kind = match &annotation.kind {
                    CoreAnnotationKind::Intent(text) => AnnotationKind::Intent(text.clone()),
                    CoreAnnotationKind::Constraint { source, expr } => {
                        let expr = map
                            .get(&expr.0)
                            .copied()
                            .ok_or(Error::EncodeDangling(expr.0))?;
                        AnnotationKind::Constraint {
                            source: source.clone(),
                            expr,
                        }
                    }
                    CoreAnnotationKind::AiImmutable(flag) => AnnotationKind::AiImmutable(*flag),
                };
                annotations.push((node, kind));
            }
        }
        for (node, kind) in annotations {
            out.annotate(node, kind);
        }
        out.validate_structure(u32::MAX as u64, 0)?;
        Ok(out)
    }

    fn lower_node(
        module: &CoreModule,
        id: active_core::NodeId,
        out: &mut InfinityModule,
        map: &mut HashMap<u32, NodeId>,
    ) -> Result<NodeId> {
        let node = module.get(id).ok_or(Error::EncodeDangling(id.0))?;
        // Literals lower recursively into composed nodes (arrays and tables are
        // node graphs in the canonical form).
        if let CoreNode::Literal(value) = node {
            return push_value(value, out, map);
        }
        let lowered = match node {
            CoreNode::Literal(_) => unreachable!("handled before the match"),
            CoreNode::Env { name, default } => {
                let default = match default {
                    Some(default) => Some(lower_ref(module, *default, out, map)?),
                    None => None,
                };
                Inode::Env {
                    name: name.clone(),
                    default,
                }
            }
            CoreNode::Secret { locator } => Inode::SecretRef {
                locator: lower_ref(module, *locator, out, map)?,
            },
            CoreNode::Ref(target) => Inode::Ref(lower_ref(module, *target, out, map)?),
            CoreNode::Ident(name) => Inode::Ident(name.clone()),
            CoreNode::Interpolate { parts } => Inode::Interpolate {
                parts: parts
                    .iter()
                    .map(|part| match part {
                        active_core::InterpPart::Literal(text) => {
                            Ok(InterpPart::Literal(text.clone()))
                        }
                        active_core::InterpPart::Expr(id) => {
                            Ok(InterpPart::Expr(lower_ref(module, *id, out, map)?))
                        }
                    })
                    .collect::<Result<Vec<_>>>()?,
            },
            CoreNode::Binary { op, lhs, rhs } => Inode::Binary {
                op: lower_binop(*op),
                lhs: lower_ref(module, *lhs, out, map)?,
                rhs: lower_ref(module, *rhs, out, map)?,
            },
            CoreNode::Unary { op, expr } => Inode::Unary {
                op: lower_unop(*op),
                expr: lower_ref(module, *expr, out, map)?,
            },
            CoreNode::Array { elements } => Inode::Array {
                elements: elements
                    .iter()
                    .map(|id| lower_ref(module, *id, out, map))
                    .collect::<Result<Vec<_>>>()?,
            },
            CoreNode::Table { fields } => Inode::Table {
                fields: fields
                    .iter()
                    .map(|(name, id)| Ok((name.clone(), lower_ref(module, *id, out, map)?)))
                    .collect::<Result<Vec<_>>>()?,
            },
            CoreNode::Quantity { value, unit } => Inode::Quantity {
                value: lower_ref(module, *value, out, map)?,
                unit: UnitTag::from(unit),
            },
            CoreNode::ApplyConstraint { target, constraint } => Inode::Constrained {
                target: lower_ref(module, *target, out, map)?,
                constraint: lower_constraint(constraint)?,
            },
            CoreNode::PatchDirective { op } => Inode::Patch(match op {
                active_core::ir::PatchOp::Set { path, value } => PatchOp::Set {
                    path: path.clone(),
                    value: lower_ref(module, *value, out, map)?,
                },
                active_core::ir::PatchOp::Remove { path } => PatchOp::Remove { path: path.clone() },
                active_core::ir::PatchOp::Rename { from, to } => PatchOp::Rename {
                    from: from.clone(),
                    to: to.clone(),
                },
            }),
            CoreNode::SchemaField { field } => Inode::SchemaField(SchemaFieldSpec {
                typ: lower_type(&field.typ)?,
                min: lower_opt(module, field.min, out, map)?,
                max: lower_opt(module, field.max, out, map)?,
                min_len: lower_opt(module, field.min_len, out, map)?,
                max_len: lower_opt(module, field.max_len, out, map)?,
                pattern: lower_opt(module, field.pattern, out, map)?,
                default: lower_opt(module, field.default, out, map)?,
                deprecated: field.deprecated.clone(),
            }),
            CoreNode::SchemaTable { fields, closed } => Inode::SchemaTable {
                fields: fields
                    .iter()
                    .map(|(name, id)| Ok((name.clone(), lower_ref(module, *id, out, map)?)))
                    .collect::<Result<Vec<_>>>()?,
                closed: *closed,
            },
            CoreNode::SchemaArray { element } => Inode::SchemaArray {
                element: lower_ref(module, *element, out, map)?,
            },
            CoreNode::Semantic { tag, inner } => Inode::Semantic {
                tag: match tag {
                    active_core::ir::SemanticTag::Prompt => SemanticTag::Prompt,
                    active_core::ir::SemanticTag::Policy => SemanticTag::Policy,
                    active_core::ir::SemanticTag::Template => SemanticTag::Template,
                },
                inner: lower_ref(module, *inner, out, map)?,
            },
        };
        let id = out.push(lowered);
        Ok(id)
    }

    /// Values lower into nodes; arrays and tables become composed nodes so the
    /// canonical form has a single representation for every shape.
    fn lower_value(value: &CoreValue) -> Inode {
        match value {
            CoreValue::Null => Inode::Null,
            CoreValue::Bool(flag) => Inode::Bool(*flag),
            CoreValue::Int(number) => Inode::Int(*number),
            CoreValue::Float(number) => Inode::Float(*number),
            CoreValue::String(text) => Inode::Str(text.clone()),
            CoreValue::DurationMs(ms) => Inode::DurationMs(*ms),
            CoreValue::Secret(text) => Inode::Secret(crate::ir::SecretBytes::from(text.clone())),
            // Quantity, arrays and tables need child nodes and are handled in
            // `push_value`, which owns the recursion.
            CoreValue::Quantity(..) | CoreValue::Array(_) | CoreValue::Table(_) => {
                unreachable!("composed values are lowered by push_value")
            }
        }
    }

    fn push_value(
        value: &CoreValue,
        out: &mut InfinityModule,
        map: &mut HashMap<u32, NodeId>,
    ) -> Result<NodeId> {
        let _ = map;
        let node = match value {
            CoreValue::Quantity(amount, unit) => {
                let number = out.push(Inode::Float(*amount));
                Inode::Quantity {
                    value: number,
                    unit: UnitTag::from(unit),
                }
            }
            CoreValue::Array(items) => {
                let mut elements = Vec::with_capacity(items.len());
                for item in items {
                    elements.push(push_value(item, out, map)?);
                }
                Inode::Array { elements }
            }
            CoreValue::Table(entries) => {
                let mut fields = Vec::with_capacity(entries.len());
                for (name, item) in entries {
                    fields.push((name.clone(), push_value(item, out, map)?));
                }
                Inode::Table { fields }
            }
            other => lower_value(other),
        };
        Ok(out.push(node))
    }

    fn lower_ref(
        module: &CoreModule,
        id: active_core::NodeId,
        out: &mut InfinityModule,
        map: &mut HashMap<u32, NodeId>,
    ) -> Result<NodeId> {
        if let Some(mapped) = map.get(&id.0) {
            return Ok(*mapped);
        }
        let lowered = lower_node(module, id, out, map)?;
        map.insert(id.0, lowered);
        Ok(lowered)
    }

    fn lower_opt(
        module: &CoreModule,
        id: Option<active_core::NodeId>,
        out: &mut InfinityModule,
        map: &mut HashMap<u32, NodeId>,
    ) -> Result<Option<NodeId>> {
        match id {
            Some(id) => Ok(Some(lower_ref(module, id, out, map)?)),
            None => Ok(None),
        }
    }

    fn lower_binop(op: active_core::ir::BinOp) -> BinOp {
        match op {
            active_core::ir::BinOp::Add => BinOp::Add,
            active_core::ir::BinOp::Sub => BinOp::Sub,
            active_core::ir::BinOp::Mul => BinOp::Mul,
            active_core::ir::BinOp::Div => BinOp::Div,
            active_core::ir::BinOp::Eq => BinOp::Eq,
            active_core::ir::BinOp::Ne => BinOp::Ne,
            active_core::ir::BinOp::Lt => BinOp::Lt,
            active_core::ir::BinOp::Le => BinOp::Le,
            active_core::ir::BinOp::Gt => BinOp::Gt,
            active_core::ir::BinOp::Ge => BinOp::Ge,
            active_core::ir::BinOp::And => BinOp::And,
            active_core::ir::BinOp::Or => BinOp::Or,
        }
    }

    fn lower_unop(op: active_core::ir::UnOp) -> UnOp {
        match op {
            active_core::ir::UnOp::Neg => UnOp::Neg,
            active_core::ir::UnOp::Not => UnOp::Not,
        }
    }

    fn lower_constraint(constraint: &CoreConstraint) -> Result<Constraint> {
        let converted = match constraint {
            CoreConstraint::MinMax { min, max } => Constraint::MinMax {
                min: *min,
                max: *max,
            },
            CoreConstraint::Enum(items) => Constraint::Enum(items.clone()),
            CoreConstraint::Pattern(pattern) => Constraint::Pattern(pattern.clone()),
            CoreConstraint::Odd => Constraint::Odd,
            CoreConstraint::Custom(text) => Constraint::Custom(text.clone()),
        };
        Ok(converted)
    }

    fn lower_type(typ: &CoreType) -> Result<TypeSpec> {
        let spec = match typ {
            CoreType::Null => TypeSpec::Null,
            CoreType::Bool => TypeSpec::Bool,
            CoreType::Int => TypeSpec::Int,
            CoreType::Float => TypeSpec::Float,
            CoreType::String => TypeSpec::String,
            CoreType::Duration => TypeSpec::Duration,
            CoreType::Bytes => TypeSpec::Bytes,
            CoreType::Table { closed } => TypeSpec::Table { closed: *closed },
            CoreType::Enum(items) => TypeSpec::Enum(items.clone()),
            CoreType::Secret => TypeSpec::Secret,
            CoreType::Any => TypeSpec::Any,
        };
        Ok(spec)
    }

    /// Convert an Infinity module back into an `active-core` module.
    ///
    /// Blob identity has no `active-core` 1.4.0 representation; a module that
    /// carries a blob node is refused with a stable error rather than silently
    /// dropping the fingerprint.
    pub fn to_active_core(module: &InfinityModule) -> Result<CoreModule> {
        let mut out = CoreModule::new("infinity");
        for node in module.nodes() {
            out.add_node(convert_node(node)?);
        }
        // Rebuild the dependency graph exactly as `active-core` does.
        for (index, node) in module.nodes().iter().enumerate() {
            let dependent = active_core::NodeId(index as u32);
            for child in node.children() {
                out.add_edge(active_core::NodeId(child.0), dependent);
            }
        }
        for (name, id) in module.bindings() {
            out.bindings.insert(name.clone(), active_core::NodeId(id.0));
        }
        out.root = module.root().map(|id| active_core::NodeId(id.0));
        for annotation in module.annotations() {
            let core = CoreAnnotation {
                kind: convert_annotation(&annotation.kind)?,
                path: format!("node{}", annotation.node.0),
                span: active_core::diag::Span {
                    line: 0,
                    column: 0,
                    end_line: 0,
                    end_column: 0,
                },
            };
            out.annotations
                .entry(active_core::NodeId(annotation.node.0))
                .or_default()
                .push(core);
        }
        Ok(out)
    }

    fn convert_annotation(kind: &AnnotationKind) -> Result<CoreAnnotationKind> {
        Ok(match kind {
            AnnotationKind::Intent(text) => CoreAnnotationKind::Intent(text.clone()),
            AnnotationKind::Constraint { source, expr } => CoreAnnotationKind::Constraint {
                source: source.clone(),
                expr: active_core::NodeId(expr.0),
            },
            AnnotationKind::AiImmutable(flag) => CoreAnnotationKind::AiImmutable(*flag),
        })
    }

    fn convert_node(node: &Inode) -> Result<CoreNode> {
        let converted = match node {
            Inode::Null => CoreNode::Literal(CoreValue::Null),
            Inode::Bool(flag) => CoreNode::Literal(CoreValue::Bool(*flag)),
            Inode::Int(number) => CoreNode::Literal(CoreValue::Int(*number)),
            Inode::Float(number) => CoreNode::Literal(CoreValue::Float(*number)),
            Inode::Str(text) => CoreNode::Literal(CoreValue::String(text.clone())),
            Inode::DurationMs(ms) => CoreNode::Literal(CoreValue::DurationMs(*ms)),
            Inode::Quantity { value, unit } => CoreNode::Quantity {
                value: active_core::NodeId(value.0),
                unit: CoreUnit::from(unit),
            },
            Inode::Array { elements } => CoreNode::Array {
                elements: elements
                    .iter()
                    .map(|id| active_core::NodeId(id.0))
                    .collect(),
            },
            Inode::Table { fields } => CoreNode::Table {
                fields: fields
                    .iter()
                    .map(|(name, id)| (name.clone(), active_core::NodeId(id.0)))
                    .collect(),
            },
            Inode::Secret(secret) => CoreNode::Literal(CoreValue::Secret(
                String::from_utf8_lossy(secret.expose()).into_owned(),
            )),
            Inode::SecretRef { locator } => CoreNode::Secret {
                locator: active_core::NodeId(locator.0),
            },
            Inode::Ref(id) => CoreNode::Ref(active_core::NodeId(id.0)),
            Inode::Env { name, default } => CoreNode::Env {
                name: name.clone(),
                default: default.map(|id| active_core::NodeId(id.0)),
            },
            Inode::Ident(name) => CoreNode::Ident(name.clone()),
            Inode::Interpolate { parts } => CoreNode::Interpolate {
                parts: parts
                    .iter()
                    .map(|part| match part {
                        InterpPart::Literal(text) => active_core::InterpPart::Literal(text.clone()),
                        InterpPart::Expr(id) => {
                            active_core::InterpPart::Expr(active_core::NodeId(id.0))
                        }
                    })
                    .collect(),
            },
            Inode::Binary { op, lhs, rhs } => CoreNode::Binary {
                op: convert_binop(*op),
                lhs: active_core::NodeId(lhs.0),
                rhs: active_core::NodeId(rhs.0),
            },
            Inode::Unary { op, expr } => CoreNode::Unary {
                op: match op {
                    UnOp::Neg => active_core::ir::UnOp::Neg,
                    UnOp::Not => active_core::ir::UnOp::Not,
                },
                expr: active_core::NodeId(expr.0),
            },
            Inode::Constrained { target, constraint } => CoreNode::ApplyConstraint {
                target: active_core::NodeId(target.0),
                constraint: convert_constraint(constraint),
            },
            Inode::Patch(op) => CoreNode::PatchDirective {
                op: match op {
                    PatchOp::Set { path, value } => active_core::ir::PatchOp::Set {
                        path: path.clone(),
                        value: active_core::NodeId(value.0),
                    },
                    PatchOp::Remove { path } => {
                        active_core::ir::PatchOp::Remove { path: path.clone() }
                    }
                    PatchOp::Rename { from, to } => active_core::ir::PatchOp::Rename {
                        from: from.clone(),
                        to: to.clone(),
                    },
                },
            },
            Inode::SchemaField(spec) => CoreNode::SchemaField {
                field: active_core::SchemaField {
                    typ: convert_type(&spec.typ)?,
                    min: spec.min.map(|id| active_core::NodeId(id.0)),
                    max: spec.max.map(|id| active_core::NodeId(id.0)),
                    min_len: spec.min_len.map(|id| active_core::NodeId(id.0)),
                    max_len: spec.max_len.map(|id| active_core::NodeId(id.0)),
                    pattern: spec.pattern.map(|id| active_core::NodeId(id.0)),
                    default: spec.default.map(|id| active_core::NodeId(id.0)),
                    deprecated: spec.deprecated.clone(),
                    span: None,
                },
            },
            Inode::SchemaTable { fields, closed } => CoreNode::SchemaTable {
                fields: fields
                    .iter()
                    .map(|(name, id)| (name.clone(), active_core::NodeId(id.0)))
                    .collect(),
                closed: *closed,
            },
            Inode::SchemaArray { element } => CoreNode::SchemaArray {
                element: active_core::NodeId(element.0),
            },
            Inode::Semantic { tag, inner } => CoreNode::Semantic {
                tag: match tag {
                    SemanticTag::Prompt => active_core::ir::SemanticTag::Prompt,
                    SemanticTag::Policy => active_core::ir::SemanticTag::Policy,
                    SemanticTag::Template => active_core::ir::SemanticTag::Template,
                },
                inner: active_core::NodeId(inner.0),
            },
            Inode::ContentAddressed { .. } => {
                return Err(Error::Encode(
                    "active-core 1.4.0 has no ContentAddressed node kind",
                ))
            }
            Inode::Blob { .. } => {
                // Documented limitation (ADR-0002): `active-core` 1.4.0 has no
                // blob value, so the bridge refuses instead of degrading the
                // identity into an ordinary table. Keep the module in Infinity.
                return Err(Error::Encode(
                    "active-core 1.4.0 has no blob value; keep the module in Infinity",
                ));
            }
        };
        Ok(converted)
    }

    fn convert_binop(op: BinOp) -> active_core::ir::BinOp {
        match op {
            BinOp::Add => active_core::ir::BinOp::Add,
            BinOp::Sub => active_core::ir::BinOp::Sub,
            BinOp::Mul => active_core::ir::BinOp::Mul,
            BinOp::Div => active_core::ir::BinOp::Div,
            BinOp::Eq => active_core::ir::BinOp::Eq,
            BinOp::Ne => active_core::ir::BinOp::Ne,
            BinOp::Lt => active_core::ir::BinOp::Lt,
            BinOp::Le => active_core::ir::BinOp::Le,
            BinOp::Gt => active_core::ir::BinOp::Gt,
            BinOp::Ge => active_core::ir::BinOp::Ge,
            BinOp::And => active_core::ir::BinOp::And,
            BinOp::Or => active_core::ir::BinOp::Or,
        }
    }

    fn convert_constraint(constraint: &Constraint) -> CoreConstraint {
        match constraint {
            Constraint::MinMax { min, max } => CoreConstraint::MinMax {
                min: *min,
                max: *max,
            },
            Constraint::Enum(items) => CoreConstraint::Enum(items.clone()),
            Constraint::Pattern(pattern) => CoreConstraint::Pattern(pattern.clone()),
            Constraint::Odd => CoreConstraint::Odd,
            Constraint::Custom(text) => CoreConstraint::Custom(text.clone()),
        }
    }

    fn convert_type(typ: &TypeSpec) -> Result<CoreType> {
        let spec = match typ {
            TypeSpec::Null => CoreType::Null,
            TypeSpec::Bool => CoreType::Bool,
            TypeSpec::Int => CoreType::Int,
            TypeSpec::Float => CoreType::Float,
            TypeSpec::String => CoreType::String,
            TypeSpec::Duration => CoreType::Duration,
            TypeSpec::Bytes => CoreType::Bytes,
            TypeSpec::Table { closed } => CoreType::Table { closed: *closed },
            TypeSpec::Enum(items) => CoreType::Enum(items.clone()),
            TypeSpec::Secret => CoreType::Secret,
            TypeSpec::Any => CoreType::Any,
            TypeSpec::Blob => {
                // Documented limitation (ADR-0002): the published `active-core`
                // has no `Blob` schema type; refuse rather than approximate.
                return Err(Error::Encode("active-core 1.4.0 has no Blob type"));
            }
        };
        Ok(spec)
    }

    /// Evaluate a module with the Active engine, honoring a budget.
    pub fn evaluate(
        module: &InfinityModule,
        budget: active_core::Budget,
    ) -> Result<(active_core::Value, Vec<active_core::Diagnostic>)> {
        let core = to_active_core(module)?;
        let mut engine = active_core::Engine::new();
        engine.budget = budget;
        engine.evaluate(&core).map_err(|error| {
            // Keep the machine-readable Active class; the payload is a code with
            // no values in it (spec/secrets.md §4).
            Error::Evaluation(active_error_code(error.code()))
        })
    }

    fn active_error_code(code: &'static str) -> &'static str {
        match code {
            "S001" => "active/S001-cycle",
            "S002" => "active/S002-missing-root",
            "S003" => "active/S003-missing-node",
            "T001" => "active/T001-type",
            "X001" => "active/X001-node-budget",
            "X002" => "active/X002-wall-clock",
            "X003" => "active/X003-depth",
            "X004" => "active/X004-array-length",
            "X005" => "active/X005-keys",
            "X006" => "active/X006-value-size",
            _ => "active/eval-error",
        }
    }
}

#[cfg(feature = "active-core")]
pub use bridge::{evaluate, from_active_core, to_active_core};

// ---------------------------------------------------------------------------
// Shared redacted projection tree
// ---------------------------------------------------------------------------

/// Deepest graph the projection will follow. A validated module is at most
/// `Limits::max_depth` deep; this is a second, independent stop so a
/// hand-built module cannot exhaust the stack.
const PROJECTION_DEPTH: usize = 1024;

/// Maximum number of nodes a single projection may materialise.
///
/// A shared DAG expands to a tree when projected: a 3 KB module with a
/// diamond chain can demand gigabytes of JSON. This bound turns that
/// expansion into a fail-closed error instead of memory exhaustion.
pub const PROJECTION_NODE_BUDGET: usize = 100_000;

/// A redacted projection of a module's value tree.
///
/// Both the JSON and the Protobuf projection render this tree. Building it once
/// keeps the two from drifting, which matters because the redaction rules are
/// security invariants and every renderer has to reproduce them exactly.
#[derive(Debug, Clone, PartialEq)]
pub enum Projected {
    /// No value (a missing root or a dangling reference).
    Null,
    /// A boolean.
    Bool(bool),
    /// A signed integer.
    Int(i64),
    /// A double-precision float.
    Float(f64),
    /// Text with secret material already removed or replaced by the marker.
    Text(String),
    /// A duration in milliseconds.
    DurationMs(u64),
    /// A value with a unit: the inner value plus the unit's name.
    Quantity(Box<Projected>, String),
    /// Ordered list elements.
    Array(Vec<Projected>),
    /// A table, in canonical field order. Keys are already redacted.
    Record(Vec<(String, Projected)>),
    /// A blob by identity. Payloads are never projected.
    Blob {
        /// Blake3-256 of the payload.
        hash: [u8; 32],
        /// Payload size in bytes.
        size: u64,
        /// Media type, redacted when the blob is tainted.
        media_type: String,
        /// Whether the blob carries secret-derived bytes.
        tainted: bool,
    },
    /// An environment lookup, by name.
    Env(String),
    /// A node kind that has no data projection (an operator, a schema, a patch).
    Expr(&'static str),
}

/// Project a module's root value with every secret redacted.
///
/// A projection walks the graph recursively, so a module with cycles or
/// dangling references is refused instead of risking the stack. The Protobuf
/// projection starts from [`project_node_with`] because it already holds the
/// secret table and the encoded image.
#[cfg(feature = "json")]
pub(crate) fn project_root(module: &InfinityModule) -> Result<Projected> {
    module.validate_structure(u32::MAX as u64, 4096)?;
    let secrets = secret_texts(module);
    let mut budget = 0usize;
    build_projected(module, module.root(), &secrets, 0, &mut budget)
}

/// The module's secret literals, for a caller that projects many nodes.
pub(crate) fn secret_table(module: &InfinityModule) -> Vec<String> {
    secret_texts(module)
}

/// Project one node with an already-computed secret table.
pub(crate) fn project_node_with(
    module: &InfinityModule,
    id: NodeId,
    secrets: &[String],
    budget: &mut usize,
) -> Result<Projected> {
    build_projected(module, Some(id), secrets, 0, budget)
}

/// A value-position string: the whole text becomes the marker as soon as it
/// contains a secret literal, so a partial copy cannot leak and a second pass is
/// a fixpoint.
pub(crate) fn redacted_value(text: &str, secrets: &[String]) -> String {
    if secrets
        .iter()
        .any(|secret| !secret.is_empty() && text.contains(secret.as_str()))
    {
        SECRET_MARKER.to_string()
    } else {
        text.to_string()
    }
}

/// One entry per key, first occurrence wins, in the module's order.
///
/// The encoder refuses duplicate provenance keys, so this only decides what a
/// projection shows for a hand-built module; all projections apply the same rule
/// so they cannot disagree about a malformed input.
pub(crate) fn first_entry_per_key(entries: &[ProvEntry]) -> Vec<&ProvEntry> {
    let mut seen = std::collections::HashSet::new();
    entries
        .iter()
        .filter(|entry| seen.insert(entry.key.as_str()))
        .collect()
}

/// A key-position string: every occurrence of every secret is replaced, so a
/// key that merely contains a copy of a secret does not leak it. Same rule as
/// [`redact_text`], including the marker-substring fixpoint.
pub(crate) fn redacted_key(text: &str, secrets: &[String]) -> String {
    redact_text(text, secrets)
}

/// Whether a node resolves to secret material, following `Ref` and `Semantic`.
///
/// Reference wrappers must be transparent for taint: an interpolated
/// `${ref_to_secret}` has to redact the whole string, not render it as `${}`.
fn resolves_to_secret(module: &InfinityModule, id: NodeId, depth: usize) -> bool {
    if depth > PROJECTION_DEPTH {
        // A pathological chain is treated as secret: fail closed.
        return true;
    }
    match module.get(id) {
        Some(Inode::Secret(_)) | Some(Inode::SecretRef { .. }) => true,
        Some(Inode::Ref(inner)) => resolves_to_secret(module, *inner, depth + 1),
        Some(Inode::Semantic { inner, .. }) => resolves_to_secret(module, *inner, depth + 1),
        Some(node) => node.is_secret(),
        None => false,
    }
}

fn build_projected(
    module: &InfinityModule,
    id: Option<NodeId>,
    secrets: &[String],
    depth: usize,
    budget: &mut usize,
) -> Result<Projected> {
    if depth > PROJECTION_DEPTH {
        return Err(Error::Encode("projection nesting exceeds the limit"));
    }
    *budget += 1;
    if *budget > PROJECTION_NODE_BUDGET {
        return Err(Error::Encode("projection node budget exceeded"));
    }
    let value = match id.and_then(|id| module.get(id)) {
        None => Projected::Null,
        Some(node) => match node {
            Inode::Null => Projected::Null,
            Inode::Bool(flag) => Projected::Bool(*flag),
            Inode::Int(number) => Projected::Int(*number),
            Inode::Float(number) => Projected::Float(*number),
            Inode::Str(text) => Projected::Text(redacted_value(text, secrets)),
            Inode::Ident(text) => Projected::Text(redacted_key(text, secrets)),
            Inode::DurationMs(ms) => Projected::DurationMs(*ms),
            Inode::Quantity { value, unit } => Projected::Quantity(
                Box::new(build_projected(
                    module,
                    Some(*value),
                    secrets,
                    depth + 1,
                    budget,
                )?),
                redacted_key(unit.name(), secrets),
            ),
            Inode::Array { elements } => Projected::Array(
                elements
                    .iter()
                    .map(|id| build_projected(module, Some(*id), secrets, depth + 1, budget))
                    .collect::<Result<Vec<_>>>()?,
            ),
            Inode::Table { fields } => {
                let mut projected = Vec::with_capacity(fields.len());
                for (name, id) in fields {
                    projected.push((
                        redacted_key(name, secrets),
                        build_projected(module, Some(*id), secrets, depth + 1, budget)?,
                    ));
                }
                Projected::Record(projected)
            }
            Inode::Secret(_) | Inode::SecretRef { .. } => {
                Projected::Text(SECRET_MARKER.to_string())
            }
            Inode::Ref(id) => build_projected(module, Some(*id), secrets, depth + 1, budget)?,
            Inode::Env { name, .. } => Projected::Env(redacted_key(name, secrets)),
            Inode::Interpolate { parts } => {
                let mut text = String::new();
                let mut tainted = false;
                for part in parts {
                    match part {
                        InterpPart::Literal(literal) => text.push_str(literal),
                        InterpPart::Expr(id) => match id.index() {
                            _ if resolves_to_secret(module, *id, 0) => tainted = true,
                            _ => text.push_str("${}"),
                        },
                    }
                }
                if tainted {
                    Projected::Text(SECRET_MARKER.to_string())
                } else {
                    Projected::Text(redacted_value(&text, secrets))
                }
            }
            Inode::Binary { .. }
            | Inode::Unary { .. }
            | Inode::Constrained { .. }
            | Inode::Patch(_)
            | Inode::SchemaField(_)
            | Inode::SchemaTable { .. }
            | Inode::SchemaArray { .. }
            | Inode::ContentAddressed { .. } => {
                Projected::Expr(crate::view::node_kind_name(node.kind_code()))
            }
            Inode::Semantic { inner, .. } => {
                build_projected(module, Some(*inner), secrets, depth + 1, budget)?
            }
            Inode::Blob {
                hash,
                size,
                tainted,
                media_type,
                ..
            } => Projected::Blob {
                hash: *hash,
                size: *size,
                media_type: if *tainted {
                    SECRET_MARKER.to_string()
                } else {
                    redacted_key(media_type, secrets)
                },
                tainted: *tainted,
            },
        },
    };
    Ok(value)
}

// ---------------------------------------------------------------------------
// Redacted JSON projection
// ---------------------------------------------------------------------------

#[cfg(feature = "json")]
mod projection {
    use super::*;

    /// Serialize a module as redacted JSON.
    ///
    /// Properties that legacy consumers rely on and auditors check:
    /// - secrets (and strings equal to a secret literal) become [`SECRET_MARKER`];
    /// - blobs project their identity only (hash, size, media type, taint);
    /// - quantities project `{"value": n, "unit": "<name>"}`;
    /// - annotations and provenance project as data, never as executable text.
    pub fn to_redacted_json(module: &InfinityModule) -> Result<String> {
        let value = to_serde(&project_root(module)?);
        serde_json::to_string(&value).map_err(|_| Error::Encode("json projection failed"))
    }

    /// Pretty-printed form of [`to_redacted_json`].
    pub fn to_redacted_json_pretty(module: &InfinityModule) -> Result<String> {
        let value = to_serde(&project_root(module)?);
        serde_json::to_string_pretty(&value).map_err(|_| Error::Encode("json projection failed"))
    }

    /// Every secret literal in the module, as text, for the redaction helpers.
    ///
    /// Crate-internal: a public plaintext accessor would defeat structural
    /// secrets. Callers outside the crate use the redacted projections.
    pub(crate) fn secret_literals(module: &InfinityModule) -> Vec<String> {
        secret_texts(module)
    }

    /// Render a projected value as JSON.
    fn to_serde(value: &Projected) -> serde_json::Value {
        match value {
            Projected::Null => serde_json::Value::Null,
            Projected::Bool(flag) => serde_json::Value::from(*flag),
            Projected::Int(number) => serde_json::Value::from(*number),
            Projected::Float(number) => serde_json::Value::from(*number),
            Projected::Text(text) => serde_json::Value::from(text.clone()),
            Projected::DurationMs(ms) => serde_json::json!({ "ms": ms }),
            Projected::Quantity(value, unit) => serde_json::json!({
                "value": to_serde(value),
                "unit": unit,
            }),
            Projected::Array(items) => {
                serde_json::Value::Array(items.iter().map(to_serde).collect())
            }
            Projected::Record(fields) => {
                let mut map = serde_json::Map::new();
                for (name, value) in fields {
                    map.insert(name.clone(), to_serde(value));
                }
                serde_json::Value::Object(map)
            }
            Projected::Blob {
                hash,
                size,
                media_type,
                tainted,
            } => serde_json::json!({
                "$active.blob": {
                    "hash": format!("blake3:{}", crate::ir::hash_hex(hash)),
                    "size": size,
                    "media_type": media_type,
                    "tainted": tainted,
                }
            }),
            Projected::Env(name) => serde_json::json!({ "$env": name }),
            Projected::Expr(kind) => serde_json::json!({ "$expr": kind }),
        }
    }

    /// Project provenance as JSON, redacting every text field and key against
    /// `secrets` (the module's secret literals).
    pub fn provenance_json(prov: &Provenance, secrets: &[String]) -> serde_json::Value {
        let text = |value: &str| serde_json::Value::from(redacted_value(value, secrets));
        let mut map = serde_json::Map::new();
        if let Some(producer) = &prov.producer {
            map.insert("producer".into(), text(producer));
        }
        if prov.timestamp_ms != 0 {
            map.insert(
                "timestamp_ms".into(),
                serde_json::Value::from(prov.timestamp_ms),
            );
        }
        if let Some(model) = &prov.model {
            map.insert("model".into(), text(model));
        }
        if let Some(tool) = &prov.tool {
            map.insert("tool".into(), text(tool));
        }
        if let Some(parent) = prov.parent {
            map.insert(
                "parent".into(),
                serde_json::Value::from(crate::ir::hash_hex(&parent)),
            );
        }
        let mut entries = serde_json::Map::new();
        for entry in first_entry_per_key(&prov.entries) {
            let value = match &entry.value {
                ProvValue::Text(t) => text(t),
                ProvValue::Int(number) => serde_json::Value::from(*number),
                ProvValue::Flag(flag) => serde_json::Value::from(*flag),
                ProvValue::Hash(hash) => serde_json::Value::from(crate::ir::hash_hex(hash)),
            };
            entries.insert(redacted_key(&entry.key, secrets), value);
        }
        map.insert("entries".into(), serde_json::Value::Object(entries));
        serde_json::Value::Object(map)
    }

    /// Project a module's provenance, collecting its secret table first.
    pub fn provenance_json_for(module: &InfinityModule) -> Option<serde_json::Value> {
        let secrets = secret_literals(module);
        module
            .provenance()
            .map(|prov| provenance_json(prov, &secrets))
    }
}

#[cfg(feature = "json")]
pub use projection::{
    provenance_json, provenance_json_for, to_redacted_json, to_redacted_json_pretty,
};

// ---------------------------------------------------------------------------
// Agent graph queries
// ---------------------------------------------------------------------------

/// Dotted paths for every named node (bindings plus table paths from the root).
pub fn value_paths(module: &InfinityModule) -> HashMap<NodeId, String> {
    // A binding or field name can contain a copy of a secret, and these paths are
    // handed to agents and logs, so keys are redacted here too.
    let secrets = secret_texts(module);
    let mut paths: HashMap<NodeId, String> = HashMap::new();
    for (name, id) in module.bindings() {
        paths.insert(*id, redacted_key(name, &secrets));
    }
    if let Some(root) = module.root() {
        let mut stack = vec![(root, String::new())];
        let mut expanded = std::collections::HashSet::new();
        while let Some((id, path)) = stack.pop() {
            // A cyclic hand-built module must not hang the query.
            if !expanded.insert(id) {
                continue;
            }
            match module.get(id) {
                Some(Inode::Table { fields }) => {
                    for (key, child) in fields {
                        let key = redacted_key(key, &secrets);
                        let child_path = if path.is_empty() {
                            key
                        } else {
                            format!("{path}.{key}")
                        };
                        paths.entry(*child).or_insert_with(|| child_path.clone());
                        stack.push((*child, child_path));
                    }
                }
                Some(Inode::SchemaTable { fields, .. }) => {
                    for (key, child) in fields {
                        let key = redacted_key(key, &secrets);
                        let child_path = if path.is_empty() {
                            key
                        } else {
                            format!("{path}.{key}")
                        };
                        paths.entry(*child).or_insert_with(|| child_path.clone());
                        stack.push((*child, child_path));
                    }
                }
                _ => {}
            }
        }
    }
    paths
}

/// Stable label for a node: dotted path, binding, or `Kind[id]`.
///
/// Unmapped internal nodes (literals inside expressions, schema arguments) get a
/// kind-and-id label instead of a bare number so an agent's `why`/`impact`
/// output stays readable. Values are never included: a label must be safe to
/// print for a module that holds secrets.
pub fn node_label(module: &InfinityModule, id: NodeId) -> String {
    if let Some(path) = value_paths(module).get(&id) {
        return path.clone();
    }
    match module.get(id) {
        Some(node) => format!("{}[{}]", node.kind().name(), id.0),
        None => format!("node{}", id.0),
    }
}

/// Resolve a dotted path the way the evaluator does (table fields, then
/// single-segment bindings).
pub fn resolve_path(module: &InfinityModule, path: &str) -> Option<NodeId> {
    if let Some(root) = module.root() {
        let mut current = root;
        let mut found = true;
        for segment in path.split('.') {
            match module.get(current) {
                Some(Inode::Table { fields }) | Some(Inode::SchemaTable { fields, .. }) => {
                    match fields.iter().find(|(name, _)| name == segment) {
                        Some((_, child)) => current = *child,
                        None => {
                            found = false;
                            break;
                        }
                    }
                }
                _ => {
                    found = false;
                    break;
                }
            }
        }
        if found {
            return Some(current);
        }
    }
    if !path.contains('.') {
        return module
            .bindings()
            .iter()
            .find(|(name, _)| name == path)
            .map(|(_, id)| *id);
    }
    None
}

fn adjacency(module: &InfinityModule) -> (Vec<Vec<NodeId>>, Vec<Vec<NodeId>>) {
    let count = module.node_count();
    let mut deps = vec![Vec::new(); count];
    let mut dependents = vec![Vec::new(); count];
    for (index, node) in module.nodes().iter().enumerate() {
        for child in node.children() {
            if child.index() < count {
                deps[index].push(child);
                dependents[child.index()].push(NodeId(index as u32));
            }
        }
    }
    (deps, dependents)
}

fn walk(adjacency: &[Vec<NodeId>], start: NodeId) -> Vec<NodeId> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut stack = vec![start];
    seen.insert(start);
    while let Some(id) = stack.pop() {
        for next in &adjacency[id.index()] {
            if seen.insert(*next) {
                out.push(*next);
                stack.push(*next);
            }
        }
    }
    out
}

/// Transitive dependents (nodes affected by a change), sorted by label.
///
/// Parent tables are included: an agent asking "what does changing this node
/// affect?" needs the tables that must be re-evaluated as much as the leaves.
pub fn impact(module: &InfinityModule, id: NodeId) -> Vec<String> {
    let (_, dependents) = adjacency(module);
    let mut labels: Vec<String> = walk(&dependents, id)
        .into_iter()
        .map(|node| node_label(module, node))
        .collect();
    labels.sort();
    labels.dedup();
    labels
}

/// Transitive dependencies (what a node is built from), sorted by label.
pub fn why(module: &InfinityModule, id: NodeId) -> Vec<String> {
    let (deps, _) = adjacency(module);
    let mut labels: Vec<String> = walk(&deps, id)
        .into_iter()
        .map(|node| node_label(module, node))
        .collect();
    labels.sort();
    labels.dedup();
    labels
}

/// Direct dependents, sorted by node id.
pub fn dependents(module: &InfinityModule, id: NodeId) -> Vec<NodeId> {
    let (_, dependents) = adjacency(module);
    let mut out = dependents.get(id.index()).cloned().unwrap_or_default();
    out.sort_unstable();
    out.dedup();
    out
}

/// Direct dependencies, sorted by node id.
pub fn dependencies(module: &InfinityModule, id: NodeId) -> Vec<NodeId> {
    let mut out = module
        .get(id)
        .map(|node| node.children())
        .unwrap_or_default();
    out.sort_unstable();
    out.dedup();
    out
}

/// Nodes in the subgraph rooted at `roots` (the cone they depend on).
pub fn subgraph(module: &InfinityModule, roots: &[NodeId]) -> Vec<NodeId> {
    let (deps, _) = adjacency(module);
    let mut seen: HashSet<NodeId> = HashSet::new();
    let mut order = Vec::new();
    let mut queue: VecDeque<NodeId> = VecDeque::new();
    for root in roots {
        if module.get(*root).is_some() && seen.insert(*root) {
            order.push(*root);
            queue.push_back(*root);
        }
    }
    while let Some(node) = queue.pop_front() {
        for dep in &deps[node.index()] {
            if seen.insert(*dep) {
                order.push(*dep);
                queue.push_back(*dep);
            }
        }
    }
    order
}

/// Dotted paths of the secret-tainted cone: every path whose subtree holds a
/// secret, including ancestors, plus the secret node's own path. Labels only.
pub fn secret_tainted_paths(module: &InfinityModule) -> Vec<String> {
    let mut tainted: Vec<bool> = vec![false; module.node_count()];
    // Fixpoint over the DAG: a node is tainted when it is a secret or any
    // child is tainted. Iterate to a fixed point (bounded by node count).
    let order = subgraph(module, &root_ids(module));
    let mut changed = true;
    while changed {
        changed = false;
        for id in &order {
            let Some(node) = module.get(*id) else {
                continue;
            };
            let value = node.is_secret()
                || node
                    .children()
                    .iter()
                    .any(|child| tainted.get(child.index()).copied().unwrap_or(false));
            if value && !tainted[id.index()] {
                tainted[id.index()] = true;
                changed = true;
            }
        }
    }
    let paths = value_paths(module);
    let mut out: Vec<String> = module
        .nodes()
        .iter()
        .enumerate()
        .filter(|(index, _)| tainted[*index])
        .filter_map(|(index, _)| paths.get(&NodeId(index as u32)).cloned())
        .collect();
    out.sort();
    out.dedup();
    out
}

fn root_ids(module: &InfinityModule) -> Vec<NodeId> {
    let mut roots = Vec::new();
    if let Some(root) = module.root() {
        roots.push(root);
    }
    roots.extend(module.bindings().iter().map(|(_, id)| *id));
    roots
}

/// Render provenance as stable `key=value` lines (values redacted when they
/// contain a secret literal).
pub fn provenance_lines(module: &InfinityModule) -> Vec<String> {
    let Some(prov) = module.provenance() else {
        return Vec::new();
    };
    let secrets: Vec<String> = module
        .nodes()
        .iter()
        .filter_map(|node| match node {
            Inode::Secret(secret) => Some(String::from_utf8_lossy(secret.expose()).into_owned()),
            _ => None,
        })
        .collect();
    let redact = |text: &str| -> String {
        if secrets
            .iter()
            .any(|secret| !secret.is_empty() && text.contains(secret.as_str()))
        {
            SECRET_MARKER.to_string()
        } else {
            text.to_string()
        }
    };
    let mut lines = Vec::new();
    if let Some(producer) = &prov.producer {
        lines.push(format!("producer={}", redact(producer)));
    }
    if prov.timestamp_ms != 0 {
        lines.push(format!("timestamp_ms={}", prov.timestamp_ms));
    }
    if let Some(model) = &prov.model {
        lines.push(format!("model={}", redact(model)));
    }
    if let Some(tool) = &prov.tool {
        lines.push(format!("tool={}", redact(tool)));
    }
    if let Some(parent) = prov.parent {
        lines.push(format!("parent=blake3:{}", crate::ir::hash_hex(&parent)));
    }
    for entry in first_entry_per_key(&prov.entries) {
        let value = match &entry.value {
            ProvValue::Text(text) => redacted_value(text, &secrets),
            ProvValue::Int(number) => number.to_string(),
            ProvValue::Flag(flag) => flag.to_string(),
            ProvValue::Hash(hash) => format!("blake3:{}", crate::ir::hash_hex(hash)),
        };
        lines.push(format!("{}={value}", redacted_key(&entry.key, &secrets)));
    }
    lines
}

/// Intent annotations attached to a node (agent-facing helper).
///
/// Text is redacted against the module's secret literals with the *storage* rule
/// (each occurrence replaced), so the answer matches what a decoded module
/// yields: canonicalization stores annotations in that form.
pub fn intents(module: &InfinityModule, id: NodeId) -> Vec<String> {
    let secrets = secret_texts(module);
    module
        .annotations()
        .iter()
        .filter(|annotation| annotation.node == id)
        .filter_map(|annotation| match &annotation.kind {
            AnnotationKind::Intent(text) => Some(redact_text(text, &secrets)),
            _ => None,
        })
        .collect()
}

/// Nodes flagged `@ai_immutable = true` (agents must not rewrite them).
pub fn immutable_nodes(module: &InfinityModule) -> Vec<NodeId> {
    let mut out: Vec<NodeId> = module
        .annotations()
        .iter()
        .filter_map(|annotation| match &annotation.kind {
            AnnotationKind::AiImmutable(true) => Some(annotation.node),
            _ => None,
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Provenance entries as typed pairs (sorted by key).
///
/// **Raw accessor**: keys and text values are *not* redacted, because a caller
/// that handles the typed record may need the exact bytes. Use
/// [`provenance_json`] or [`provenance_lines`] for output that leaves the
/// process.
pub fn provenance_pairs(prov: &Provenance) -> Vec<&ProvEntry> {
    let mut entries: Vec<&ProvEntry> = prov.entries.iter().collect();
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    entries
}

/// Build a module from a parsed text document (feature `active-core`).
///
/// This is the convenience entry point used by agents: parse Active source,
/// then hand the module to the codec.
#[cfg(feature = "active-core")]
pub fn from_active_source(source: &str, name: &str) -> Result<InfinityModule> {
    let core = active_core::parse(source, name)
        .map_err(|_| Error::Encode("Active source failed to parse"))?;
    from_active_core(&core)
}
