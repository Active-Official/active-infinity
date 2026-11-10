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
//!    secret cannot leave through the projection. Both projections and the
//!    `active-core` bridge are lossy by design; the full loss table is the
//!    canonical one in the `to_redacted_json` documentation (INF-INTEROP-06).
//! 3. **Agent graph queries** (`why`, `impact`, `dependents`, `dependencies`,
//!    `secret_tainted_paths`): the binary form of the questions agents ask,
//!    answered with labels only — never values.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::error::{Error, Result};
use crate::ir::{
    AnnotationKind, Constraint, InfinityModule, Inode, InterpPart, NodeId, PatchOp, ProvEntry,
    ProvValue, Provenance, TypeSpec,
};
#[cfg(feature = "active-core")]
use crate::ir::{BinOp, SchemaFieldSpec, SemanticTag, UnOp};
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
    secret_literals(module)
        .into_iter()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .collect()
}

/// Every secret literal in a module, as raw bytes.
///
/// Crate-internal on purpose (see [`secret_texts`]): a byte-level surface must
/// compare against the real bytes, or a secret that is not valid UTF-8 would be
/// lossily converted and never match its own copy.
pub(crate) fn secret_bytes(module: &InfinityModule) -> Vec<Vec<u8>> {
    secret_literals(module)
}

/// The union of every secret literal, deduplicated, in one pass.
///
/// `Inode::Secret` nodes carry their bytes directly; a `SecretRef` contributes
/// every literal in its locator subtree (`Str`/`Ident`, and each interpolated
/// part, including inside a `Binary`/`Unary`/... expression). One shared visited
/// set and one set of outputs keep the walk linear in the graph: the previous
/// per-ref cache duplicated each literal per reference (measured 131 MB for
/// 1 000 refs of one 64 KiB literal) and allocated a visited vector per distinct
/// locator.
///
/// Set semantics are what every consumer uses (`contains`/`replace`/marker
/// checks), so a sorted, deduplicated vector is equivalent.
fn secret_literals(module: &InfinityModule) -> Vec<Vec<u8>> {
    let count = module.node_count();
    let mut visited = vec![false; count];
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut stack: Vec<NodeId> = Vec::new();
    for node in module.nodes() {
        match node {
            Inode::Secret(secret) => out.push(secret.expose().to_vec()),
            Inode::SecretRef { locator } => stack.push(*locator),
            _ => {}
        }
    }
    while let Some(id) = stack.pop() {
        if id.index() >= count || visited[id.index()] {
            continue;
        }
        visited[id.index()] = true;
        let Some(node) = module.get(id) else {
            continue;
        };
        match node {
            Inode::Str(text) | Inode::Ident(text) => out.push(text.as_bytes().to_vec()),
            Inode::Interpolate { parts } => {
                for part in parts {
                    if let crate::ir::InterpPart::Literal(text) = part {
                        out.push(text.as_bytes().to_vec());
                    }
                }
            }
            _ => {}
        }
        stack.extend(node.children());
    }
    out.sort();
    out.dedup();
    out
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

    /// Deepest reference chain the bridge will follow.
    const MAX_BRIDGE_DEPTH: u32 = 256;

    /// Convert a parsed `active-core` module into an Infinity module.
    pub fn from_active_core(module: &CoreModule) -> Result<InfinityModule> {
        let mut out = InfinityModule::new();
        let mut map: HashMap<u32, NodeId> = HashMap::new();
        // A caller-built `CoreModule` is arbitrary input: a cycle or a very deep
        // reference chain used to recurse until the stack aborted. The guard
        // turns both into a refusal (cross-cutting pass 1, #7).
        let mut visiting: HashSet<u32> = HashSet::new();
        // Ids are allocated in arena order so the conversion is deterministic
        // and diagnostics that reference `n<id>` stay interpretable.
        for index in 0..module.arena.len() {
            let core_id = active_core::NodeId(index as u32);
            if module.get(core_id).is_none() {
                continue;
            }
            // A node already lowered as another node's child must not be
            // lowered again. The loop used to lower *every* arena node
            // unconditionally, so a parent-first arena (legal for a
            // caller-built `CoreModule`) pushed the child a second time and
            // `map.insert` below then pointed at the duplicate while the
            // parent kept referencing the first copy (INF-INTEROP-01).
            // `lower_ref` consults `map` before lowering; the loop did not.
            if map.contains_key(&core_id.0) {
                continue;
            }
            let node = lower_node(module, core_id, &mut out, &mut map, &mut visiting, 0)?;
            map.insert(core_id.0, node);
        }
        for (name, core_id) in &module.bindings {
            // A binding naming a node the arena never produced is caller
            // error, not a droppable detail: silently skipping it used to
            // bridge a module whose `ghost` binding simply vanished
            // (INF-INTEROP-02). Refuse with the same `EncodeDangling` the
            // annotation-`expr` path below already returns.
            let id = map
                .get(&core_id.0)
                .copied()
                .ok_or(Error::EncodeDangling(core_id.0))?;
            out.bind(name.clone(), id);
        }
        if let Some(root) = module.root {
            // Same refusal for the root: `set_root(None)` used to turn a
            // dangling root into a rootless module with no error.
            let root = map
                .get(&root.0)
                .copied()
                .ok_or(Error::EncodeDangling(root.0))?;
            out.set_root(Some(root));
        }
        let mut annotations: Vec<(NodeId, AnnotationKind)> = Vec::new();
        for (core_id, list) in &module.annotations {
            // Same refusal for an annotation keyed on an unmapped node:
            // `continue` used to drop the whole annotation list silently.
            let Some(node) = map.get(&core_id.0).copied() else {
                return Err(Error::EncodeDangling(core_id.0));
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
        // Same ceiling as `prepare()` (INF-09): a `0` here used to mean
        // "no ceiling", so a deep active-core module lowered fine and then
        // produced an image the default decoder refused. Lowering now
        // refuses it first, with `infinity/depth`. (In practice the
        // bridge's own `MAX_BRIDGE_DEPTH` (256) trips first, so this is
        // defence-in-depth for the lowering path, not a new refusal.)
        out.validate_structure(u32::MAX as u64, crate::layout::Limits::default().max_depth)?;
        Ok(out)
    }

    fn lower_node(
        module: &CoreModule,
        id: active_core::NodeId,
        out: &mut InfinityModule,
        map: &mut HashMap<u32, NodeId>,
        visiting: &mut HashSet<u32>,
        depth: u32,
    ) -> Result<NodeId> {
        let node = module.get(id).ok_or(Error::EncodeDangling(id.0))?;
        // Literals lower recursively into composed nodes (arrays and tables are
        // node graphs in the canonical form).
        if let CoreNode::Literal(value) = node {
            return push_value(value, out, map, depth);
        }
        let lowered = match node {
            CoreNode::Literal(_) => unreachable!("handled before the match"),
            CoreNode::Env { name, default } => {
                let default = match default {
                    Some(default) => Some(lower_ref(module, *default, out, map, visiting, depth)?),
                    None => None,
                };
                Inode::Env {
                    name: name.clone(),
                    default,
                }
            }
            CoreNode::Secret { locator } => Inode::SecretRef {
                locator: lower_ref(module, *locator, out, map, visiting, depth)?,
            },
            CoreNode::Ref(target) => {
                Inode::Ref(lower_ref(module, *target, out, map, visiting, depth)?)
            }
            CoreNode::Ident(name) => Inode::Ident(name.clone()),
            CoreNode::Interpolate { parts } => Inode::Interpolate {
                parts: parts
                    .iter()
                    .map(|part| match part {
                        active_core::InterpPart::Literal(text) => {
                            Ok(InterpPart::Literal(text.clone()))
                        }
                        active_core::InterpPart::Expr(id) => Ok(InterpPart::Expr(lower_ref(
                            module, *id, out, map, visiting, depth,
                        )?)),
                    })
                    .collect::<Result<Vec<_>>>()?,
            },
            CoreNode::Binary { op, lhs, rhs } => Inode::Binary {
                op: lower_binop(*op),
                lhs: lower_ref(module, *lhs, out, map, visiting, depth)?,
                rhs: lower_ref(module, *rhs, out, map, visiting, depth)?,
            },
            CoreNode::Unary { op, expr } => Inode::Unary {
                op: lower_unop(*op),
                expr: lower_ref(module, *expr, out, map, visiting, depth)?,
            },
            CoreNode::Array { elements } => Inode::Array {
                elements: elements
                    .iter()
                    .map(|id| lower_ref(module, *id, out, map, visiting, depth))
                    .collect::<Result<Vec<_>>>()?,
            },
            CoreNode::Table { fields } => Inode::Table {
                fields: fields
                    .iter()
                    .map(|(name, id)| {
                        Ok((
                            name.clone(),
                            lower_ref(module, *id, out, map, visiting, depth)?,
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?,
            },
            CoreNode::Quantity { value, unit } => Inode::Quantity {
                value: lower_ref(module, *value, out, map, visiting, depth)?,
                unit: UnitTag::from(unit),
            },
            CoreNode::ApplyConstraint { target, constraint } => Inode::Constrained {
                target: lower_ref(module, *target, out, map, visiting, depth)?,
                constraint: lower_constraint(constraint)?,
            },
            CoreNode::PatchDirective { op } => Inode::Patch(match op {
                active_core::ir::PatchOp::Set { path, value } => PatchOp::Set {
                    path: path.clone(),
                    value: lower_ref(module, *value, out, map, visiting, depth)?,
                },
                active_core::ir::PatchOp::Remove { path } => PatchOp::Remove { path: path.clone() },
                active_core::ir::PatchOp::Rename { from, to } => PatchOp::Rename {
                    from: from.clone(),
                    to: to.clone(),
                },
            }),
            CoreNode::SchemaField { field } => Inode::SchemaField(SchemaFieldSpec {
                typ: lower_type(&field.typ)?,
                min: lower_opt(module, field.min, out, map, visiting, depth)?,
                max: lower_opt(module, field.max, out, map, visiting, depth)?,
                min_len: lower_opt(module, field.min_len, out, map, visiting, depth)?,
                max_len: lower_opt(module, field.max_len, out, map, visiting, depth)?,
                pattern: lower_opt(module, field.pattern, out, map, visiting, depth)?,
                default: lower_opt(module, field.default, out, map, visiting, depth)?,
                deprecated: field.deprecated.clone(),
            }),
            CoreNode::SchemaTable { fields, closed } => Inode::SchemaTable {
                fields: fields
                    .iter()
                    .map(|(name, id)| {
                        Ok((
                            name.clone(),
                            lower_ref(module, *id, out, map, visiting, depth)?,
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?,
                closed: *closed,
            },
            CoreNode::SchemaArray { element } => Inode::SchemaArray {
                element: lower_ref(module, *element, out, map, visiting, depth)?,
            },
            CoreNode::Semantic { tag, inner } => Inode::Semantic {
                tag: match tag {
                    active_core::ir::SemanticTag::Prompt => SemanticTag::Prompt,
                    active_core::ir::SemanticTag::Policy => SemanticTag::Policy,
                    active_core::ir::SemanticTag::Template => SemanticTag::Template,
                },
                inner: lower_ref(module, *inner, out, map, visiting, depth)?,
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
        depth: u32,
    ) -> Result<NodeId> {
        // A literal's own nesting is caller-controlled too: a 10k-deep array
        // aborted the stack before any reference walk ran (pass 2, #3).
        if depth >= MAX_BRIDGE_DEPTH {
            return Err(Error::Limit {
                kind: "bridge depth",
                limit: MAX_BRIDGE_DEPTH as u64,
            });
        }
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
                    elements.push(push_value(item, out, map, depth + 1)?);
                }
                Inode::Array { elements }
            }
            CoreValue::Table(entries) => {
                let mut fields = Vec::with_capacity(entries.len());
                for (name, item) in entries {
                    fields.push((name.clone(), push_value(item, out, map, depth + 1)?));
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
        visiting: &mut HashSet<u32>,
        depth: u32,
    ) -> Result<NodeId> {
        if let Some(mapped) = map.get(&id.0) {
            return Ok(*mapped);
        }
        if !visiting.insert(id.0) {
            return Err(Error::Cycle { node: id.0 });
        }
        if depth >= MAX_BRIDGE_DEPTH {
            return Err(Error::Limit {
                kind: "bridge depth",
                limit: MAX_BRIDGE_DEPTH as u64,
            });
        }
        let lowered = lower_node(module, id, out, map, visiting, depth + 1)?;
        visiting.remove(&id.0);
        map.insert(id.0, lowered);
        Ok(lowered)
    }

    fn lower_opt(
        module: &CoreModule,
        id: Option<active_core::NodeId>,
        out: &mut InfinityModule,
        map: &mut HashMap<u32, NodeId>,
        visiting: &mut HashSet<u32>,
        depth: u32,
    ) -> Result<Option<NodeId>> {
        match id {
            Some(id) => Ok(Some(lower_ref(module, id, out, map, visiting, depth)?)),
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
    /// Blob identity has no `active-core` 1.4.0 representation, and a secret has
    /// no structural form on the other side: a module that carries a blob or a
    /// secret node is refused with a stable error rather than silently dropping
    /// the fingerprint or exporting the plaintext.
    ///
    /// Loss table: the bridge is lossy beyond those refusals -- provenance
    /// and extensions are dropped entirely, annotation spans are zeroed and
    /// paths rewritten, the schema pointer is dropped. The full table is
    /// the canonical one in the `to_redacted_json` documentation
    /// (INF-INTEROP-06); this function points there instead of repeating
    /// it.
    pub fn to_active_core(module: &InfinityModule) -> Result<CoreModule> {
        // `active-core` models a secret as a plain string. Lowering one would
        // hand the plaintext to every consumer of the bridge, so a
        // secret-bearing module stays in Infinity (ADR-0010).
        if module.has_secret() {
            return Err(Error::Encode(
                "the active-core bridge does not export secret material; keep the module in Infinity",
            ));
        }
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
            Inode::Secret(_) => {
                // `active-core` models a secret as a plain string, so lowering
                // one would hand the plaintext to every consumer of the bridge
                // (INF-INTEROP-04). The `has_secret` gate in `to_active_core`
                // refuses secret-bearing modules first, so this arm is
                // unreachable today -- but it must refuse on its own if the
                // gate ever moves: defence in depth, matching the `Blob` and
                // `ContentAddressed` arms below. Same message as the gate, so
                // the error is identical whichever tripwire fires.
                return Err(Error::Encode(
                    "the active-core bridge does not export secret material; keep the module in Infinity",
                ));
            }
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
            // Keep the machine-readable Active class as the sub-code, and
            // carry the first diagnostic's position and message too
            // (INF-INTEROP-05): the bare code alone left an evaluation
            // failure undebuggable. The message can quote literal values
            // from the evaluated module, which is safe here because
            // `to_active_core` above refuses secret-bearing modules
            // before the engine runs, so no secret material can reach
            // the evaluator or its messages. A failure with no source
            // position (cycle, missing root, secret leak, global budget)
            // reports line 0, column 0 -- the documented "no position"
            // sentinel (parser lines are 1-based). Through this bridge
            // that is every failure today: lowering drops the parser's
            // node spans (`InfinityModule` carries no span store) and the
            // rebuilt `CoreModule` has an empty `node_spans` map, so
            // `EvalError::span()` is `None`. Real eval positions need
            // spans to survive the bridge (see the INF-INTEROP-05 record).
            //
            // `EvalError::span` already returns the first diagnostic's
            // span for `ValidationFailed`; only its message needs the
            // special case, because `Display` for that variant is the
            // bare "validation failed" with the diagnostics inside the
            // variant. That arm is unreachable through this bridge today
            // -- `to_active_core` drops the `Module::schema` pointer and
            // rewrites annotation paths to `node<N>` placeholders, so
            // neither schema nor constraint validation can fail here --
            // but it is the correct mapping if the bridge ever preserves
            // them, and the code map below already names their classes
            // (T002/T003/T004).
            let (line, column) = error
                .span()
                .map(|span| (span.line, span.column))
                .unwrap_or((0, 0));
            let message = match &error {
                active_core::EvalError::ValidationFailed { diagnostics } => diagnostics
                    .first()
                    .map(|diagnostic| diagnostic.message.clone())
                    .unwrap_or_else(|| error.to_string()),
                _ => error.to_string(),
            };
            Error::Evaluation {
                code: active_error_code(error.code()),
                line,
                column,
                message,
            }
        })
    }

    fn active_error_code(code: &'static str) -> &'static str {
        match code {
            "S001" => "active/S001-cycle",
            "S002" => "active/S002-missing-root",
            "S003" => "active/S003-missing-node",
            "T001" => "active/T001-type",
            // INF-INTEROP-05: these classes used to fall through to the
            // generic `active/eval-error`, discarding the diagnostic class
            // the same way the message was discarded. T002/T003/T004 are
            // the `ValidationFailed` classes (schema violation / enum
            // membership / missing required key, active-core 1.4.0
            // `validate.rs`); E019 is `PatchError`, S004 is `SecretLeak`.
            "T002" => "active/T002-schema",
            "T003" => "active/T003-schema-enum",
            "T004" => "active/T004-schema-missing",
            "E019" => "active/E019-patch",
            "S004" => "active/S004-secret-leak",
            "X001" => "active/X001-node-budget",
            "X002" => "active/X002-wall-clock",
            "X003" => "active/X003-depth",
            "X004" => "active/X004-array-length",
            "X005" => "active/X005-keys",
            "X006" => "active/X006-value-size",
            _ => "active/eval-error",
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// INF-INTEROP-04: the `Secret` arm of `convert_node` must refuse
        /// on its own, past the `has_secret` gate. The gate in
        /// `to_active_core` refuses secret-bearing modules first, so this
        /// arm is unreachable through any public entry point today -- this
        /// test calls the lowering function directly, so a future refactor
        /// that moves or bypasses the gate cannot silently re-export secret
        /// plaintext into `active-core`, where a secret is a plain string.
        /// The arm reports exactly the gate's message, so the error is
        /// identical whichever tripwire fires.
        #[test]
        fn convert_node_refuses_a_secret_node() {
            let error = convert_node(&Inode::Secret(crate::ir::SecretBytes::from(
                "hunter2-canary-interop04",
            )))
            .expect_err("a secret node must be refused by the lowering arm itself");
            assert_eq!(error.code(), "infinity/encode", "{error}");
            assert_eq!(
                error.to_string(),
                "cannot encode module: the active-core bridge does not export secret material; keep the module in Infinity",
                "the arm must report exactly the gate's message, so the error is identical whichever tripwire fires"
            );
            assert!(
                !error.to_string().contains("hunter2-canary-interop04"),
                "the refusal must not carry the plaintext anywhere; got {error}"
            );
        }

        /// INF-INTEROP-05: the evaluator's code map must name every class
        /// `EvalError::code()` can produce. Before the fix the validation
        /// (T002/T003/T004), patch (E019) and secret-leak (S004) classes
        /// fell through to the generic `active/eval-error`, discarding
        /// the diagnostic class the same way the message was discarded.
        /// The established classes are pinned too, so a future
        /// active-core code cannot silently join the generic bucket.
        #[test]
        fn active_error_code_names_every_evaluator_class() {
            for (code, expected) in [
                ("S001", "active/S001-cycle"),
                ("S002", "active/S002-missing-root"),
                ("S003", "active/S003-missing-node"),
                ("T001", "active/T001-type"),
                ("T002", "active/T002-schema"),
                ("T003", "active/T003-schema-enum"),
                ("T004", "active/T004-schema-missing"),
                ("E019", "active/E019-patch"),
                ("S004", "active/S004-secret-leak"),
                ("X001", "active/X001-node-budget"),
                ("X002", "active/X002-wall-clock"),
                ("X003", "active/X003-depth"),
                ("X004", "active/X004-array-length"),
                ("X005", "active/X005-keys"),
                ("X006", "active/X006-value-size"),
            ] {
                assert_eq!(active_error_code(code), expected, "class {code}");
            }
            assert_eq!(
                active_error_code("Z999"),
                "active/eval-error",
                "an unknown future class still falls back to the generic code"
            );
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
/// Deepest container nesting a projection will walk.
///
/// The walk is recursive (build, redaction check, protobuf encode), and the
/// module depth ceiling alone is 1024: 600 nested tables overflow the default
/// thread stack in a debug build, which aborts the process instead of refusing
/// (cross-cutting pass 1, #4). 256 is far past any schema and safely inside the
/// smallest stack this crate runs on.
const PROJECTION_DEPTH: usize = 256;

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
    /// An environment lookup, by name, with its fallback value when one
    /// exists. The default is the recursively projected node it points at
    /// (INF-INTEROP-06): a default is a value, so it projects like any
    /// other value -- a secret default becomes the marker, an operator
    /// default its kind tag. `None` renders exactly as before.
    Env {
        /// The environment variable name, redacted like any label.
        name: String,
        /// The projected default, when the `Env` node carries one.
        default: Option<Box<Projected>>,
    },
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
    // Project the *canonical* module, exactly as the protobuf path does. A
    // locator literal is promoted to a secret entry only at canonicalization,
    // so the secret table of a hand-built module would miss it and the
    // projection would publish the literal.
    let image = crate::encode(module)?;
    let canonical = crate::decode(&image)?;
    let module = &canonical;
    // Named, not literal: the same default ceiling `prepare()` enforces
    // (INF-09). The value is unchanged (4096).
    module.validate_structure(u32::MAX as u64, crate::layout::Limits::default().max_depth)?;
    let secrets = secret_texts(module);
    let hash_secrets = secret_bytes(module);
    let mut budget = 0usize;
    let mut redaction = PROJECTION_REDACTION_BUDGET;
    let mut bytes = PROJECTION_BYTES;
    let placeholder = hiding_placeholder(&secrets);
    build_projected(
        module,
        module.root(),
        &secrets,
        &hash_secrets,
        placeholder,
        0,
        &mut budget,
        &mut redaction,
        &mut bytes,
    )
}

/// The module's secret literals, for a caller that projects many nodes.
pub(crate) fn secret_table(module: &InfinityModule) -> Vec<String> {
    secret_texts(module)
}

/// Project one node with an already-computed secret table.
#[allow(clippy::too_many_arguments)]
pub(crate) fn project_node_with(
    module: &InfinityModule,
    id: NodeId,
    secrets: &[String],
    hash_secrets: &[Vec<u8>],
    placeholder: &'static str,
    budget: &mut usize,
    redaction: &mut usize,
    bytes: &mut usize,
) -> Result<Projected> {
    build_projected(
        module,
        Some(id),
        secrets,
        hash_secrets,
        placeholder,
        0,
        budget,
        redaction,
        bytes,
    )
}

/// Scanned bytes one projection may spend redacting.
///
/// A per-string ceiling bounds one scan; a module with many strings would
/// otherwise multiply it, so every redaction in one projection draws from this
/// single budget.
pub(crate) const PROJECTION_REDACTION_BUDGET: usize = 256 << 20;

/// Scan budget for one non-projection export.
///
/// `provenance_lines`, `provenance_json_for`, `value_paths` and `intents` hand
/// text to logs and agents rather than a wire image, so they cannot refuse.
/// Past this budget every remaining value and key saturates to the hiding
/// placeholder: fail-closed, and the work is bounded by the budget itself.
pub(crate) const EXPORT_REDACTION_BUDGET: usize = 64 << 20;

/// Total dotted-path text one [`value_paths`] call may materialize.
///
/// A path is built per node and copies its parent's prefix, so an adversarial
/// deep table turns the map into quadratic text (a 924 KB image measured
/// 29.5 MB); at the permitted `max_depth` the same shape is tens of GB.
pub(crate) const MAX_EXPORT_PATH_BYTES: usize = 16 << 20;

/// Deepest dotted path [`value_paths`] builds before falling back to labels.
pub(crate) const MAX_EXPORT_PATH_DEPTH: usize = 64;

/// Charge one redaction against an export budget; `false` means it is spent.
fn charge_export(text: &str, secrets: &[String], budget: &mut usize) -> bool {
    let cost = crate::canonical::redaction_cost(text, secrets);
    if cost > *budget {
        *budget = 0;
        return false;
    }
    *budget -= cost;
    true
}

/// [`redacted_value`] charged to `budget`; `None` means the budget is spent.
///
/// The caller substitutes the placeholder once, computed per export rather than
/// per value: recomputing it here would scan the whole secret table for every
/// remaining value and undo the bound this budget exists to enforce.
fn redacted_value_capped(text: &str, secrets: &[String], budget: &mut usize) -> Option<String> {
    if !charge_export(text, secrets, budget) {
        return None;
    }
    Some(redacted_value(text, secrets))
}

/// [`redacted_key`] charged to `budget`; `None` means the budget is spent.
///
/// A key has no substitute that keeps its meaning, so the exports stop emitting
/// keys: a spent budget must never fabricate one.
fn redacted_key_capped(text: &str, secrets: &[String], budget: &mut usize) -> Option<String> {
    if !charge_export(text, secrets, budget) {
        return None;
    }
    Some(redacted_key(text, secrets))
}

/// Bytes of projected text one projection may materialize.
///
/// A DAG can reference one large string from many fields, so a node-count
/// budget alone lets the tree expand past memory before the visit budget trips.
const PROJECTION_BYTES: usize = 256 << 20;

fn charge_projection_bytes(budget: &mut usize, text: &str) -> Result<()> {
    *budget = budget.checked_sub(text.len()).ok_or(Error::Limit {
        kind: "projection bytes",
        limit: PROJECTION_BYTES as u64,
    })?;
    Ok(())
}

/// [`hiding_placeholder`] for a raw-byte table: the marker is unsafe when any
/// secret's text is a substring of it.
fn hiding_placeholder_text(secrets: &[Vec<u8>]) -> &'static str {
    let texts: Vec<String> = secrets
        .iter()
        .map(|secret| String::from_utf8_lossy(secret).into_owned())
        .collect();
    hiding_placeholder(&texts)
}

/// The text a projection substitutes for secret material.
///
/// [`SECRET_MARKER`] unless a secret is itself a substring of the marker: then
/// inserting the marker would publish that secret, and the only replacement
/// that never contains a secret is the empty string.
pub(crate) fn hiding_placeholder(secrets: &[String]) -> &'static str {
    if secrets
        .iter()
        .any(|secret| !secret.is_empty() && SECRET_MARKER.contains(secret.as_str()))
    {
        ""
    } else {
        SECRET_MARKER
    }
}

/// Redact free text for a projection, charging one shared scan budget.
///
/// When the marker is safe this is [`redact_text`]. When a secret occurs inside
/// the marker, insertions are replaced by deletions and the pass repeats until
/// the text is clean; a join that keeps recreating a secret collapses the whole
/// value to the empty string.
pub(crate) fn redact_within(text: &str, secrets: &[String], budget: &mut usize) -> Result<String> {
    let cost = crate::canonical::redaction_cost(text, secrets);
    if cost > *budget {
        return Err(Error::Limit {
            kind: "projection redaction scan bytes",
            limit: PROJECTION_REDACTION_BUDGET as u64,
        });
    }
    *budget -= cost;
    if hiding_placeholder(secrets) == SECRET_MARKER {
        return Ok(redact_text(text, secrets));
    }
    Ok(delete_secrets(text, secrets))
}

/// Remove every secret occurrence until the text is clean.
///
/// Used when [`SECRET_MARKER`] itself contains a secret and therefore cannot be
/// inserted. Deleting can join the text around it into a new secret, so the
/// pass repeats; a text that keeps recreating one collapses to empty.
fn delete_secrets(text: &str, secrets: &[String]) -> String {
    let mut out = text.to_string();
    for _ in 0..8 {
        let mut matched: Vec<&String> = secrets
            .iter()
            .filter(|secret| !secret.is_empty() && out.contains(secret.as_str()))
            .collect();
        if matched.is_empty() {
            return out;
        }
        matched.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        for secret in matched {
            out = out.replace(secret.as_str(), "");
        }
    }
    String::new()
}

/// Escape free text for the `key=value` line codec: a newline or an `=` in a
/// value would otherwise forge a field for a line-oriented consumer.
fn escape_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '=' => out.push_str("\\="),
            other => out.push(other),
        }
    }
    out
}

/// A value-position string: the whole text becomes the placeholder as soon as
/// it contains a secret literal.
pub(crate) fn redacted_value_within(
    text: &str,
    secrets: &[String],
    budget: &mut usize,
) -> Result<String> {
    let cost = crate::canonical::redaction_cost(text, secrets);
    if cost > *budget {
        return Err(Error::Limit {
            kind: "projection redaction scan bytes",
            limit: PROJECTION_REDACTION_BUDGET as u64,
        });
    }
    *budget -= cost;
    Ok(redacted_value(text, secrets))
}

/// A value-position string: the whole text becomes the marker as soon as it
/// contains a secret literal, so a partial copy cannot leak and a second pass is
/// a fixpoint.
pub(crate) fn redacted_value(text: &str, secrets: &[String]) -> String {
    if secrets
        .iter()
        .any(|secret| !secret.is_empty() && text.contains(secret.as_str()))
    {
        hiding_placeholder(secrets).to_string()
    } else {
        text.to_string()
    }
}

/// A redaction handle for one module's secret literals.
///
/// A cone, a restricted subtree or a projection derived from a module no longer
/// contains the secret node itself, so the redactor cannot rediscover the text
/// a copy must be compared against. The handle carries that text for the life of
/// the operation and exposes no accessor: only rewriting. `Debug` prints the
/// count.
pub struct Redactor {
    secrets: Vec<String>,
    /// The same literals as bytes: a binary surface (a hash, a payload) can
    /// copy a secret a text comparison never sees (pass 2, #4).
    raw: Vec<Vec<u8>>,
    placeholder: String,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Redactor")
            .field("secrets", &self.secrets.len())
            .finish()
    }
}

impl Redactor {
    /// Collect the secret literals a module names.
    pub fn for_module(module: &InfinityModule) -> Self {
        let secrets = secret_texts(module);
        let raw = secret_bytes(module);
        let placeholder = hiding_placeholder(&secrets).to_string();
        Self {
            secrets,
            raw,
            placeholder,
        }
    }

    /// True when the module names no secret, so redaction is a no-op.
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Rewrite `module` in place until no text carries a secret literal.
    ///
    /// Every secret node becomes [`SECRET_MARKER`]; a `Str`, `Ident`, `Env`
    /// name, table or schema field name, interpolated literal, blob media type,
    /// deprecation note, annotation text or provenance text that contains a
    /// secret becomes the marker whole (value position) or loses the occurrence
    /// (metadata prose), the same rule the projections apply.
    ///
    /// The node set is untouched, so an id resolved against the source module
    /// still names the same node. Returns [`Error::Encode`] when two field or
    /// binding names redact to the same key.
    pub fn redact(&self, module: &mut InfinityModule) -> Result<()> {
        let mut budget = PROJECTION_REDACTION_BUDGET;
        for index in 0..module.node_count() {
            let id = NodeId(index as u32);
            let Some(node) = module.get(id) else {
                continue;
            };
            let replacement = match node {
                Inode::Secret(_) | Inode::SecretRef { .. } => {
                    Some(Inode::Str(self.placeholder.clone()))
                }
                Inode::Str(text) => {
                    let redacted = redacted_value_within(text, &self.secrets, &mut budget)?;
                    (redacted != *text).then_some(Inode::Str(redacted))
                }
                Inode::Ident(text) => {
                    // A name is a label: the projection replaces occurrences,
                    // not the whole text, so the two must agree (pass 2, #8).
                    let redacted = redact_within(text, &self.secrets, &mut budget)?;
                    (redacted != *text).then_some(Inode::Ident(redacted))
                }
                // A custom unit name is text: a unit that copies a secret
                // must not survive the redaction (pass 2, #1).
                Inode::Quantity {
                    value,
                    unit: UnitTag::Named(name),
                } => {
                    let redacted = redact_within(name, &self.secrets, &mut budget)?;
                    (redacted != *name).then(|| Inode::Quantity {
                        value: *value,
                        unit: UnitTag::Named(redacted),
                    })
                }
                Inode::Env { name, default } => {
                    let redacted = redact_within(name, &self.secrets, &mut budget)?;
                    (redacted != *name).then(|| Inode::Env {
                        name: redacted,
                        default: *default,
                    })
                }
                Inode::Table { fields } => {
                    let (fields, changed) = redact_field_names(fields, &self.secrets, &mut budget)?;
                    changed.then_some(Inode::Table { fields })
                }
                Inode::SchemaTable { fields, closed } => {
                    let (fields, changed) = redact_field_names(fields, &self.secrets, &mut budget)?;
                    changed.then_some(Inode::SchemaTable {
                        fields,
                        closed: *closed,
                    })
                }
                Inode::Interpolate { parts } => {
                    let mut out = Vec::with_capacity(parts.len());
                    let mut changed = false;
                    for part in parts {
                        match part {
                            InterpPart::Literal(text) => {
                                let redacted =
                                    redacted_value_within(text, &self.secrets, &mut budget)?;
                                changed |= redacted != *text;
                                out.push(InterpPart::Literal(redacted));
                            }
                            other => out.push(other.clone()),
                        }
                    }
                    changed.then_some(Inode::Interpolate { parts: out })
                }
                Inode::SchemaField(spec) => {
                    let mut spec = spec.clone();
                    let mut changed = false;
                    if let Some(note) = &spec.deprecated {
                        let redacted = redact_within(note, &self.secrets, &mut budget)?;
                        changed |= redacted != *note;
                        spec.deprecated = Some(redacted);
                    }
                    changed |= self.redact_type(&mut spec.typ, &mut budget)?;
                    changed.then_some(Inode::SchemaField(spec))
                }
                Inode::Constrained { target, constraint } => {
                    let mut constraint = constraint.clone();
                    if self.redact_constraint(&mut constraint, &mut budget)? {
                        Some(Inode::Constrained {
                            target: *target,
                            constraint,
                        })
                    } else {
                        None
                    }
                }
                Inode::Patch(op) => {
                    let mut op = op.clone();
                    let changed = match &mut op {
                        PatchOp::Set { path, .. } => {
                            let redacted = redacted_value_within(path, &self.secrets, &mut budget)?;
                            let changed = redacted != *path;
                            *path = redacted;
                            changed
                        }
                        PatchOp::Remove { path } => {
                            let redacted = redacted_value_within(path, &self.secrets, &mut budget)?;
                            let changed = redacted != *path;
                            *path = redacted;
                            changed
                        }
                        PatchOp::Rename { from, to } => {
                            let redacted_from =
                                redacted_value_within(from, &self.secrets, &mut budget)?;
                            let redacted_to =
                                redacted_value_within(to, &self.secrets, &mut budget)?;
                            let changed = redacted_from != *from || redacted_to != *to;
                            *from = redacted_from;
                            *to = redacted_to;
                            changed
                        }
                    };
                    changed.then_some(Inode::Patch(op))
                }
                Inode::Blob {
                    hash,
                    size,
                    tainted,
                    media_type,
                    payload,
                } => {
                    let redacted = redacted_value_within(media_type, &self.secrets, &mut budget)?;
                    (redacted != *media_type).then(|| Inode::Blob {
                        hash: *hash,
                        size: *size,
                        tainted: *tainted,
                        media_type: redacted,
                        payload: payload.clone(),
                    })
                }
                _ => None,
            };
            if let Some(replacement) = replacement {
                *module.node_mut(id)? = replacement;
            }
        }
        self.redact_metadata(module, &mut budget)?;
        self.reject_binary_copies(module)?;
        redact_binding_names(module, &self.secrets, &mut budget)
    }

    /// Refuse a module whose binary surfaces copy a secret.
    ///
    /// The codec refuses these when the module still holds the secret node, but
    /// a cone built from a source whose secret lives outside it carries no
    /// secret node: the encode would then accept the copy (pass 2, #4).
    fn reject_binary_copies(&self, module: &InfinityModule) -> Result<()> {
        if self.raw.is_empty() {
            return Ok(());
        }
        let matches = |bytes: &[u8]| {
            self.raw
                .iter()
                .any(|secret| !secret.is_empty() && secret == bytes)
        };
        let carries = |payload: &[u8]| {
            self.raw.iter().any(|secret| {
                !secret.is_empty()
                    && secret.len() <= payload.len()
                    && payload.windows(secret.len()).any(|window| window == secret)
            })
        };
        for node in module.nodes() {
            if let Inode::Blob { hash, payload, .. } = node {
                if matches(hash) {
                    return Err(Error::Encode("blob hash equals a secret"));
                }
                if let Some(payload) = payload {
                    if carries(payload) {
                        return Err(Error::Encode("blob payload carries a secret literal"));
                    }
                }
            }
        }
        for (_, payload) in module.extensions() {
            if carries(payload) {
                return Err(Error::Encode("extension payload carries a secret literal"));
            }
        }
        Ok(())
    }

    /// Redact an enum type's members.
    fn redact_type(&self, typ: &mut TypeSpec, budget: &mut usize) -> Result<bool> {
        let TypeSpec::Enum(members) = typ else {
            return Ok(false);
        };
        let mut changed = false;
        for member in members.iter_mut() {
            let redacted = redacted_value_within(member, &self.secrets, budget)?;
            changed |= redacted != *member;
            *member = redacted;
        }
        Ok(changed)
    }

    /// Redact an enum, pattern or custom constraint.
    fn redact_constraint(&self, constraint: &mut Constraint, budget: &mut usize) -> Result<bool> {
        match constraint {
            Constraint::Enum(members) => {
                let mut changed = false;
                for member in members.iter_mut() {
                    let redacted = redacted_value_within(member, &self.secrets, budget)?;
                    changed |= redacted != *member;
                    *member = redacted;
                }
                Ok(changed)
            }
            Constraint::Pattern(text) | Constraint::Custom(text) => {
                let redacted = redacted_value_within(text, &self.secrets, budget)?;
                let changed = redacted != *text;
                *text = redacted;
                Ok(changed)
            }
            Constraint::MinMax { .. } | Constraint::Odd => Ok(false),
        }
    }

    /// Redact annotation and provenance prose.
    fn redact_metadata(&self, module: &mut InfinityModule, budget: &mut usize) -> Result<()> {
        let mut changed = false;
        let mut kept: Vec<(NodeId, AnnotationKind)> =
            Vec::with_capacity(module.annotations().len());
        for annotation in module.annotations() {
            let kind = match &annotation.kind {
                AnnotationKind::Intent(text) => {
                    let redacted = redact_within(text, &self.secrets, budget)?;
                    changed |= redacted != *text;
                    AnnotationKind::Intent(redacted)
                }
                AnnotationKind::Constraint { source, expr } => {
                    let redacted = redact_within(source, &self.secrets, budget)?;
                    changed |= redacted != *source;
                    AnnotationKind::Constraint {
                        source: redacted,
                        expr: *expr,
                    }
                }
                other => other.clone(),
            };
            kept.push((annotation.node, kind));
        }
        if changed {
            module.clear_annotations();
            for (node, kind) in kept {
                module.annotate(node, kind);
            }
        }

        let Some(mut provenance) = module.provenance().cloned() else {
            return Ok(());
        };
        let mut changed = false;
        for field in [
            &mut provenance.producer,
            &mut provenance.model,
            &mut provenance.tool,
        ] {
            if let Some(text) = field {
                let redacted = redact_within(text, &self.secrets, budget)?;
                changed |= redacted != *text;
                *field = Some(redacted);
            }
        }
        if let Some(parent) = provenance.parent {
            if self
                .raw
                .iter()
                .any(|secret| secret.len() == 32 && secret.as_slice() == parent)
            {
                provenance.parent = None;
                changed = true;
            }
        }
        let mut entries = Vec::with_capacity(provenance.entries.len());
        for mut entry in std::mem::take(&mut provenance.entries) {
            let redacted = redact_within(&entry.key, &self.secrets, budget)?;
            changed |= redacted != entry.key;
            entry.key = redacted;
            match &mut entry.value {
                ProvValue::Text(text) => {
                    let redacted = redact_within(text, &self.secrets, budget)?;
                    changed |= redacted != *text;
                    *text = redacted;
                }
                ProvValue::Hash(hash) => {
                    if self
                        .raw
                        .iter()
                        .any(|secret| secret.len() == 32 && secret.as_slice() == hash)
                    {
                        // A content address that copies a secret is the secret.
                        changed = true;
                        continue;
                    }
                }
                ProvValue::Int(_) | ProvValue::Flag(_) => {}
            }
            entries.push(entry);
        }
        provenance.entries = entries;
        if changed {
            module.set_provenance(Some(provenance));
        }
        Ok(())
    }
}

/// A copy of `module` in which no text carries secret material.
///
/// This is the projection rule applied to the image itself. The canonical encode
/// runs first, while the secret nodes are still present: that is when the codec
/// can refuse a free-text or binary copy and redact the metadata prose, and when
/// a secret locator is promoted out of the public string heap.
pub fn redact_module(module: &InfinityModule) -> Result<InfinityModule> {
    let canonical = crate::encode(module)?;
    let mut redacted = crate::decode(&canonical)?;
    let redactor = Redactor::for_module(&redacted);
    if !redacted.nodes().iter().any(|node| node.is_secret()) && redactor.is_empty() {
        return Ok(redacted);
    }
    redactor.redact(&mut redacted)?;
    Ok(redacted)
}

/// [`redact_module`] over image bytes, returning image bytes.
pub fn redact_image(bytes: &[u8]) -> Result<Vec<u8>> {
    let module = crate::decode(bytes)?;
    crate::encode(&redact_module(&module)?)
}

/// Redact field names, refusing a collapse onto one key.
fn redact_field_names(
    fields: &[(String, NodeId)],
    secrets: &[String],
    budget: &mut usize,
) -> Result<(Vec<(String, NodeId)>, bool)> {
    let mut out = Vec::with_capacity(fields.len());
    let mut changed = false;
    for (name, id) in fields {
        let redacted = redact_within(name, secrets, budget)?;
        changed |= redacted != *name;
        out.push((redacted, *id));
    }
    if changed {
        let mut seen = std::collections::BTreeSet::new();
        if out.iter().any(|(name, _)| !seen.insert(name.clone())) {
            return Err(Error::Encode("two field names redact to the same key"));
        }
    }
    Ok((out, changed))
}

/// Redact binding names, refusing a collapse onto one key.
fn redact_binding_names(
    module: &mut InfinityModule,
    secrets: &[String],
    budget: &mut usize,
) -> Result<()> {
    let mut out = Vec::with_capacity(module.bindings().len());
    let mut changed = false;
    for (name, id) in module.bindings() {
        let redacted = redact_within(name, secrets, budget)?;
        changed |= redacted != *name;
        out.push((redacted, *id));
    }
    if !changed {
        return Ok(());
    }
    let mut seen = std::collections::BTreeSet::new();
    if out.iter().any(|(name, _)| !seen.insert(name.clone())) {
        return Err(Error::Encode("two binding names redact to the same key"));
    }
    module.clear_bindings();
    for (name, id) in out {
        module.bind(name, id);
    }
    Ok(())
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
    if hiding_placeholder(secrets) == SECRET_MARKER {
        return redact_text(text, secrets);
    }
    delete_secrets(text, secrets)
}

/// Whether a node resolves to secret material, following `Ref` and `Semantic`.
///
/// Reference wrappers must be transparent for taint: an interpolated
/// `${ref_to_secret}` has to redact the whole string, not render it as `${}`.
fn resolves_to_secret(
    module: &InfinityModule,
    id: NodeId,
    depth: usize,
    budget: &mut usize,
) -> Result<bool> {
    *budget = budget.saturating_add(1);
    if *budget > PROJECTION_NODE_BUDGET {
        return Err(Error::Limit {
            kind: "projection node budget",
            limit: PROJECTION_NODE_BUDGET as u64,
        });
    }
    if depth > PROJECTION_DEPTH {
        // A pathological chain is treated as secret: fail closed.
        return Ok(true);
    }
    Ok(match module.get(id) {
        Some(Inode::Secret(_)) | Some(Inode::SecretRef { .. }) => true,
        // Every wrapper that passes a value through is transparent for taint:
        // a secret reached through one of them must redact the outer string,
        // not print its shape.
        Some(Inode::Ref(inner) | Inode::Semantic { inner, .. }) => {
            resolves_to_secret(module, *inner, depth + 1, budget)?
        }
        Some(Inode::Quantity { value, .. }) => {
            resolves_to_secret(module, *value, depth + 1, budget)?
        }
        Some(Inode::Unary { expr, .. }) => resolves_to_secret(module, *expr, depth + 1, budget)?,
        Some(Inode::Binary { lhs, rhs, .. }) => {
            resolves_to_secret(module, *lhs, depth + 1, budget)?
                || resolves_to_secret(module, *rhs, depth + 1, budget)?
        }
        Some(Inode::Constrained { target, .. }) => {
            resolves_to_secret(module, *target, depth + 1, budget)?
        }
        Some(Inode::Patch(crate::ir::PatchOp::Set { value, .. })) => {
            resolves_to_secret(module, *value, depth + 1, budget)?
        }
        Some(Inode::ContentAddressed { data, .. }) => {
            resolves_to_secret(module, *data, depth + 1, budget)?
        }
        Some(Inode::Env {
            default: Some(fallback),
            ..
        }) => resolves_to_secret(module, *fallback, depth + 1, budget)?,
        Some(Inode::Interpolate { parts }) => {
            let mut found = false;
            for part in parts {
                if let crate::ir::InterpPart::Expr(inner) = part {
                    found = found || resolves_to_secret(module, *inner, depth + 1, budget)?;
                }
            }
            found
        }
        Some(node) => node.is_secret(),
        None => false,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_projected(
    module: &InfinityModule,
    id: Option<NodeId>,
    secrets: &[String],
    hash_secrets: &[Vec<u8>],
    placeholder: &'static str,
    depth: usize,
    budget: &mut usize,
    redaction: &mut usize,
    bytes: &mut usize,
) -> Result<Projected> {
    if depth > PROJECTION_DEPTH {
        return Err(Error::Limit {
            kind: "projection depth",
            limit: PROJECTION_DEPTH as u64,
        });
    }
    *budget += 1;
    if *budget > PROJECTION_NODE_BUDGET {
        return Err(Error::Limit {
            kind: "projection node budget",
            limit: PROJECTION_NODE_BUDGET as u64,
        });
    }
    let value = match id.and_then(|id| module.get(id)) {
        None => Projected::Null,
        Some(node) => match node {
            Inode::Null => Projected::Null,
            Inode::Bool(flag) => Projected::Bool(*flag),
            Inode::Int(number) => Projected::Int(*number),
            Inode::Float(number) => Projected::Float(*number),
            Inode::Str(text) => {
                let text = redacted_value_within(text, secrets, redaction)?;
                charge_projection_bytes(bytes, &text)?;
                Projected::Text(text)
            }
            Inode::Ident(text) => {
                let text = redact_within(text, secrets, redaction)?;
                charge_projection_bytes(bytes, &text)?;
                Projected::Text(text)
            }
            Inode::DurationMs(ms) => Projected::DurationMs(*ms),
            Inode::Quantity { value, unit } => Projected::Quantity(
                Box::new(build_projected(
                    module,
                    Some(*value),
                    secrets,
                    hash_secrets,
                    placeholder,
                    depth + 1,
                    budget,
                    redaction,
                    bytes,
                )?),
                {
                    let unit = redact_within(unit.name(), secrets, redaction)?;
                    charge_projection_bytes(bytes, &unit)?;
                    unit
                },
            ),
            Inode::Array { elements } => Projected::Array(
                elements
                    .iter()
                    .map(|id| {
                        build_projected(
                            module,
                            Some(*id),
                            secrets,
                            hash_secrets,
                            placeholder,
                            depth + 1,
                            budget,
                            redaction,
                            bytes,
                        )
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
            Inode::Table { fields } => {
                let mut projected = Vec::with_capacity(fields.len());
                for (name, id) in fields {
                    let key = redact_within(name, secrets, redaction)?;
                    charge_projection_bytes(bytes, &key)?;
                    projected.push((
                        key,
                        build_projected(
                            module,
                            Some(*id),
                            secrets,
                            hash_secrets,
                            placeholder,
                            depth + 1,
                            budget,
                            redaction,
                            bytes,
                        )?,
                    ));
                }
                // A projection is deterministic over the module's *content*,
                // not its in-memory order, so fields are emitted sorted by
                // their redacted name. Two names that redact to the same key
                // would make a JSON reader drop one silently.
                projected.sort_by(|a, b| a.0.cmp(&b.0));
                if projected.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                    return Err(Error::Encode("two field names redact to the same key"));
                }
                Projected::Record(projected)
            }
            Inode::Secret(_) | Inode::SecretRef { .. } => Projected::Text(placeholder.to_string()),
            Inode::Ref(id) => build_projected(
                module,
                Some(*id),
                secrets,
                hash_secrets,
                placeholder,
                depth + 1,
                budget,
                redaction,
                bytes,
            )?,
            Inode::Env { name, default } => {
                let name = redact_within(name, secrets, redaction)?;
                charge_projection_bytes(bytes, &name)?;
                // The default is a value, so it projects through the same
                // recursive call as every other node (INF-INTEROP-06): the
                // full redaction applies, and a secret default becomes the
                // marker instead of rendering in plaintext. A default CAN
                // be secret -- `Inode::Env.default` is an arbitrary node
                // id with no kind check, and the suite itself builds an
                // `Env` whose default is a `Secret` node. The recursion
                // shares the depth, node-budget and byte counters, so a
                // default cannot spend a second allowance.
                let default = match default {
                    Some(id) => Some(Box::new(build_projected(
                        module,
                        Some(*id),
                        secrets,
                        hash_secrets,
                        placeholder,
                        depth + 1,
                        budget,
                        redaction,
                        bytes,
                    )?)),
                    None => None,
                };
                Projected::Env { name, default }
            }
            Inode::Interpolate { parts } => {
                let mut text = String::new();
                let mut tainted = false;
                for part in parts {
                    match part {
                        InterpPart::Literal(literal) => text.push_str(literal),
                        InterpPart::Expr(id) => {
                            if resolves_to_secret(module, *id, 0, budget)? {
                                tainted = true;
                            } else {
                                text.push_str("${}");
                            }
                        }
                    }
                }
                if tainted {
                    Projected::Text(placeholder.to_string())
                } else {
                    let text = redacted_value_within(&text, secrets, redaction)?;
                    charge_projection_bytes(bytes, &text)?;
                    Projected::Text(text)
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
            Inode::Semantic { inner, .. } => build_projected(
                module,
                Some(*inner),
                secrets,
                hash_secrets,
                placeholder,
                depth + 1,
                budget,
                redaction,
                bytes,
            )?,
            Inode::Blob {
                hash,
                size,
                tainted,
                media_type,
                ..
            } => {
                // A blob hash is published verbatim. A hash that copies a
                // 32-byte secret would publish it, so the projection refuses
                // a hand-built module the encoder would already have refused.
                if hash_secrets
                    .iter()
                    .any(|secret| !secret.is_empty() && secret.as_slice() == hash)
                {
                    return Err(Error::Encode("blob hash equals a secret"));
                }
                Projected::Blob {
                    hash: *hash,
                    size: *size,
                    media_type: if *tainted {
                        placeholder.to_string()
                    } else {
                        let media_type = redact_within(media_type, secrets, redaction)?;
                        charge_projection_bytes(bytes, &media_type)?;
                        media_type
                    },
                    tainted: *tainted,
                }
            }
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
    /// - non-finite floats project as a tagged object (`{"$float": "NaN"}`;
    ///   `"Infinity"`, `"-Infinity"`), never as JSON `null`: a NaN used to
    ///   render as `null`, indistinguishable from a real null (INF-INTEROP-03);
    /// - annotations and provenance project as data, never as executable text.
    ///
    /// # Loss table (INF-INTEROP-06)
    ///
    /// Projections are lossy by design, and the loss is documented here
    /// rather than left for a consumer to discover: this table is the
    /// canonical copy. `to_protobuf` and `to_active_core` point here
    /// instead of repeating it, so the three surfaces cannot drift apart.
    /// `docs/spec/projection.md` states shapes; it does not restate this
    /// table.
    ///
    /// A loss is a silent change to what a consumer sees; a refusal is
    /// loud (an `Err`), and refusals are listed separately at the end.
    /// "Preserved" means the same value, not merely the same shape.
    ///
    /// ## The shared projected tree: JSON and Protobuf render the same tree
    ///
    /// Both renderers consume the `Projected` tree built by
    /// `build_projected`, so they cannot disagree about what is allowed
    /// to leave the process. Every row below applies to both, unless the
    /// row says otherwise.
    ///
    /// | Source | What the projection carries | What is lost |
    /// | --- | --- | --- |
    /// | `Secret` / `SecretRef` | the marker (`***SECRET***`) | the secret bytes, and the locator text: a `SecretRef` never projects its locator |
    /// | `Str` containing a secret literal | the marker, whole value | the string itself: a partial copy cannot leak, so the whole value goes |
    /// | `Str` otherwise | the text, verbatim | nothing |
    /// | `Ident` | the name, redacted per occurrence | a secret embedded in the name is replaced in place, so the name can change |
    /// | `Env` without a default | `{"$env": name}` / `Env{name}` | nothing; the name is redacted per occurrence like any label |
    /// | `Env` with a default | `{"$env": name, "default": <projected default>}` / `Env{name, default}` | nothing since INF-INTEROP-06: before it, the default was dropped silently. The default is a nested projected value, so a secret default becomes the marker and an operator default its kind tag |
    /// | `Binary`, `Unary`, `Constrained`, `Patch`, `SchemaField`, `SchemaTable`, `SchemaArray`, `ContentAddressed` | `{"$expr": "<kind>"}` / `Expr{kind}` | everything except the kind name: operators and operands, constraint bounds, patch ops, schema bounds / patterns / defaults / deprecation notes, blob media type and data |
    /// | `Semantic` | the inner value, projected | the tag (`Prompt` / `Policy` / `Template`): the wrapper is transparent |
    /// | `Ref` | the referenced value, projected | the indirection itself: a reference has no data of its own |
    /// | `Interpolate` | flattened text, `${}` where an expression part stood | the part structure: which expression each `${}` stood for. An interpolation that resolves to a secret renders as the marker, whole string |
    /// | `Blob` | identity only: hash, size, media type, taint | the payload, always. A tainted blob's media type becomes the marker |
    /// | `Quantity` | `{"value": v, "unit": "<name>"}` | nothing: a unit IS its name (`UnitTag::name`) |
    /// | `Float`, non-finite | JSON: `{"$float": "NaN"}` / `"Infinity"` / `"-Infinity"` (INF-INTEROP-03); Protobuf: the real IEEE double | JSON: the class only -- NaN payload bits are lost (the canonical form already normalises every NaN to one quiet NaN). Protobuf: nothing |
    /// | Table / record | fields in canonical (sorted, redacted-name) order | the in-memory field order. Two names that redact to one key are refused, not merged |
    /// | `DurationMs` | `{"ms": n}` | nothing |
    ///
    /// ## JSON only (`to_redacted_json` / `to_redacted_json_pretty`)
    ///
    /// | Source | What the projection carries | What is lost |
    /// | --- | --- | --- |
    /// | Envelope | the root value only | bindings, annotations, provenance, extensions, content hash and image size: a consumer that needs the metadata reads the Protobuf form |
    /// | Data key starting with `$` | the key, escaped by doubling (`$env` becomes `$$env`) | the unescaped spelling: markers (`$env`, `$expr`, `$float`, `$active.blob`) are reserved, so data can never impersonate one |
    ///
    /// ## Protobuf only (`to_protobuf`)
    ///
    /// | Source | What the projection carries | What is lost |
    /// | --- | --- | --- |
    /// | Envelope | root, bindings, annotations, provenance, extensions, content hash, total size | nothing the module holds -- except the annotation path/span, which Infinity annotations do not carry in the first place |
    /// | `Env` default | `Env.default`, field 2, a nested `Value`; omitted when the `Env` has no default | nothing. The field is additive (spec §4.2: new fields take the next free number), so a reader built against the old schema skips it |
    /// | Record keys | names verbatim | nothing: the `$` escaping is JSON-only, the Protobuf form has no markers to impersonate |
    /// | Provenance entries | first entry per key | later entries sharing a key (same rule as `provenance_lines`) |
    ///
    /// ## The `active-core` bridge (`to_active_core`)
    ///
    /// | Source | What the bridge carries | What is lost |
    /// | --- | --- | --- |
    /// | Provenance | nothing | the whole provenance block: `active-core` 1.4.0 `Module` has no provenance field (verified against the 1.4.0 registry source), so there is nowhere to put it |
    /// | Extensions | nothing | every extension (tag and payload): `active-core` 1.4.0 `Module` has no extensions field |
    /// | `Module::schema` pointer and `schemas` map | nothing | the document schema: neither survives, so schema/constraint validation (T002/T003/T004) can never fail through `evaluate` |
    /// | Annotation spans | zeroed (`line 0, column 0`) | every diagnostic position: `InfinityModule` carries no span store, and the rebuilt `CoreModule` has an empty `node_spans` map |
    /// | Annotation paths | `node<N>` placeholders | the original dotted path |
    /// | `SchemaField` span | `None` | the span only; bounds, pattern and default convert |
    /// | Everything else (nodes, edges, bindings, root, annotation kinds) | converted 1:1 | nothing -- including the `Env` default, which converts (`CoreNode::Env { default }`) |
    ///
    /// The reverse direction is lossy too: `from_active_core` reads only
    /// the arena, bindings, root and annotations, so a `CoreModule`'s
    /// diagnostics, source name and style, spans, files, healing, trivia,
    /// includes, profiles, patches, schema, schemas and `depends_on`
    /// never reach Infinity.
    ///
    /// ## Refusals, not losses
    ///
    /// These are loud errors, never silent drops: a secret-bearing module
    /// is refused by `to_active_core` (`active-core` models a secret as a
    /// plain string); a module carrying a `Blob` or `ContentAddressed`
    /// node is refused by `to_active_core` (no `active-core` 1.4.0
    /// counterpart; `TypeSpec::Blob` likewise); a module whose opaque
    /// extension payload contains a secret literal is refused by
    /// `to_protobuf`; a projection deeper than 256 edges, past the
    /// 100 000-visit node budget, or with two names redacting to one key
    /// is refused rather than truncated.
    ///
    /// # Example
    ///
    /// An `Env` with a default renders the default as a nested projected
    /// value; without one it renders exactly as it always has:
    ///
    /// ```
    /// use active_infinity::{InfinityModule, Inode};
    /// use active_infinity::interop::to_redacted_json;
    ///
    /// let mut module = InfinityModule::new();
    /// let default = module.push(Inode::Str("/home/dave".into()));
    /// let env = module.push(Inode::Env {
    ///     name: "HOME".into(),
    ///     default: Some(default),
    /// });
    /// module.set_root(Some(env));
    /// assert_eq!(
    ///     to_redacted_json(&module).unwrap(),
    ///     r#"{"$env":"HOME","default":"/home/dave"}"#
    /// );
    ///
    /// let mut plain = InfinityModule::new();
    /// let env = plain.push(Inode::Env {
    ///     name: "HOME".into(),
    ///     default: None,
    /// });
    /// plain.set_root(Some(env));
    /// assert_eq!(
    ///     to_redacted_json(&plain).unwrap(),
    ///     r#"{"$env":"HOME"}"#
    /// );
    /// ```
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
            Projected::Float(number) => {
                // `serde_json::Value::from(f64)` yields `Value::Null` for a
                // non-finite float, so a NaN or an infinity used to render as
                // JSON `null` -- silently, with no error and no marker,
                // indistinguishable from a real null while the protobuf
                // projection of the same module preserves the NaN bits
                // (INF-INTEROP-03). A non-finite float is therefore rendered
                // as a tagged object, following this renderer's existing
                // marker convention (`$env`, `$expr`, `$active.blob`). The tag
                // is unambiguous: a real null renders as bare `null`, a real
                // string as a bare JSON string, and a data record key starting
                // with `$` is escaped by doubling in the `Record` arm above,
                // so no data record can produce a bare `{"$float": ...}`
                // object. The tag preserves the float class only, not NaN
                // payload bits -- JSON has no vocabulary for them, and the
                // canonical form already normalizes every NaN to one quiet
                // NaN (`layout::canonical_f64`), so the class is exactly what
                // the canonical form preserves.
                if number.is_finite() {
                    serde_json::Value::from(*number)
                } else if number.is_nan() {
                    serde_json::json!({ "$float": "NaN" })
                } else if *number == f64::INFINITY {
                    serde_json::json!({ "$float": "Infinity" })
                } else {
                    serde_json::json!({ "$float": "-Infinity" })
                }
            }
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
                    // A data key that starts with `$` would be byte-identical
                    // to a JSON marker (`$env`, `$expr`, `$active.blob`), so it
                    // is escaped here, in the JSON renderer only: the protobuf
                    // projection has no markers and keeps the module's names.
                    let mut key = name.clone();
                    if key.starts_with('$') {
                        key.insert(0, '$');
                    }
                    map.insert(key, to_serde(value));
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
            Projected::Env { name, default } => match default {
                // No default: exactly the shape Env always rendered,
                // `{"$env": name}`. A default gains the field, as a nested
                // projected value (INF-INTEROP-06): a string default stays
                // a JSON string, an integer stays a number, an operator
                // default collapses to its `$expr` tag. The `default` key
                // is part of the marker object, like `$float` and `$expr`:
                // a data record can never produce it, because a data key
                // starting with `$` is escaped by doubling in the `Record`
                // arm above.
                Some(default) => {
                    serde_json::json!({ "$env": name, "default": to_serde(default) })
                }
                None => serde_json::json!({ "$env": name }),
            },
            Projected::Expr(kind) => serde_json::json!({ "$expr": kind }),
        }
    }

    /// Project provenance as JSON, redacting every text field and key against
    /// `secrets` (the module's secret literals).
    ///
    /// This projection never fails: a redacted-key collision keeps the first
    /// entry (the same rule as [`provenance_lines`]).
    ///
    /// It is lossy on budget exhaustion: once the shared export redaction
    /// budget (`EXPORT_REDACTION_BUDGET`, 64 MiB) is spent, text values
    /// saturate to the hiding placeholder and the entry list ends -- later
    /// entries are silently dropped, with no marker that anything was
    /// dropped. The result is still a JSON object, never `null`: budget
    /// exhaustion truncates, it does not refuse. For the shared
    /// projection-loss vocabulary see the canonical loss table in
    /// [`to_redacted_json`] (INF-INTEROP-06).
    ///
    /// The `Value::Null` return exists only for a refused projection, which
    /// cannot happen in non-strict mode: the helper returns `None` only when
    /// a redacted-key collision is refused, and this call does not refuse
    /// collisions. A caller must therefore not read `null` as "the module
    /// has no provenance": this function takes a `Provenance`, not a module,
    /// and "no provenance" is expressed by the caller having nothing to
    /// pass (INF-INTEROP-07).
    ///
    /// Prefer [`provenance_json_for`]: it collects the module's secrets
    /// itself (including the raw bytes, so a non-UTF-8 secret is not
    /// published as hex) and is strict -- it returns `None` instead of
    /// silently keeping the first of two colliding entries. Note its `None`
    /// conflates two reasons -- no provenance, or a refused projection --
    /// see its docs.
    pub fn provenance_json(prov: &Provenance, secrets: &[String]) -> serde_json::Value {
        // The text-only entry point compares against the secrets' text; a module
        // caller (`provenance_json_for`) also passes the raw bytes, so a
        // non-UTF-8 secret is not published as hex.
        let raw: Vec<Vec<u8>> = secrets
            .iter()
            .map(|secret| secret.as_bytes().to_vec())
            .collect();
        let mut budget = EXPORT_REDACTION_BUDGET;
        // This helper has a `Value` return, so it cannot report a redacted-key
        // collision; it keeps the first entry (the same rule as
        // `provenance_lines`). `provenance_json_for` is strict.
        match provenance_json_with(prov, secrets, &raw, &mut budget, false) {
            Some(value) => value,
            None => serde_json::Value::Null,
        }
    }

    fn provenance_json_with(
        prov: &Provenance,
        secrets: &[String],
        raw_secrets: &[Vec<u8>],
        budget: &mut usize,
        strict_collisions: bool,
    ) -> Option<serde_json::Value> {
        // A 32-byte secret can be copied into a hash field verbatim. A hash has
        // no textual form to redact, so a copy is replaced by the marker rather
        // than published as hex. The placeholder and the 32-byte set are
        // computed once: doing it per entry is O(#hashes x #secrets) and was
        // measured at 2.4 MB of churn for 2 000 hashes.
        let raw_placeholder = hiding_placeholder_text(raw_secrets);
        let hash_secrets: std::collections::HashSet<&[u8]> = raw_secrets
            .iter()
            .filter(|secret| !secret.is_empty())
            .map(|secret| secret.as_slice())
            .collect();
        let hash_value = |hash: &[u8; 32], _secrets: &[Vec<u8>]| -> serde_json::Value {
            if hash_secrets.contains(hash.as_slice()) {
                serde_json::Value::from(raw_placeholder)
            } else {
                serde_json::Value::from(crate::ir::hash_hex(hash))
            }
        };
        let placeholder = hiding_placeholder(secrets);
        // `budget` is a parameter, not a capture: the closure stays alive while
        // the entry loop also charges keys against the same budget.
        let value = |text: &str, budget: &mut usize| {
            serde_json::Value::from(
                redacted_value_capped(text, secrets, budget).unwrap_or_else(|| placeholder.into()),
            )
        };
        let mut map = serde_json::Map::new();
        if let Some(producer) = &prov.producer {
            map.insert("producer".into(), value(producer, budget));
        }
        if prov.timestamp_ms != 0 {
            map.insert(
                "timestamp_ms".into(),
                serde_json::Value::from(prov.timestamp_ms),
            );
        }
        if let Some(model) = &prov.model {
            map.insert("model".into(), value(model, budget));
        }
        if let Some(tool) = &prov.tool {
            map.insert("tool".into(), value(tool, budget));
        }
        if let Some(parent) = prov.parent {
            map.insert("parent".into(), hash_value(&parent, raw_secrets));
        }
        let mut entries = serde_json::Map::new();
        for entry in first_entry_per_key(&prov.entries) {
            // A spent budget ends the entry list: emitting a placeholder key
            // would fabricate a name the module does not have.
            let Some(key) = redacted_key_capped(&entry.key, secrets, budget) else {
                break;
            };
            if entries.contains_key(&key) {
                // Two keys redacted to one. The line codec keeps the first
                // entry, so this one must agree; a wire caller is refused.
                if strict_collisions {
                    return None;
                }
                continue;
            }
            let value = match &entry.value {
                ProvValue::Text(t) => value(t, budget),
                ProvValue::Int(number) => serde_json::Value::from(*number),
                ProvValue::Flag(flag) => serde_json::Value::from(*flag),
                ProvValue::Hash(hash) => hash_value(hash, raw_secrets),
            };
            entries.insert(key, value);
        }
        map.insert("entries".into(), serde_json::Value::Object(entries));
        Some(serde_json::Value::Object(map))
    }

    /// Project a module's provenance, collecting its secret table first.
    ///
    /// Strict: a redacted-key collision refuses the projection (`None`)
    /// instead of silently keeping the first entry, as
    /// [`provenance_json`] does. Prefer this over [`provenance_json`] for
    /// that reason, and because it also passes the raw secret bytes, so a
    /// non-UTF-8 secret is not published as hex.
    ///
    /// `None` means two different things -- the module carries no
    /// provenance, or the projection was refused (a collision) -- and the
    /// return value alone cannot tell them apart. Check
    /// `module.provenance().is_none()` first when the distinction matters:
    /// `None` there means absence, `Some` means refusal (INF-INTEROP-07).
    ///
    /// Budget exhaustion is not a refusal here either: like
    /// [`provenance_json`], the entry list is truncated and values saturate
    /// to the marker, and the result is still `Some(object)`.
    pub fn provenance_json_for(module: &InfinityModule) -> Option<serde_json::Value> {
        let secrets = secret_literals(module);
        let raw = secret_bytes(module);
        let mut budget = EXPORT_REDACTION_BUDGET;
        module
            .provenance()
            .and_then(|prov| provenance_json_with(prov, &secrets, &raw, &mut budget, true))
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
    let placeholder = hiding_placeholder(&secrets);
    let mut budget = EXPORT_REDACTION_BUDGET;
    let mut paths: HashMap<NodeId, String> = HashMap::new();
    let mut expanded = std::collections::HashSet::new();
    let mut stack: Vec<(NodeId, String, usize)> = Vec::new();
    // A binding is a root for the path walk: a secret under `cfg = {pw: ...}`
    // must report `cfg.pw`, not only `cfg`. Binding labels are path text too, so
    // they are charged against the same byte cap.
    let mut emitted = 0usize;
    // A binding label obeys the same rules as a dotted path: it is charged
    // against the export cap and never shares another node's label (pass 2,
    // #7). The fallback id label is applied in the deduplication pass below,
    // which sees every entry.
    let mut seen_bindings: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (name, id) in module.bindings() {
        let mut key = redacted_key_capped(name, &secrets, &mut budget)
            .unwrap_or_else(|| placeholder.to_string());
        if emitted.saturating_add(key.len()) > MAX_EXPORT_PATH_BYTES
            || !seen_bindings.insert(key.clone())
        {
            key = format!("@node[{}]", id.0);
        } else {
            emitted = emitted.saturating_add(key.len());
        }
        paths.insert(*id, key.clone());
        stack.push((*id, key, 0));
    }
    // An annotation subject can be a subtree that nothing else reaches. Push
    // those first and the module root last: the stack is LIFO, so the root's
    // real names are discovered before a synthetic annotation label can win.
    let mut annotations: Vec<&crate::ir::Annotation> = module.annotations().iter().collect();
    annotations.sort_by(|a, b| {
        a.node
            .cmp(&b.node)
            .then_with(|| annotation_rank(a).cmp(&annotation_rank(b)))
            .then_with(|| annotation_text(a).cmp(annotation_text(b)))
    });
    for (index, annotation) in annotations.into_iter().enumerate() {
        stack.push((annotation.node, format!("@annotation[{index}]"), 0));
        if let AnnotationKind::Constraint { expr, .. } = &annotation.kind {
            stack.push((*expr, format!("@constraint[{index}]"), 0));
        }
    }
    if let Some(root) = module.root() {
        stack.push((root, String::new(), 0));
    }
    let mut order: Vec<(NodeId, String)> = Vec::new();
    // A dotted path is materialized per node and shared with every child, so a
    // deep or wide module otherwise builds quadratic text. Past the cap a node
    // keeps a short identity label instead: still stable, still unique.
    while let Some((id, path, depth)) = stack.pop() {
        // A cyclic hand-built module must not hang the query.
        if !expanded.insert(id) {
            continue;
        }
        match module.get(id) {
            Some(Inode::Table { fields }) | Some(Inode::SchemaTable { fields, .. }) => {
                for (key, child) in fields {
                    // A path is structural: a spent budget still needs one per
                    // node, so the key saturates instead of stopping the walk.
                    let key = redacted_key_capped(key, &secrets, &mut budget)
                        .unwrap_or_else(|| placeholder.to_string());
                    let child_path = if depth >= MAX_EXPORT_PATH_DEPTH {
                        format!("@node[{}]", child.0)
                    } else if path.is_empty() {
                        key
                    } else {
                        format!("{path}.{key}")
                    };
                    let child_path = if depth < MAX_EXPORT_PATH_DEPTH
                        && emitted.saturating_add(child_path.len()) <= MAX_EXPORT_PATH_BYTES
                    {
                        emitted = emitted.saturating_add(child_path.len());
                        child_path
                    } else {
                        format!("@node[{}]", child.0)
                    };
                    stack.push((*child, child_path, depth + 1));
                }
            }
            _ => {}
        }
        order.push((id, path));
    }
    // Two nodes can reach the same text: two field names that redact to one
    // key, or a budget-saturated label. Deduplicating labels then silently
    // dropped a node from `why`/`impact` (cross-cutting pass 1, #8), so a
    // collision falls back to the id label, which is unique per node.
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (id, path) in order {
        if paths.contains_key(&id) {
            continue;
        }
        let chosen = if used.insert(path.clone()) {
            path
        } else {
            format!("@node[{}]", id.0)
        };
        paths.insert(id, chosen);
    }
    paths
}

fn annotation_rank(annotation: &crate::ir::Annotation) -> u8 {
    match &annotation.kind {
        AnnotationKind::Intent(_) => 0,
        AnnotationKind::Constraint { .. } => 1,
        AnnotationKind::AiImmutable(_) => 2,
    }
}

fn annotation_text(annotation: &crate::ir::Annotation) -> &str {
    match &annotation.kind {
        AnnotationKind::Intent(text) => text.as_str(),
        AnnotationKind::Constraint { source, .. } => source.as_str(),
        AnnotationKind::AiImmutable(_) => "",
    }
}

/// Stable label for a node: dotted path, binding, or `Kind[id]`.
///
/// Unmapped internal nodes (literals inside expressions, schema arguments) get a
/// kind-and-id label instead of a bare number so an agent's `why`/`impact`
/// output stays readable. Values are never included: a label must be safe to
/// print for a module that holds secrets.
pub fn node_label(module: &InfinityModule, id: NodeId) -> String {
    node_label_with(&value_paths(module), module, id)
}

/// [`node_label`] with a precomputed path map.
///
/// `value_paths` is O(module); building it per node made `impact`/`why`
/// quadratic.
fn node_label_with(paths: &HashMap<NodeId, String>, module: &InfinityModule, id: NodeId) -> String {
    if let Some(path) = paths.get(&id) {
        return path.clone();
    }
    match module.get(id) {
        Some(node) => format!("{}[{}]", node.kind().name(), id.0),
        None => format!("node{}", id.0),
    }
}

/// Split a dotted path into segments, reversing the escaping `merge.rs`
/// applies to field names in conflict paths (`escape_field`): `\\` is one
/// literal backslash, `\.` is a literal dot, and `\<` at the start of a
/// segment is a literal `<` (a leading `<` would otherwise read as one of
/// the merge markers `<bindings>`, `<annotations>`, `<provenance>` or
/// `<extensions>`).
///
/// A backslash before any other character, and a dangling trailing
/// backslash, stay literal: no path that contains no escape sequence
/// changes meaning, so every plain `server.port` path resolves exactly as
/// before.
fn split_escaped_path(path: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut chars = path.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => match chars.peek() {
                Some('.') => {
                    chars.next();
                    current.push('.');
                }
                Some('\\') => {
                    chars.next();
                    current.push('\\');
                }
                Some('<') if current.is_empty() => {
                    chars.next();
                    current.push('<');
                }
                _ => current.push('\\'),
            },
            '.' => {
                segments.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    segments.push(current);
    segments
}

/// Resolve a dotted path the way the evaluator does (table fields, then
/// single-segment bindings).
///
/// A path segment is unescaped the way `merge.rs` escapes field names in
/// conflict paths (`escape_field`, `src/merge.rs`): `\.` is a literal dot
/// in a field name, `\\` a literal backslash, and a leading `\<` a
/// literal `<` -- so a merge conflict path resolves in the module it names
/// (INF-INTEROP-07). A backslash before any other character, and a dangling
/// trailing backslash, stay literal.
///
/// The binding fallback is driven by the parsed segment count (one segment),
/// not by whether the raw text contains a dot, so a binding whose name
/// contains a literal dot resolves via its escaped spelling too.
///
/// Note: [`value_paths`] joins raw keys with `.` and does not escape, so its
/// labels do not round-trip through here when a field name contains a `.`.
pub fn resolve_path(module: &InfinityModule, path: &str) -> Option<NodeId> {
    let segments = split_escaped_path(path);
    if let Some(root) = module.root() {
        let mut current = root;
        let mut found = true;
        for segment in &segments {
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
    if segments.len() == 1 {
        return module
            .bindings()
            .iter()
            .find(|(name, _)| name == &segments[0])
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
    if id.index() >= module.node_count() {
        return Vec::new();
    }
    let (_, dependents) = adjacency(module);
    let paths = value_paths(module);
    let mut labels: Vec<String> = walk(&dependents, id)
        .into_iter()
        .map(|node| node_label_with(&paths, module, node))
        .collect();
    labels.sort();
    labels.dedup();
    labels
}

/// Transitive dependencies (what a node is built from), sorted by label.
pub fn why(module: &InfinityModule, id: NodeId) -> Vec<String> {
    if id.index() >= module.node_count() {
        return Vec::new();
    }
    let (deps, _) = adjacency(module);
    let paths = value_paths(module);
    let mut labels: Vec<String> = walk(&deps, id)
        .into_iter()
        .map(|node| node_label_with(&paths, module, node))
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
    // A node is tainted when it is a secret or a descendant of one. Propagate
    // from every secret across the reverse edges (`dependents`): one pass over
    // each edge, cycle-safe, and it cannot miss a node whose only route to the
    // secret is a back edge (a post-order walk marked such a node done early).
    let (_, dependents) = adjacency(module);
    let mut queue: std::collections::VecDeque<NodeId> = module
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| node.is_secret())
        .map(|(index, _)| NodeId(index as u32))
        .collect();
    for id in &queue {
        tainted[id.index()] = true;
    }
    while let Some(id) = queue.pop_front() {
        for parent in &dependents[id.index()] {
            if !tainted[parent.index()] {
                tainted[parent.index()] = true;
                queue.push_back(*parent);
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

/// Render provenance as stable `key=value` lines (values redacted when they
/// contain a secret literal).
pub fn provenance_lines(module: &InfinityModule) -> Vec<String> {
    let Some(prov) = module.provenance() else {
        return Vec::new();
    };
    let secrets = secret_texts(module);
    let raw_secrets = secret_bytes(module);
    let placeholder = hiding_placeholder(&secrets);
    let mut budget = EXPORT_REDACTION_BUDGET;
    let value = |text: &str, budget: &mut usize| {
        redacted_value_capped(text, &secrets, budget).unwrap_or_else(|| placeholder.to_string())
    };
    let mut lines = Vec::new();
    if let Some(producer) = &prov.producer {
        lines.push(format!(
            "producer={}",
            escape_line(&value(producer, &mut budget))
        ));
    }
    if prov.timestamp_ms != 0 {
        lines.push(format!("timestamp_ms={}", prov.timestamp_ms));
    }
    if let Some(model) = &prov.model {
        lines.push(format!("model={}", escape_line(&value(model, &mut budget))));
    }
    if let Some(tool) = &prov.tool {
        lines.push(format!("tool={}", escape_line(&value(tool, &mut budget))));
    }
    let raw_placeholder = hiding_placeholder_text(&raw_secrets);
    let hash_secrets: std::collections::HashSet<&[u8]> = raw_secrets
        .iter()
        .filter(|secret| !secret.is_empty())
        .map(|secret| secret.as_slice())
        .collect();
    let hash_text = |hash: &[u8; 32]| -> String {
        if hash_secrets.contains(hash.as_slice()) {
            raw_placeholder.to_string()
        } else {
            format!("blake3:{}", crate::ir::hash_hex(hash))
        }
    };
    if let Some(parent) = prov.parent {
        lines.push(format!("parent={}", hash_text(&parent)));
    }
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in first_entry_per_key(&prov.entries) {
        // Same rule as the JSON projection: a spent budget ends the list.
        let Some(key) = redacted_key_capped(&entry.key, &secrets, &mut budget) else {
            break;
        };
        // Two keys that redact to one must not produce two lines for one key;
        // the JSON projection keeps the same first entry.
        if !seen.insert(key.clone()) {
            continue;
        }
        let value = match &entry.value {
            ProvValue::Text(text) => escape_line(&value(text, &mut budget)),
            ProvValue::Int(number) => number.to_string(),
            ProvValue::Flag(flag) => flag.to_string(),
            ProvValue::Hash(hash) => hash_text(hash),
        };
        lines.push(format!("{}={value}", escape_line(&key)));
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
    let placeholder = hiding_placeholder(&secrets);
    let mut budget = EXPORT_REDACTION_BUDGET;
    module
        .annotations()
        .iter()
        .filter(|annotation| annotation.node == id)
        .filter_map(|annotation| match &annotation.kind {
            // `redacted_key` is exactly the storage rule: replace each
            // occurrence, keeping the marker when the marker is safe.
            AnnotationKind::Intent(text) => Some(
                redacted_key_capped(text, &secrets, &mut budget)
                    .unwrap_or_else(|| placeholder.to_string()),
            ),
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
    let core = active_core::parse(source, name).map_err(|diagnostics| {
        // Carry the first diagnostic (INF-INTEROP-05): the old generic
        // `Error::Encode("Active source failed to parse")` discarded the
        // parser's line/column/message, leaving a parse failure
        // undebuggable. The parser returns its hard errors in source
        // order (lexer errors first), so the first one is the fault the
        // caller must fix first; the count is not preserved -- only the
        // first diagnostic travels. The message is safe to surface: the
        // active-core 1.4.0 parser names token kinds, keys and type
        // names in its messages and never quotes a string literal's
        // content, so it cannot carry secret material. `parse` never
        // returns an empty error list (it returns `Ok` instead), so the
        // `None` arm is defensive only.
        match diagnostics.first() {
            Some(diagnostic) => {
                let (line, column) = diagnostic
                    .span
                    .as_ref()
                    .map(|span| (span.line, span.column))
                    .unwrap_or((0, 0));
                Error::Parse {
                    line,
                    column,
                    message: diagnostic.message.clone(),
                }
            }
            None => Error::Parse {
                line: 0,
                column: 0,
                message: "Active source failed to parse".to_string(),
            },
        }
    })?;
    from_active_core(&core)
}
