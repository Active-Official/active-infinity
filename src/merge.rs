//! A three-way, field-level merge of module roots.
//!
//! Two parties start from a shared `base` module and each produces a `left` and
//! a `right` module. The merge compares the root tables field by field, and
//! when both sides changed the same table field it compares that table's
//! fields in turn, recursing until a field that actually disagrees is found
//! (INF-MERGE-01): two sides editing disjoint leaves of the same nested
//! table merge cleanly, and only a leaf both sides changed differently
//! conflicts. Subtrees are compared by the canonical encoding of the
//! subtree alone, so a field that merely moved inside a module still compares
//! equal.
//!
//! Two things never merge automatically, because a "clean" answer would be a
//! lie or an oracle:
//!
//! - **Annotations** are not combined field by field. If the two sides carry
//!   different annotations, the merge reports `<annotations>` rather than
//!   guessing which intent, constraint or immutability flag survives. (An
//!   annotation has no name to merge by, and two sides that each replaced the
//!   same annotation would otherwise end up with both.)
//! - **Secret material** is never compared. A field whose subtree reaches a
//!   secret conflicts even when both sides are byte-identical, so the outcome
//!   says nothing about whether two secrets match (`SECURITY.md` I-2).
//!
//! Bindings, provenance and extensions are base-aware: a component changed on
//! one side only is taken, and a component changed differently on both sides is
//! a conflict. Free text in metadata is compared **redacted** (secret literals
//! are replaced by the marker first), so a metadata comparison cannot be used
//! to guess a secret.
//!
//! Work is bounded by a node budget: every subtree comparison materialises only
//! the reachable cone of that subtree (never the whole module), imported
//! right-hand nodes are charged against [`MAX_MERGE_NODES`], and a total visit
//! budget [`MAX_MERGE_WORK`] stops a pathological conflict walk.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use crate::ir::{AnnotationKind, InfinityModule, Inode, NodeId, Provenance};
use crate::layout::EncodeOpts;
use crate::stream::merge_fragment;
use crate::{decode, encode, encode_with, Error, Result};

/// Largest module this merge accepts, in nodes, and the most right-hand nodes
/// it will import in total.
///
/// Each subtree comparison encodes a subtree, so the work is proportional to
/// the reachable node count. The ceiling keeps one hostile or accidental input
/// from turning a local merge into an unbounded job; it is far above any module
/// an agent edits by hand.
pub const MAX_MERGE_NODES: usize = 262_144;

/// Total node visits one merge may spend on substring materialisation and
/// secret walks. Three comparisons per disjoint field stay well below this;
/// a pathological nested conflict walk hits it and fails closed.
pub const MAX_MERGE_WORK: usize = 16 * MAX_MERGE_NODES;

/// References (table fields, array elements, children) a merge compares.
///
/// A node can hold far more references than [`MAX_MERGE_NODES`] counts nodes,
/// and merge builds per-input maps keyed by field name, so a two-node table
/// with millions of fields would cost memory proportional to its width while
/// the node budget saw nothing. This ceiling is checked before a map or a
/// traversal is built.
pub const MAX_MERGE_EDGES: usize = 4 * MAX_MERGE_NODES;

/// Canonical subtree bytes a merge encodes while comparing.
///
/// Equality compares re-encoded fragments, and a small node set can share one
/// large value across thousands of fields, so a node budget alone would let
/// the work amplify to gigabytes. This budget bounds the encoding itself.
pub const MAX_MERGE_BYTES: usize = 256 << 20;

/// Total bytes of conflict paths one merge may report.
pub const MAX_CONFLICT_PATH_BYTES: usize = 1 << 20;

/// Deepest nested conflict path reported.
const MAX_CONFLICT_DEPTH: usize = 64;

/// Why a field could not be merged automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    /// Both sides added the field with different values.
    AddAdd,
    /// Both sides changed the field to different values.
    ModifyModify,
    /// One side deleted the field while the other changed it.
    DeleteModify,
    /// The roots are not tables of the same shape. The merge never descends into
    /// a non-table field to classify a mismatch: a nested shape change is
    /// `ModifyModify`.
    KindMismatch,
}

/// One conflicting field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// Path from the module root (`"server.port"`); `""` names the root itself.
    ///
    /// A field name is escaped so the path is unambiguous: `\` becomes `\\`,
    /// `.` becomes `\.`, and a leading `<` becomes `\<` (the `<bindings>`,
    /// `<annotations>`, `<provenance>` and `<extensions>` markers belong to the
    /// merge, not to a field). Unescape by reversing those three rules.
    pub field: String,
    /// Why the merge refused to choose.
    pub kind: ConflictKind,
}

/// The result of a merge.
#[derive(Debug, Clone, PartialEq)]
pub enum Merge {
    /// Every field merged; the module is canonical and validated.
    Clean(Box<InfinityModule>),
    /// At least one field conflicts; no module is produced.
    Conflicts(Vec<Conflict>),
}

impl Merge {
    /// Share the merged module, when the merge was clean.
    pub fn module(&self) -> Option<&InfinityModule> {
        match self {
            Merge::Clean(module) => Some(module),
            Merge::Conflicts(_) => None,
        }
    }

    /// Take the merged module, when the merge was clean.
    pub fn into_module(self) -> Option<InfinityModule> {
        match self {
            Merge::Clean(module) => Some(*module),
            Merge::Conflicts(_) => None,
        }
    }

    /// The conflicts, when the merge had any.
    pub fn conflicts(&self) -> &[Conflict] {
        match self {
            Merge::Clean(_) => &[],
            Merge::Conflicts(conflicts) => conflicts,
        }
    }
}

/// Merge `left` and `right` against their common `base`.
pub fn merge(
    base: &InfinityModule,
    left: &InfinityModule,
    right: &InfinityModule,
) -> Result<Merge> {
    // Reject dangling references, cycles, excessive depth and oversized
    // modules before any canonical work: every later walk assumes a graph.
    let max_depth = crate::layout::Limits::default().max_depth;
    for module in [base, left, right] {
        if module.node_count() > MAX_MERGE_NODES {
            return Err(Error::Limit {
                kind: "merge node count",
                limit: MAX_MERGE_NODES as u64,
            });
        }
        module.validate_structure(MAX_MERGE_NODES as u64, max_depth)?;
    }
    // Every secret anywhere in the three inputs, so a hash that copies one is
    // never compared by value even when the copy lives in another input.
    let mut hash_secrets: Vec<Vec<u8>> = Vec::new();
    for module in [base, left, right] {
        hash_secrets.extend(crate::interop::secret_bytes(module));
    }
    // A conflict path is an export: a field name that copies a secret literal
    // would publish it in the report, exactly like an annotation or a binding
    // name. One union of the three inputs' text forms covers a copy that lives
    // in a different input (cross-cutting pass 1, #5).
    let mut secret_texts: Vec<String> = Vec::new();
    for module in [base, left, right] {
        secret_texts.extend(crate::interop::secret_texts(module));
    }
    secret_texts.sort();
    secret_texts.dedup();
    let ctx = Ctx {
        base,
        left,
        right,
        budget: Cell::new(MAX_MERGE_WORK),
        bytes: Cell::new(MAX_MERGE_BYTES),
        hash_secrets,
        secret_texts,
        redaction: Cell::new(MAX_MERGE_WORK),
    };

    let mut conflicts = ConflictSet::default();
    let plan = ctx.metadata_plan(&mut conflicts)?;

    let Some(base_fields) = root_fields(base) else {
        conflicts.push(String::new(), ConflictKind::KindMismatch)?;
        return Ok(Merge::Conflicts(conflicts.into_vec()));
    };
    let Some(left_fields) = root_fields(left) else {
        conflicts.push(String::new(), ConflictKind::KindMismatch)?;
        return Ok(Merge::Conflicts(conflicts.into_vec()));
    };
    let Some(right_fields) = root_fields(right) else {
        conflicts.push(String::new(), ConflictKind::KindMismatch)?;
        return Ok(Merge::Conflicts(conflicts.into_vec()));
    };
    let base_map = field_map(base_fields)?;
    let left_map = field_map(left_fields)?;
    let right_map = field_map(right_fields)?;

    let names: BTreeSet<&str> = base_map
        .keys()
        .chain(left_map.keys())
        .chain(right_map.keys())
        .copied()
        .collect();

    let mut decisions: BTreeMap<String, Decision> = BTreeMap::new();
    for name in names {
        let b = base_map.get(name).copied();
        let l = left_map.get(name).copied();
        let r = right_map.get(name).copied();
        match ctx.decide(b, l, r, 0)? {
            Decision::Conflict(kind) => {
                // Describe the conflict as precisely as the shapes allow: both
                // sides being tables means the disagreement is inside them, and
                // a dotted path names the field that actually differs.
                let before = conflicts.len();
                ctx.nested_conflicts(name, b, l, r, 0, &mut conflicts)?;
                if conflicts.len() == before {
                    conflicts.push(ctx.field_label(name)?, kind)?;
                }
            }
            decision => {
                decisions.insert(name.to_string(), decision);
            }
        }
    }
    if !conflicts.is_empty() {
        conflicts.sort();
        return Ok(Merge::Conflicts(conflicts.into_vec()));
    }

    let mut merged = left.clone();
    let mut imported = 0usize;
    let mut additions: Vec<(String, NodeId)> = Vec::new();
    if let Some(root) = merged.root() {
        // Copy right-hand subtrees before mutating the root table, so the
        // fragment import never sees a borrowed root.
        for (name, decision) in &decisions {
            if let Decision::TakeRight(id) = decision {
                let (copied, nodes) = import_subtree(&mut merged, right, *id)?;
                imported = imported.saturating_add(nodes);
                if imported > MAX_MERGE_NODES {
                    return Err(Error::Limit {
                        kind: "merge imported nodes",
                        limit: MAX_MERGE_NODES as u64,
                    });
                }
                additions.push((name.clone(), copied));
            }
        }
        let removed: BTreeSet<&str> = decisions
            .iter()
            .filter_map(|(name, decision)| match decision {
                Decision::Delete => Some(name.as_str()),
                _ => None,
            })
            .collect();
        let table = merged
            .node_mut(root)
            .map_err(|_| Error::Encode("merged root disappeared"))?;
        let Inode::Table { fields } = table else {
            conflicts.push(String::new(), ConflictKind::KindMismatch)?;
            return Ok(Merge::Conflicts(conflicts.into_vec()));
        };
        fields.retain(|(name, _)| !removed.contains(name.as_str()));
        // Index the surviving fields once: a linear scan per addition is
        // quadratic in the table width (`additions x fields`).
        let mut pending: std::collections::HashMap<&str, NodeId> = additions
            .iter()
            .map(|(name, id)| (name.as_str(), *id))
            .collect();
        for (name, slot) in fields.iter_mut() {
            if let Some(id) = pending.remove(name.as_str()) {
                *slot = id;
            }
        }
        for (name, id) in &additions {
            if pending.contains_key(name.as_str()) {
                fields.push((name.clone(), *id));
            }
        }
        fields.sort_by(|a, b| a.0.cmp(&b.0));
    }

    // Apply the nested merges (INF-MERGE-01): each `MergeNested` decision
    // mutates the merged copy of the left table in place. The root-table
    // application above never touches these fields, and node ids are
    // stable across imports, so the child table is found by name here.
    for (name, decision) in &decisions {
        let Decision::MergeNested(children) = decision else {
            continue;
        };
        let Some(root) = merged.root() else {
            return Err(Error::Encode("merged root disappeared"));
        };
        let table = match merged.get(root) {
            Some(Inode::Table { fields }) => fields
                .iter()
                .find(|(field, _)| field == name)
                .map(|(_, id)| *id),
            _ => None,
        };
        let Some(table) = table else {
            return Err(Error::Encode("merged nested table disappeared"));
        };
        apply_nested(&mut merged, right, table, children, &mut imported)?;
    }

    apply_metadata(&mut merged, right, plan, &mut imported)?;

    // Canonicalize: this drops any fragment nodes the selected subtree does not
    // reach and validates the result. The drop is explicit here (INF-04): a
    // merge keeps only the selected subtree, so the unselected fragment nodes
    // are orphaned by design, and the default fail-closed encode would
    // refuse them.
    let image = encode_with(
        &merged,
        EncodeOpts {
            drop_unreachable: true,
            ..EncodeOpts::default()
        },
    )?;
    let module = decode(&image)?;
    // A clean merge imports at most one right-hand cone on top of the left
    // module, so the result can be twice an input. Keep the returned module
    // under the same ceiling a caller needed to hand in.
    if module.node_count() > MAX_MERGE_NODES {
        return Err(Error::Limit {
            kind: "merge output nodes",
            limit: MAX_MERGE_NODES as u64,
        });
    }
    Ok(Merge::Clean(Box::new(module)))
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

enum Decision {
    KeepLeft,
    TakeRight(NodeId),
    Delete,
    Conflict(ConflictKind),
    /// Both sides changed different nested fields of the same table; the
    /// children carry the per-field decisions, recursively. A child that
    /// itself conflicts makes the whole table a conflict instead (see
    /// `Ctx::decide`), so a `MergeNested` tree never contains a `Conflict`.
    MergeNested(Vec<(String, Decision)>),
}

/// One module-level component the field merge does not own.
enum BindingAction {
    TakeRight(NodeId),
    Delete,
}

#[derive(Default)]
struct MetaPlan {
    bindings: Vec<(String, BindingAction)>,
    /// `Some(new value)` applies the right-hand provenance.
    provenance: Option<Option<Provenance>>,
    /// `Some(new set)` applies the right-hand extensions.
    extensions: Option<Vec<(u64, Vec<u8>)>>,
}

struct Ctx<'a> {
    base: &'a InfinityModule,
    left: &'a InfinityModule,
    right: &'a InfinityModule,
    budget: Cell<usize>,
    bytes: Cell<usize>,
    hash_secrets: Vec<Vec<u8>>,
    /// Text of every secret in the three inputs, for conflict labels.
    secret_texts: Vec<String>,
    /// Cumulative budget for redacting labels.
    redaction: Cell<usize>,
}

impl Ctx<'_> {
    /// A field name as a conflict path: redacted against every secret, escaped
    /// for the dotted path syntax.
    fn field_label(&self, name: &str) -> Result<String> {
        let mut budget = self.redaction.get();
        let redacted = crate::interop::redact_within(name, &self.secret_texts, &mut budget)?;
        self.redaction.set(budget);
        Ok(escape_field(&redacted))
    }

    fn charge(&self, nodes: usize) -> Result<()> {
        let remaining = self.budget.get();
        if remaining < nodes {
            return Err(Error::Limit {
                kind: "merge work",
                limit: MAX_MERGE_WORK as u64,
            });
        }
        self.budget.set(remaining - nodes);
        Ok(())
    }

    fn charge_bytes(&self, bytes: usize) -> Result<()> {
        let remaining = self.bytes.get();
        if remaining < bytes {
            return Err(Error::Limit {
                kind: "merge bytes",
                limit: MAX_MERGE_BYTES as u64,
            });
        }
        self.bytes.set(remaining - bytes);
        Ok(())
    }

    fn decide(
        &self,
        b: Option<NodeId>,
        l: Option<NodeId>,
        r: Option<NodeId>,
        depth: usize,
    ) -> Result<Decision> {
        // Secret material is never compared. Equality is an oracle
        // (`SECURITY.md` I-2), so a field that holds a secret on either side is
        // a conflict even when the two subtrees are byte-identical: the
        // `Conflict` then says nothing about whether the secrets match. Only a
        // field that both sides deleted is still a clean deletion.
        if l.is_some() || r.is_some() {
            let left_secret = match l {
                Some(id) => self.has_secret(self.left, id)?,
                None => false,
            };
            let right_secret = match r {
                Some(id) => self.has_secret(self.right, id)?,
                None => false,
            };
            if left_secret || right_secret {
                return Ok(Decision::Conflict(ConflictKind::ModifyModify));
            }
        }
        let left_eq_base = self.equal(self.base, b, self.left, l)?;
        let right_eq_base = self.equal(self.base, b, self.right, r)?;
        let left_eq_right = self.equal(self.left, l, self.right, r)?;

        if left_eq_base && right_eq_base {
            return Ok(Decision::KeepLeft);
        }
        if left_eq_right {
            // Both sides agree; prefer the right node so a value added on both
            // sides is carried once.
            return Ok(match r {
                Some(_) => Decision::TakeRight(r.expect("checked")),
                None => Decision::Delete,
            });
        }
        if left_eq_base {
            return Ok(match r {
                Some(id) => Decision::TakeRight(id),
                None => Decision::Delete,
            });
        }
        if right_eq_base {
            return Ok(Decision::KeepLeft);
        }
        // Both sides changed the field and disagree.
        let kind = if b.is_none() {
            ConflictKind::AddAdd
        } else if l.is_none() || r.is_none() {
            ConflictKind::DeleteModify
        } else {
            ConflictKind::ModifyModify
        };
        // Both sides changed a table field: try to settle it field by
        // field (INF-MERGE-01). The whole-field conflict above stands when
        // the shapes differ, when a nested field itself conflicts, or when
        // the recursion bound is reached.
        if depth < MAX_CONFLICT_DEPTH {
            if let Some(children) = self.try_nested_merge(b, l, r, depth)? {
                return Ok(Decision::MergeNested(children));
            }
        }
        Ok(Decision::Conflict(kind))
    }

    /// Try to settle a both-changed table field per nested field
    /// (INF-MERGE-01).
    ///
    /// Returns `Some(children)` when every nested field decides without a
    /// conflict — the children are the per-field decisions, themselves
    /// recursive — and `None` when the field must stay a whole-field
    /// conflict: a side is not a table, the base is not a table, or any
    /// nested field itself conflicts. The caller keeps the whole-field
    /// conflict kind it already computed; this function never reports a
    /// conflict of its own.
    fn try_nested_merge(
        &self,
        b: Option<NodeId>,
        l: Option<NodeId>,
        r: Option<NodeId>,
        depth: usize,
    ) -> Result<Option<Vec<(String, Decision)>>> {
        let (Some(left_id), Some(right_id)) = (l, r) else {
            // One side deleted the field: nothing to merge field by field.
            return Ok(None);
        };
        // The base must be a table too, when it exists: a base that is not
        // a table means the shape changed, and the parent's conflict
        // stands (`a_non_table_base_is_not_descended_into`).
        let base_fields = match b {
            Some(id) => match table_fields(self.base, id)? {
                Some(fields) => Some(fields),
                None => return Ok(None),
            },
            None => None,
        };
        let (Some(left_fields), Some(right_fields)) = (
            table_fields(self.left, left_id)?,
            table_fields(self.right, right_id)?,
        ) else {
            // Either side is not a table: the shapes differ.
            return Ok(None);
        };
        let names: BTreeSet<&str> = left_fields
            .keys()
            .chain(right_fields.keys())
            .copied()
            .collect();
        let mut children: Vec<(String, Decision)> = Vec::with_capacity(names.len());
        for name in names {
            let child_base = base_fields
                .as_ref()
                .and_then(|fields| fields.get(name))
                .copied();
            let child_left = left_fields.get(name).copied();
            let child_right = right_fields.get(name).copied();
            match self.decide(child_base, child_left, child_right, depth + 1)? {
                Decision::Conflict(_) => return Ok(None),
                decision => children.push((name.to_string(), decision)),
            }
        }
        Ok(Some(children))
    }

    /// Compare two optional nodes across modules by their canonical subtree.
    ///
    /// A secret anywhere in either subtree makes the answer `false` without
    /// comparing bytes: the caller turns that into a conflict.
    fn equal(
        &self,
        first: &InfinityModule,
        a: Option<NodeId>,
        second: &InfinityModule,
        b: Option<NodeId>,
    ) -> Result<bool> {
        match (a, b) {
            (None, None) => Ok(true),
            (Some(_), None) | (None, Some(_)) => Ok(false),
            (Some(a), Some(b)) => {
                if self.has_secret(first, a)? || self.has_secret(second, b)? {
                    return Ok(false);
                }
                Ok(self.image(first, a)? == self.image(second, b)?)
            }
        }
    }

    /// Canonical bytes of one subtree: only the reachable cone, with every
    /// other root cleared, so equal subtrees in different modules agree.
    fn image(&self, module: &InfinityModule, id: NodeId) -> Result<Vec<u8>> {
        let fragment = subtree_fragment(module, id)?;
        self.charge(fragment.node_count())?;
        let encoded = encode(&fragment)?;
        self.charge_bytes(encoded.len())?;
        Ok(encoded)
    }

    /// Whether a subtree reaches secret material, charging every node visited.
    fn has_secret(&self, module: &InfinityModule, id: NodeId) -> Result<bool> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![id];
        let mut found = false;
        while let Some(current) = stack.pop() {
            if !seen.insert(current) {
                continue;
            }
            let Some(node) = module.get(current) else {
                return Err(Error::NodeRef(current.0));
            };
            if node.is_secret() {
                found = true;
            }
            let children = node.children();
            // Charge the references before pushing them: a wide node would
            // otherwise commit its whole child list to the stack first.
            self.charge(children.len())?;
            stack.extend(children);
        }
        self.charge(seen.len())?;
        Ok(found)
    }

    /// Describe a conflict inside two tables with dotted paths.
    ///
    /// The caller has already established that the two top-level values
    /// disagree. When both are tables *and the base agrees they are tables*,
    /// the disagreement is inside them: recurse per field so the report names
    /// `server.port` rather than `server`. A base that is not a table means the
    /// shape changed, and the parent's `ModifyModify` stands. A subtree that
    /// reaches a secret is never walked, and the depth is capped so a
    /// pathological shape cannot recurse without bound.
    fn nested_conflicts(
        &self,
        path: &str,
        b: Option<NodeId>,
        l: Option<NodeId>,
        r: Option<NodeId>,
        depth: usize,
        out: &mut ConflictSet,
    ) -> Result<()> {
        if depth >= MAX_CONFLICT_DEPTH {
            return Ok(());
        }
        let (Some(left_id), Some(right_id)) = (l, r) else {
            return Ok(());
        };
        if self.has_secret(self.left, left_id)? || self.has_secret(self.right, right_id)? {
            return Ok(());
        }
        let base_fields = match b {
            Some(id) => match table_fields(self.base, id)? {
                Some(fields) => Some(fields),
                // The base is not a table while both sides are: the shape
                // changed, so this is the parent's conflict, not a child's.
                None => return Ok(()),
            },
            None => None,
        };
        let (Some(left_fields), Some(right_fields)) = (
            table_fields(self.left, left_id)?,
            table_fields(self.right, right_id)?,
        ) else {
            return Ok(());
        };
        let names: BTreeSet<&str> = left_fields
            .keys()
            .chain(right_fields.keys())
            .copied()
            .collect();
        for name in names {
            let child_base = base_fields
                .as_ref()
                .and_then(|fields| fields.get(name))
                .copied();
            let child_left = left_fields.get(name).copied();
            let child_right = right_fields.get(name).copied();
            if let Decision::Conflict(kind) =
                self.decide(child_base, child_left, child_right, depth + 1)?
            {
                let child_path = format!("{path}.{}", self.field_label(name)?);
                let before = out.len();
                self.nested_conflicts(
                    &child_path,
                    child_base,
                    child_left,
                    child_right,
                    depth + 1,
                    out,
                )?;
                if out.len() == before {
                    out.push(child_path, kind)?;
                }
            }
        }
        Ok(())
    }

    /// Compare the module-level components and plan how to apply the one-sided
    /// changes.
    fn metadata_plan(&self, conflicts: &mut ConflictSet) -> Result<MetaPlan> {
        let mut plan = MetaPlan::default();
        let base_map = binding_map(self.base)?;
        let left_map = binding_map(self.left)?;
        let right_map = binding_map(self.right)?;
        let names: BTreeSet<&str> = base_map
            .keys()
            .chain(left_map.keys())
            .chain(right_map.keys())
            .copied()
            .collect();
        for name in names {
            let b = base_map.get(name).copied();
            let l = left_map.get(name).copied();
            let r = right_map.get(name).copied();
            if self.equal(self.left, l, self.right, r)? {
                continue;
            }
            if self.equal(self.base, b, self.right, r)? {
                // Right is unchanged; keep the left binding (or its absence).
                continue;
            }
            if self.equal(self.base, b, self.left, l)? {
                match r {
                    Some(id) => plan
                        .bindings
                        .push((name.to_string(), BindingAction::TakeRight(id))),
                    None => plan
                        .bindings
                        .push((name.to_string(), BindingAction::Delete)),
                }
                continue;
            }
            conflicts.push("<bindings>".to_string(), ConflictKind::KindMismatch)?;
        }

        // Provenance: one block, compared through a redacted rendering. One
        // cumulative budget per block: an infallible replacement per field let
        // 10k entries x 1k secrets run for minutes (pass 2, #6).
        let mut provenance_budget = self.redaction.get();
        let left_key = provenance_key(self.left, &self.hash_secrets, &mut provenance_budget)?;
        let right_key = provenance_key(self.right, &self.hash_secrets, &mut provenance_budget)?;
        if left_key != right_key {
            let base_key = provenance_key(self.base, &self.hash_secrets, &mut provenance_budget)?;
            if base_key == left_key {
                plan.provenance = Some(self.right.provenance().cloned());
            } else if base_key != right_key {
                conflicts.push("<provenance>".to_string(), ConflictKind::KindMismatch)?;
            }
        }

        // Extensions: one set, sorted by tag, compared through redacted
        // payloads. A payload that is not text cannot be redacted, so a set
        // holding one next to a secret is never compared: it conflicts.
        let mut extensions_budget = self.redaction.get();
        let left_key = extensions_key(self.left, &mut extensions_budget);
        let right_key = extensions_key(self.right, &mut extensions_budget);
        if left_key.is_none() || right_key.is_none() {
            conflicts.push("<extensions>".to_string(), ConflictKind::KindMismatch)?;
        } else if left_key != right_key {
            let base_key = extensions_key(self.base, &mut extensions_budget);
            if left_key == base_key {
                plan.extensions = Some(self.right.extensions().to_vec());
            } else if right_key != base_key {
                conflicts.push("<extensions>".to_string(), ConflictKind::KindMismatch)?;
            }
        }

        // Annotations: no name to merge by, so any difference is a conflict.
        // The comparison is order-insensitive and redacted.
        if self.annotation_keys(self.left)? != self.annotation_keys(self.right)? {
            conflicts.push("<annotations>".to_string(), ConflictKind::KindMismatch)?;
        }
        Ok(plan)
    }

    fn annotation_keys(&self, module: &InfinityModule) -> Result<Vec<String>> {
        let secrets = crate::interop::secret_texts(module);
        let mut budget = self.redaction.get();
        let mut keys = Vec::with_capacity(module.annotations().len());
        for annotation in module.annotations() {
            let subject = if self.has_secret(module, annotation.node)? {
                "SECRET".to_string()
            } else {
                hex(&self.image(module, annotation.node)?)
            };
            let (code, text, expr) = match &annotation.kind {
                AnnotationKind::Intent(text) => (0u8, text.clone(), String::new()),
                AnnotationKind::Constraint { source, expr } => (
                    1,
                    source.clone(),
                    if self.has_secret(module, *expr)? {
                        "SECRET".to_string()
                    } else {
                        hex(&self.image(module, *expr)?)
                    },
                ),
                AnnotationKind::AiImmutable(flag) => (2, flag.to_string(), String::new()),
            };
            let text = crate::interop::redact_within(&text, &secrets, &mut budget)?;
            keys.push(format!("{code}|{subject}|{expr}|{text}"));
        }
        self.redaction.set(budget);
        keys.sort();
        Ok(keys)
    }
}

// ---------------------------------------------------------------------------
// Applying a clean merge
// ---------------------------------------------------------------------------

fn apply_metadata(
    merged: &mut InfinityModule,
    right: &InfinityModule,
    plan: MetaPlan,
    imported: &mut usize,
) -> Result<()> {
    if !plan.bindings.is_empty() {
        let mut bindings: BTreeMap<String, NodeId> = merged.bindings().iter().cloned().collect();
        for (name, action) in plan.bindings {
            match action {
                BindingAction::Delete => {
                    bindings.remove(&name);
                }
                BindingAction::TakeRight(id) => {
                    let (copied, nodes) = import_subtree(merged, right, id)?;
                    *imported = imported.saturating_add(nodes);
                    if *imported > MAX_MERGE_NODES {
                        return Err(Error::Limit {
                            kind: "merge imported nodes",
                            limit: MAX_MERGE_NODES as u64,
                        });
                    }
                    bindings.insert(name, copied);
                }
            }
        }
        merged.clear_bindings();
        for (name, id) in bindings {
            merged.bind(name, id);
        }
    }
    if let Some(provenance) = plan.provenance {
        merged.set_provenance(provenance);
    }
    if let Some(extensions) = plan.extensions {
        merged.set_extensions(extensions);
    }
    Ok(())
}

/// Apply the per-field decisions of one nested table merge (INF-MERGE-01)
/// to the merged copy of the left table.
///
/// `table` is the node in `into` holding the left table. Its field list is
/// rewritten once, mirroring the root-table application in `merge`:
/// `TakeRight` slots are imported from `from` and replaced (or added, when
/// the right side added the nested field), `Delete` slots are removed, and
/// `MergeNested` children recurse into their own table. The child ids are
/// read before any import — imports append nodes, so those ids stay valid
/// — and the recursion depth is bounded by construction: the decision tree
/// was built under `MAX_CONFLICT_DEPTH`.
fn apply_nested(
    into: &mut InfinityModule,
    from: &InfinityModule,
    table: NodeId,
    decisions: &[(String, Decision)],
    imported: &mut usize,
) -> Result<()> {
    // Snapshot the table's current field slots before any import: the
    // borrow must end before `import_subtree` takes `into` mutably.
    let slots: Vec<(String, NodeId)> = match into.get(table) {
        Some(Inode::Table { fields }) => fields.clone(),
        _ => return Err(Error::Encode("merged nested table disappeared")),
    };
    // Copy right-hand subtrees before mutating the table, so the fragment
    // import never sees a borrowed table (same order as the root apply).
    let mut additions: Vec<(String, NodeId)> = Vec::new();
    let mut nested: Vec<(NodeId, &[(String, Decision)])> = Vec::new();
    let mut removed: BTreeSet<&str> = BTreeSet::new();
    for (name, decision) in decisions {
        match decision {
            Decision::KeepLeft => {}
            Decision::TakeRight(id) => {
                let (copied, nodes) = import_subtree(into, from, *id)?;
                *imported = imported.saturating_add(nodes);
                if *imported > MAX_MERGE_NODES {
                    return Err(Error::Limit {
                        kind: "merge imported nodes",
                        limit: MAX_MERGE_NODES as u64,
                    });
                }
                additions.push((name.clone(), copied));
            }
            Decision::Delete => {
                removed.insert(name.as_str());
            }
            Decision::MergeNested(children) => {
                let child = slots
                    .iter()
                    .find(|(field, _)| field == name)
                    .map(|(_, id)| *id)
                    .ok_or(Error::Encode("merged nested table disappeared"))?;
                nested.push((child, children.as_slice()));
            }
            Decision::Conflict(_) => {
                // A `MergeNested` tree never contains a conflict: the
                // parent `decide` fell back to the whole-field conflict
                // instead. Fail closed if one ever appears.
                return Err(Error::Encode("nested merge holds a conflict"));
            }
        }
    }
    // Rewrite this table's field list once: drop the deletes, replace the
    // imported slots, append the added ones, and keep the canonical field
    // order — the same shape as the root-table application.
    let table_node = into
        .node_mut(table)
        .map_err(|_| Error::Encode("merged nested table disappeared"))?;
    let Inode::Table { fields } = table_node else {
        return Err(Error::Encode("merged nested table disappeared"));
    };
    fields.retain(|(name, _)| !removed.contains(name.as_str()));
    let mut pending: std::collections::HashMap<&str, NodeId> = additions
        .iter()
        .map(|(name, id)| (name.as_str(), *id))
        .collect();
    for (name, slot) in fields.iter_mut() {
        if let Some(id) = pending.remove(name.as_str()) {
            *slot = id;
        }
    }
    for (name, id) in &additions {
        if pending.contains_key(name.as_str()) {
            fields.push((name.clone(), *id));
        }
    }
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    // Recurse into the nested tables: their node ids were read before this
    // rewrite and are unaffected by it.
    for (child, children) in nested {
        apply_nested(into, from, child, children, imported)?;
    }
    Ok(())
}

/// Copy the reachable cone of `id` into `into`, returning the new root and the
/// number of nodes appended.
fn import_subtree(
    into: &mut InfinityModule,
    from: &InfinityModule,
    id: NodeId,
) -> Result<(NodeId, usize)> {
    let fragment = subtree_fragment(from, id)?;
    let nodes = fragment.node_count();
    let root = merge_fragment(into, &fragment)?;
    Ok((root, nodes))
}

/// A module holding only the reachable cone of `id`.
///
/// Nodes are appended in post-order, so every child is mapped before its
/// parent is remapped. A shared child is materialised once, and a cycle (which
/// [`InfinityModule::validate_structure`] has already refused) fails closed on
/// the dangling remap instead of looping.
fn subtree_fragment(module: &InfinityModule, id: NodeId) -> Result<InfinityModule> {
    let mut mapped: Vec<NodeId> = vec![NodeId::NONE; module.node_count()];
    let mut order: Vec<NodeId> = Vec::new();
    let mut seen: BTreeSet<NodeId> = BTreeSet::new();
    let mut stack = vec![(id, false)];
    let mut edges = 0usize;
    while let Some((node, expanded)) = stack.pop() {
        if expanded {
            order.push(node);
            continue;
        }
        if !seen.insert(node) {
            continue;
        }
        if module.get(node).is_none() {
            return Err(Error::NodeRef(node.0));
        }
        stack.push((node, true));
        let children = module.get(node).map(Inode::children).unwrap_or_default();
        edges = edges
            .checked_add(children.len())
            .filter(|total| *total <= MAX_MERGE_EDGES)
            .ok_or(Error::Limit {
                kind: "merge subtree edges",
                limit: MAX_MERGE_EDGES as u64,
            })?;
        for child in children {
            stack.push((child, false));
        }
    }
    let mut fragment = InfinityModule::new();
    for old in order {
        let node = module.get(old).ok_or(Error::NodeRef(old.0))?;
        let remapped = crate::canonical::remap_node(node, &mapped)?;
        mapped[old.index()] = fragment.push(remapped);
    }
    fragment.set_root(Some(mapped[id.index()]));
    Ok(fragment)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ConflictSet {
    list: Vec<Conflict>,
    bytes: usize,
}

impl ConflictSet {
    fn len(&self) -> usize {
        self.list.len()
    }

    fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    fn push(&mut self, field: String, kind: ConflictKind) -> Result<()> {
        self.bytes = self.bytes.saturating_add(field.len());
        if self.bytes > MAX_CONFLICT_PATH_BYTES {
            return Err(Error::Limit {
                kind: "merge conflict paths",
                limit: MAX_CONFLICT_PATH_BYTES as u64,
            });
        }
        self.list.push(Conflict { field, kind });
        Ok(())
    }

    fn sort(&mut self) {
        self.list.sort_by(|a, b| a.field.cmp(&b.field));
    }

    fn into_vec(self) -> Vec<Conflict> {
        self.list
    }
}

/// Escape a field name so a dotted path is unambiguous.
fn escape_field(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for (index, character) in name.chars().enumerate() {
        match character {
            '\\' => out.push_str("\\\\"),
            '.' => out.push_str("\\."),
            '<' if index == 0 => out.push_str("\\<"),
            _ => out.push(character),
        }
    }
    out
}

fn field_map(fields: &[(String, NodeId)]) -> Result<BTreeMap<&str, NodeId>> {
    if fields.len() > MAX_MERGE_EDGES {
        return Err(Error::Limit {
            kind: "merge table width",
            limit: MAX_MERGE_EDGES as u64,
        });
    }
    Ok(fields
        .iter()
        .map(|(name, id)| (name.as_str(), *id))
        .collect())
}

fn binding_map(module: &InfinityModule) -> Result<BTreeMap<&str, NodeId>> {
    let bindings = module.bindings();
    if bindings.len() > MAX_MERGE_EDGES {
        return Err(Error::Limit {
            kind: "merge bindings",
            limit: MAX_MERGE_EDGES as u64,
        });
    }
    Ok(bindings
        .iter()
        .map(|(name, id)| (name.as_str(), *id))
        .collect())
}

/// The fields of a table node, keyed by name.
fn table_fields(module: &InfinityModule, id: NodeId) -> Result<Option<BTreeMap<&str, NodeId>>> {
    match module.get(id) {
        Some(Inode::Table { fields }) => field_map(fields).map(Some),
        _ => Ok(None),
    }
}

fn root_fields(module: &InfinityModule) -> Option<&[(String, NodeId)]> {
    let root = module.root()?;
    match module.get(root) {
        Some(Inode::Table { fields }) => Some(fields),
        _ => None,
    }
}

/// A deterministic rendering of provenance with every free text redacted.
fn provenance_key(
    module: &InfinityModule,
    hash_secrets: &[Vec<u8>],
    budget: &mut usize,
) -> Result<Option<String>> {
    let Some(provenance) = module.provenance() else {
        return Ok(None);
    };
    let secrets = crate::interop::secret_texts(module);
    // A budget shortfall propagates: substituting the marker made two distinct
    // provenance blocks compare equal, so the merge silently dropped one side
    // (audit AINF-002).
    let mut redact = |text: &str| crate::interop::redact_within(text, &secrets, budget);
    // A 32-byte secret can be copied into a hash field. A hash has no text to
    // redact, so a copy becomes the marker, exactly as the projections do.
    let hash_text = |hash: &[u8; 32]| -> String {
        if hash_secrets
            .iter()
            .any(|secret| !secret.is_empty() && secret.as_slice() == hash)
        {
            crate::canonical::SECRET_MARKER.to_string()
        } else {
            hex(hash)
        }
    };
    let mut out = String::new();
    for text in [
        provenance.producer.as_deref(),
        provenance.model.as_deref(),
        provenance.tool.as_deref(),
    ] {
        match text {
            Some(text) => {
                let text = redact(text)?;
                out.push_str(&format!("S{}:{};", text.len(), text));
            }
            None => out.push_str("N;"),
        }
    }
    out.push_str(&format!("t{};", provenance.timestamp_ms));
    match provenance.parent {
        Some(hash) => out.push_str(&format!("p{};", hash_text(&hash))),
        None => out.push_str("p-;"),
    }
    let mut entries: Vec<(String, String)> = provenance
        .entries
        .iter()
        .map(|entry| {
            let key = redact(&entry.key)?;
            let value = match &entry.value {
                crate::ir::ProvValue::Text(text) => format!("T{}", redact(text)?),
                crate::ir::ProvValue::Int(value) => format!("I{value}"),
                crate::ir::ProvValue::Flag(flag) => format!("F{flag}"),
                crate::ir::ProvValue::Hash(hash) => format!("H{}", hash_text(hash)),
            };
            Ok((key, value))
        })
        .collect::<Result<Vec<_>>>()?;
    entries.sort();
    for (key, value) in entries {
        out.push_str(&format!("K{}:{}={};", key.len(), key, value));
    }
    Ok(Some(out))
}

/// A deterministic rendering of the extension set with payloads redacted when
/// they are text.
///
/// `None` means the set cannot be compared safely: a secret is present and a
/// payload is not UTF-8, so redaction would not be faithful.
fn extensions_key(module: &InfinityModule, budget: &mut usize) -> Option<String> {
    let secrets = crate::interop::secret_texts(module);
    let mut extensions = module.extensions().to_vec();
    extensions.sort_by_key(|(tag, _)| *tag);
    let mut out = String::new();
    for (tag, payload) in extensions {
        out.push_str(&format!("{tag}:{}:", payload.len()));
        if secrets.is_empty() {
            out.push_str(&hex(&payload));
        } else {
            let text = std::str::from_utf8(&payload).ok()?;
            let text = crate::interop::redact_within(text, &secrets, budget).ok()?;
            out.push_str(&format!("{}:{}", text.len(), text));
        }
        out.push(';');
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InfinityModule, Inode, Provenance, SecretBytes};

    /// 32 bytes, so it can be copied into a provenance hash verbatim.
    const CANARY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

    /// A hash that copies a secret is replaced by the marker in the comparison
    /// key, exactly as every projection renders it. Without this, the key is a
    /// value comparison against secret bytes.
    #[test]
    fn a_provenance_hash_that_copies_a_secret_is_marked() {
        let mut module = InfinityModule::new();
        let value = module.push(Inode::Secret(SecretBytes::from(
            std::str::from_utf8(CANARY).expect("ascii"),
        )));
        module.set_root(Some(value));
        module.set_provenance(Some(Provenance {
            parent: Some(*CANARY),
            ..Provenance::default()
        }));

        let mut budget = MAX_MERGE_WORK;
        let key = provenance_key(&module, &[CANARY.to_vec()], &mut budget)
            .expect("key")
            .expect("provenance");
        assert!(key.contains(crate::canonical::SECRET_MARKER), "{key}");
        assert!(!key.contains(&hex(CANARY)), "{key}");

        // Without a matching secret the hash is ordinary data.
        let key = provenance_key(&module, &[], &mut budget)
            .expect("key")
            .expect("provenance");
        assert!(key.contains(&hex(CANARY)), "{key}");
    }
}
