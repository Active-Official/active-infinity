//! A three-way, field-level merge of module roots.
//!
//! Two parties start from a shared `base` module and each produces a `left` and
//! a `right` module. The merge compares the root tables field by field and
//! reports a typed conflict whenever both sides changed the same field in
//! incompatible ways. Subtrees are compared by their canonical encoding, so a
//! field that merely moved inside a module still compares equal.
//!
//! Two things never merge automatically, because a "clean" answer would be a
//! lie or an oracle:
//!
//! - **Module metadata** (bindings, annotations, provenance, extensions) is not
//!   combined field by field. If the two sides disagree on any component, the
//!   merge reports a conflict named after that component rather than keeping
//!   one side and dropping the other's change.
//! - **Secret material** is never compared. A field whose subtree reaches a
//!   secret conflicts even when both sides are byte-identical, so the outcome
//!   says nothing about whether two secrets match (`SECURITY.md` I-2).
//!
//! A caller that wants to resolve conflicts can merge each side against the
//! base with the same API, or strip the metadata it does not need.

use std::collections::{BTreeMap, BTreeSet};

use crate::ir::{InfinityModule, Inode, NodeId};
use crate::stream::merge_fragment;
use crate::{decode, encode, Result};

/// Largest module this merge accepts, in nodes.
///
/// Each field comparison re-encodes a subtree, so the work is proportional to
/// the node count times the field count. The ceiling keeps one hostile or
/// accidental input from turning a local merge into an unbounded job; it is
/// far above any module an agent edits by hand.
pub const MAX_MERGE_NODES: usize = 262_144;

/// Why a field could not be merged automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    /// Both sides added the field with different values.
    AddAdd,
    /// Both sides changed the field to different values.
    ModifyModify,
    /// One side deleted the field while the other changed it.
    DeleteModify,
    /// The roots are not tables of the same shape, or a module-level metadata
    /// component (bindings, annotations, provenance, extensions) differs
    /// between the two sides. The merge never descends into a non-table field
    /// to classify a mismatch: a nested shape change is `ModifyModify`.
    KindMismatch,
}

/// One conflicting field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// Dotted field path (`""` for the root itself).
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
    // Bound the work before touching canonical forms: `prepare` is linear in
    // the node count and the per-field comparison multiplies it by the field
    // count.
    for module in [base, left, right] {
        if module.node_count() > MAX_MERGE_NODES {
            return Err(crate::Error::Limit {
                kind: "merge node count",
                limit: MAX_MERGE_NODES as u64,
            });
        }
    }
    // Module-level metadata is not combined field by field. Refuse rather than
    // keep the left copy and drop the right side's change.
    let metadata = metadata_conflicts(left, right)?;
    if !metadata.is_empty() {
        return Ok(Merge::Conflicts(metadata));
    }
    let Some(base_fields) = root_fields(base) else {
        return Ok(Merge::Conflicts(vec![Conflict {
            field: String::new(),
            kind: ConflictKind::KindMismatch,
        }]));
    };
    let Some(left_fields) = root_fields(left) else {
        return Ok(Merge::Conflicts(vec![Conflict {
            field: String::new(),
            kind: ConflictKind::KindMismatch,
        }]));
    };
    let Some(right_fields) = root_fields(right) else {
        return Ok(Merge::Conflicts(vec![Conflict {
            field: String::new(),
            kind: ConflictKind::KindMismatch,
        }]));
    };
    let base_map: BTreeMap<&str, NodeId> = base_fields
        .iter()
        .map(|(name, id)| (name.as_str(), *id))
        .collect();
    let left_map: BTreeMap<&str, NodeId> = left_fields
        .iter()
        .map(|(name, id)| (name.as_str(), *id))
        .collect();
    let right_map: BTreeMap<&str, NodeId> = right_fields
        .iter()
        .map(|(name, id)| (name.as_str(), *id))
        .collect();

    let names: BTreeSet<&str> = base_map
        .keys()
        .chain(left_map.keys())
        .chain(right_map.keys())
        .copied()
        .collect();

    let mut decisions: BTreeMap<String, Decision> = BTreeMap::new();
    let mut conflicts = Vec::new();
    for name in names {
        let b = base_map.get(name).copied();
        let l = left_map.get(name).copied();
        let r = right_map.get(name).copied();
        match decide(base, left, right, b, l, r)? {
            Decision::Conflict(kind) => conflicts.push(Conflict {
                field: name.to_string(),
                kind,
            }),
            decision => {
                decisions.insert(name.to_string(), decision);
            }
        }
    }
    if !conflicts.is_empty() {
        conflicts.sort_by(|a, b| a.field.cmp(&b.field));
        return Ok(Merge::Conflicts(conflicts));
    }

    let mut merged = left.clone();
    let mut additions: Vec<(String, NodeId)> = Vec::new();
    if let Some(root) = merged.root() {
        // Copy right-hand subtrees before mutating the root table, so the
        // fragment import never sees a borrowed root.
        for (name, decision) in &decisions {
            if let Decision::TakeRight(id) = decision {
                let copied = import_subtree(&mut merged, right, *id)?;
                additions.push((name.clone(), copied));
            }
        }
        let mut removed: Vec<String> = decisions
            .iter()
            .filter_map(|(name, decision)| match decision {
                Decision::Delete => Some(name.clone()),
                _ => None,
            })
            .collect();
        removed.sort();
        let table = merged
            .node_mut(root)
            .map_err(|_| crate::Error::InvalidArgument("merged root disappeared"))?;
        let Inode::Table { fields } = table else {
            return Ok(Merge::Conflicts(vec![Conflict {
                field: String::new(),
                kind: ConflictKind::KindMismatch,
            }]));
        };
        fields.retain(|(name, _)| !removed.contains(name));
        for (name, id) in additions {
            match fields.iter_mut().find(|(field, _)| *field == name) {
                Some((_, slot)) => *slot = id,
                None => fields.push((name, id)),
            }
        }
        fields.sort_by(|a, b| a.0.cmp(&b.0));
    }

    // Canonicalize: this drops any fragment nodes the selected subtree does not
    // reach and validates the result.
    let image = encode(&merged)?;
    let module = decode(&image)?;
    Ok(Merge::Clean(Box::new(module)))
}

enum Decision {
    KeepLeft,
    TakeRight(NodeId),
    Delete,
    Conflict(ConflictKind),
}

fn decide(
    base: &InfinityModule,
    left: &InfinityModule,
    right: &InfinityModule,
    b: Option<NodeId>,
    l: Option<NodeId>,
    r: Option<NodeId>,
) -> Result<Decision> {
    // Secret material is never compared. Equality is an oracle (`SECURITY.md`
    // I-2), so a field that holds a secret on either side is a conflict even
    // when the two subtrees are byte-identical: `Conflict` then says nothing
    // about whether the secrets match. Only a field that both sides deleted is
    // still a clean deletion.
    if l.is_some() || r.is_some() {
        let left_secret = l.is_some_and(|id| subtree_has_secret(left, id));
        let right_secret = r.is_some_and(|id| subtree_has_secret(right, id));
        if left_secret || right_secret {
            return Ok(Decision::Conflict(ConflictKind::ModifyModify));
        }
    }
    let left_eq_base = equal(base, left, b, l)?;
    let right_eq_base = equal(base, right, b, r)?;
    let left_eq_right = equal(left, right, l, r)?;

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
    Ok(Decision::Conflict(kind))
}

/// Compare two optional nodes across modules by their canonical subtree image.
fn equal(
    first: &InfinityModule,
    second: &InfinityModule,
    a: Option<NodeId>,
    b: Option<NodeId>,
) -> Result<bool> {
    match (a, b) {
        (None, None) => Ok(true),
        (Some(_), None) | (None, Some(_)) => Ok(false),
        (Some(a), Some(b)) => Ok(subtree_image(first, a)? == subtree_image(second, b)?),
    }
}

/// Whether a subtree reaches secret material.
///
/// Walks the node references rather than the whole module: a secret elsewhere
/// in the module does not block merging an unrelated field, but a secret inside
/// the compared subtree does.
fn subtree_has_secret(module: &InfinityModule, id: NodeId) -> bool {
    let mut seen = BTreeSet::new();
    let mut stack = vec![id];
    while let Some(current) = stack.pop() {
        if !seen.insert(current) {
            continue;
        }
        let Some(node) = module.get(current) else {
            continue;
        };
        if node.is_secret() {
            return true;
        }
        stack.extend(node.children());
    }
    false
}

/// Conflicts in the module-level metadata the field merge does not combine.
///
/// The canonical forms are compared, so node references are already renumbered
/// and two structurally equal metadata sets compare equal across modules. Any
/// difference between the two sides is a conflict: keeping the left copy would
/// silently drop the right side's change.
fn metadata_conflicts(left: &InfinityModule, right: &InfinityModule) -> Result<Vec<Conflict>> {
    let left = crate::canonical::prepare(left)?;
    let right = crate::canonical::prepare(right)?;
    let mut conflicts = Vec::new();
    let mut push = |field: &str| {
        conflicts.push(Conflict {
            field: field.to_string(),
            kind: ConflictKind::KindMismatch,
        })
    };
    if left.bindings != right.bindings {
        push("<bindings>");
    }
    if left.annotations != right.annotations {
        push("<annotations>");
    }
    if left.provenance != right.provenance {
        push("<provenance>");
    }
    if left.extensions != right.extensions {
        push("<extensions>");
    }
    Ok(conflicts)
}

fn subtree_image(module: &InfinityModule, id: NodeId) -> Result<Vec<u8>> {
    // Compare just this subtree: drop every other root (bindings, annotations,
    // provenance, extensions) so two equal subtrees in different modules encode
    // to the same bytes.
    let mut probe = module.clone();
    probe.clear_bindings();
    probe.clear_annotations();
    probe.set_provenance(None);
    probe.set_extensions(Vec::new());
    probe.set_root(Some(id));
    encode(&probe)
}

fn import_subtree(into: &mut InfinityModule, from: &InfinityModule, id: NodeId) -> Result<NodeId> {
    let mut fragment = from.clone();
    fragment.set_root(Some(id));
    merge_fragment(into, &fragment)
}

fn root_fields(module: &InfinityModule) -> Option<&[(String, NodeId)]> {
    let root = module.root()?;
    match module.get(root) {
        Some(Inode::Table { fields }) => Some(fields),
        _ => None,
    }
}
