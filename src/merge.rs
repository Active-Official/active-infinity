//! A three-way, field-level merge of module roots.
//!
//! Two parties start from a shared `base` module and each produces a `left` and
//! a `right` module. The merge compares the root tables field by field and
//! reports a typed conflict whenever both sides changed the same field in
//! incompatible ways. Subtrees are compared by their canonical encoding, so a
//! field that merely moved inside a module still compares equal.
//!
//! This is a deliberate sketch: it merges the root table recursively one level
//! at a time through the field set, keeps the left value for a conflicting
//! field, and returns no module at all when any conflict exists. A caller that
//! wants to resolve conflicts can merge each side against the base with the
//! same API.

use std::collections::{BTreeMap, BTreeSet};

use crate::ir::{InfinityModule, Inode, NodeId};
use crate::stream::merge_fragment;
use crate::{decode, encode, Result};

/// Why a field could not be merged automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    /// Both sides added the field with different values.
    AddAdd,
    /// Both sides changed the field to different values.
    ModifyModify,
    /// One side deleted the field while the other changed it.
    DeleteModify,
    /// The roots (or a compared node) are not tables of the same shape.
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
