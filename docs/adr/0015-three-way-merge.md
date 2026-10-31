# ADR-0015 — Three-way field-level module merge

**Status:** accepted (2026-10-31). Additive; no wire change.

## Context

Two agents that share a base module often edit different parts in parallel.
Concatenating their deltas is unsafe: the same field may have been changed on
both sides, or deleted on one and edited on the other. The merge must produce a
canonical module when the changes are compatible and report *typed* conflicts
when they are not.

## Decision

`merge::merge(base, left, right)` compares the root tables field by field:

- A field is compared by the canonical encoding of its subtree (bindings,
  annotations, provenance and extensions are cleared first), so a field that
  moved inside a module still compares equal.
- One side changed → take that side.
- Both sides changed identically → take it once.
- Both sides changed differently → conflict:
  - `AddAdd` when the field is new on both sides with different values,
  - `ModifyModify` when both changed an existing field,
  - `DeleteModify` when one deleted and the other changed,
  - `KindMismatch` when a root is not a table (field `""`), or when a
    module-level metadata component differs between the sides.
- A deletion wins when the other side left the field unchanged.
- A clean merge copies the chosen right-hand subtrees into the left module
  (fragment import), then canonicalizes, which drops the unreferenced fragment
  nodes and validates the result.
- Any conflict returns **no module**, only the conflict list. A caller resolves
  by merging again with a decision about the conflicting fields.

Two inputs never merge automatically, because a clean answer would be wrong or
would leak equality:

- **Module metadata.** Bindings, annotations, provenance and extensions are not
  combined field by field. The canonical forms are compared, and a difference
  between the sides is a conflict named `<bindings>`, `<annotations>`,
  `<provenance>` or `<extensions>` (`KindMismatch`). Keeping the left copy —
  the earlier behavior — silently dropped the right side's change.
- **Secret material.** A field whose subtree reaches a `Secret`/`SecretRef`
  conflicts with `ModifyModify` even when both sides are byte-identical.
  Comparing secret bytes would answer "are these the same secret?", which is
  the anti-oracle invariant (`SECURITY.md` I-2). Only a field that both sides
  deleted still merges cleanly.

## Consequences

- `Merge`, `Conflict`, `ConflictKind` join the public API; `merge` is a free
  function.
- Complexity is O(fields × module size) because each comparison encodes the
  subtree; this is a correctness-first sketch, not the hot path. A future
  revision can hash subtrees once per module. Inputs above `MAX_MERGE_NODES`
  (262 144 nodes) are refused with `infinity/limit` before any canonical form
  is computed, so one large or hostile module cannot turn a local merge into an
  unbounded job.
- Metadata components are compared by **value**: bindings by name and target
  subtree, annotations by payload and target subtree, provenance and extensions
  directly. Comparing prepared indices instead would miss a retarget between two
  shape-identical nodes (silent loss) and would report a conflict whenever one
  side added a node (spurious).
- Nested conflicts are reported at the top-level field name in v1. A dotted
  path and recursive resolution are additive extensions.
- A module with any metadata on one side only cannot be merged by this API. A
  caller that needs to merge such modules strips the metadata it does not need
  (or merges it itself) before calling; the merge never discards it.
- The merge is a local operation; it confers no authority. Who may write each
  side is decided by the RPC capability layer before the modules reach this
  function.
