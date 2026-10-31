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
  - `KindMismatch` when a root is not a table (field `""`).
- A deletion wins when the other side left the field unchanged.
- A clean merge copies the chosen right-hand subtrees into the left module
  (fragment import), then canonicalizes, which drops the unreferenced fragment
  nodes and validates the result.
- Any conflict returns **no module**, only the conflict list. A caller resolves
  by merging again with a decision about the conflicting fields.

## Consequences

- `Merge`, `Conflict`, `ConflictKind` join the public API; `merge` is a free
  function.
- Complexity is O(fields × module size) because each comparison encodes the
  subtree; this is a correctness-first sketch, not the hot path. A future
  revision can hash subtrees once per module.
- Nested conflicts are reported at the top-level field name in v1. A dotted
  path and recursive resolution are additive extensions.
- The merge is a local operation; it confers no authority. Who may write each
  side is decided by the RPC capability layer before the modules reach this
  function.
