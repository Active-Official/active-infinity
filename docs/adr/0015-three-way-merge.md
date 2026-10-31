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
  moved inside a module still compares equal. Only the subtree's reachable cone
  is materialised, never the whole module.
- One side changed → take that side.
- Both sides changed identically → take it once.
- Both sides changed differently → conflict:
  - `AddAdd` when the field is new on both sides with different values,
  - `ModifyModify` when both changed an existing field,
  - `DeleteModify` when one deleted and the other changed,
  - `KindMismatch` when a root is not a table (field `""`), when annotations
    differ, or when bindings, provenance or extensions were changed differently
    on both sides (the conflict is named after the component).
- A deletion wins when the other side left the field unchanged.
- A clean merge copies the reachable cone of each chosen right-hand subtree
  into the left module (fragment import), then canonicalizes and validates the
  result. Left-side nodes the merge replaced become unreachable and are dropped
  by canonicalization.
- Any conflict returns **no module**, only the conflict list. A caller resolves
  by merging again with a decision about the conflicting fields.

Two inputs never merge automatically, because a clean answer would be wrong or
would leak equality:

- **Annotations.** An annotation has no name to merge by. A set union would let
  two sides that each replaced the same annotation end up with both intents,
  constraints or immutability flags, so any difference is a conflict named
  `<annotations>` (`KindMismatch`). The comparison is order-insensitive (the
  annotation list is sorted by content) and redacted.
- **Secret material.** A field whose subtree reaches a `Secret`/`SecretRef`
  conflicts with `ModifyModify` even when both sides are byte-identical.
  Comparing secret bytes would answer "are these the same secret?", which is
  the anti-oracle invariant (`SECURITY.md` I-2). Only a field that both sides
  deleted still merges cleanly.

**Bindings, provenance and extensions are base-aware**, like a field: a
component changed on one side only is taken, a component changed identically on
both sides is taken once, and a component changed differently on both sides is a
conflict named `<bindings>`, `<provenance>` or `<extensions>`. Free text in
provenance and annotation payloads is compared **redacted** (secret literals
replaced by the marker first), so a metadata comparison cannot be used to guess
a secret. An extension payload that is not UTF-8 cannot be redacted; a set that
holds one next to a secret is a conflict rather than a comparison.

## Consequences

- `Merge`, `Conflict`, `ConflictKind` join the public API; `merge` is a free
  function.
- Each comparison materialises only the reachable cone of the compared
  subtree, so a merge costs O(compared nodes), not O(fields × module size):
  measured on a 60 000-node arena with 1 000 fields, 62.5 s before the cone walk
  and 107 ms after it (release, same machine). A total visit budget
  (`MAX_MERGE_WORK`, 16 × `MAX_MERGE_NODES`) bounds a pathological nested
  conflict walk, and right-hand imports are charged against `MAX_MERGE_NODES`.
  Inputs above the node ceiling, or with a dangling reference, a cycle or
  excessive depth, are refused with `infinity/limit` / `infinity/node-ref`
  before any canonical form is computed.
- Metadata components are compared by **value**: bindings by name and target
  subtree, annotations by payload and target subtree, provenance and extensions
  through a deterministic redacted rendering. Comparing prepared indices instead
  would miss a retarget between two shape-identical nodes (silent loss) and
  would report a conflict whenever one side added a node (spurious).
- Nested conflicts are reported with a **dotted path** (`server.port`) to the
  leaf that differs, with the leaf's own kind (`AddAdd`, `ModifyModify`,
  `DeleteModify`). A field name escapes `\`, `.` and a leading `<`, so a field
  literally named `a.b` renders as `a\.b` and cannot be confused with a nested
  `a.b` or with a `<bindings>` marker. The walk stops at 64 levels, never
  descends when the base is not a table (the shape changed; the parent's
  conflict stands), never descends into a subtree that reaches a secret, and
  falls back to the parent field's conflict when the shapes cannot be
  described. Total conflict-path bytes are capped at 1 MiB (`infinity/limit`).
- Resolution is still all-or-nothing: any conflict returns no module.
- A one-sided metadata change is adopted for bindings, provenance and
  extensions. Annotations remain all-or-nothing: a difference is a conflict, and
  a caller that needs to combine them strips the annotations it does not need
  (or merges them itself) before calling; the merge never discards one silently.
- The merge is a local operation; it confers no authority. Who may write each
  side is decided by the RPC capability layer before the modules reach this
  function.
