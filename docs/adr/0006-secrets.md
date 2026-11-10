# ADR-0006 — Structural secrets, anti-oracle equality and locator promotion

**Status:** accepted (2026-10-27)

## Context

Active's secret model is absolute: secret material never reaches a diagnostic, a
log, an error message or an export, and secret equality is always false so a
guess cannot be confirmed. `active-core` models a secret as a node kind whose
*locator* is an ordinary node — commonly a string literal written in the source:

```active
password = secret("hunter2")
```

If that literal is encoded as a normal `Str` node, it lands in the public string
heap, and `strings module.ainf` reveals it even though every projection redacts.

## Decision

1. The wire format keeps `Secret` (a literal) and `SecretRef` (a locator) as
   distinct kinds. Taint is the kind; there is no bit to clear.
2. `SecretBytes` has no public accessor for its bytes, no `Display`, no
   `Serialize`, a redacting `Debug`, and a `PartialEq` that always returns
   `false`.
3. Module equality is *structural* and blinds secret payloads: it compares
   presence, never content, so comparing two modules cannot become an oracle.
4. At canonicalization, a string literal that is referenced **only** by secret
   nodes and is not a root is promoted into the secret table. The bytes leave
   the public string heap and live where no projection enumerates.
5. Everything else — projections, diagnostics, provenance lines, graph labels —
   emits the marker `***SECRET***`, and string values equal to a known secret are
   redacted too, so a copy cannot escape.
6. There is no unlock API. The codec and the `active-core` bridge read the bytes
   through a crate-private accessor, and both are audited.

## Consequences

- The raw image still contains secret bytes (it is the data, like the source
  file is). Confidentiality at rest is a storage concern — sign, encrypt or keep
  the module in a protected store. What the format guarantees is that *no code
  path in this crate* prints, exports, serializes or compares them.
- Promotion changes node kinds during encoding (`Str` → `Secret` under a
  `SecretRef`). Decoding, re-encoding and equality all agree, so the change is
  invisible to a consumer beyond the stronger guarantee.
- A literal shared between a secret and a public field is *not* promoted: it is
  public by construction, and hiding it would corrupt the public value.

## Amendment — INF-07: two levels of equality (2026-11-09)

The "secret equality is always false" rule in Context above turned out to be
true at only one level, and the two levels disagreed: `SecretBytes::eq` was
always false (including for self) while `InfinityModule::eq` treated
`(Secret, Secret)` as equal, so generic code comparing nodes (`assert_eq!`
on an `Inode`, `vec.contains`, dedup) got the opposite answer to
module-level code. `structurally_eq` additionally returned false when
`prepare()` failed, so a module with a dangling reference was not equal to
itself.

The rule is now stated per level, and the invariant is unchanged in substance
(no comparison anywhere in this crate looks at secret bytes, so no comparison
can confirm a guess):

1. **Value level — always false.** `SecretBytes::eq` is still always false,
   including for self. This is the anti-oracle rule, and it is what invariant
   I-2 in `docs/spec/security.md` now says.
2. **Node/module level — presence only.** `Inode::Secret == Inode::Secret`
   is true regardless of content, and `InfinityModule::eq` /
   `structurally_eq` compare the same way. Presence-only equality reveals
   nothing beyond the node kind, which is already public via `Inode::kind`,
   so it cannot become an oracle. `Inode`'s `PartialEq` is hand-written
   (`node_eq` in `src/ir.rs`, the single implementation shared with
   `structurally_eq`) so the two levels cannot drift apart again; the match
   is exhaustive, so a new `Inode` variant fails to compile until its
   comparison is decided.
3. **Unpreparable modules — tri-state.** `structurally_eq` falls back to a
   raw-arena comparison when `prepare()` fails, so `==` stays reflexive
   even for a module with a dangling reference; `try_structurally_eq() ->
   Result<bool>` exposes the third state (equal / different /
   unpreparable) for callers that need to distinguish "different" from
   "invalid".
