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
