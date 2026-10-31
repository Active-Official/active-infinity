# ADR-0014 — Optional proof-carrying sidecars

**Status:** accepted (2026-10-31). Additive; no image or wire change.

## Context

An AINF image is self-describing for its own bytes: the header carries the
content hash, counts and dialect, and validation recomputes them. A consumer
that receives an image *plus* claims about it (size, secret presence, schema)
currently has no compact way to check the claims without decoding everything,
and a producer has no way to state "this is the schema I validated against".

## Decision

`active_infinity::proof` adds an optional JSON sidecar:

```json
{
  "format": "active-infinity/proof/1",
  "content_hash": "<64 hex>",
  "size": 1248, "nodes": 42, "edges": 40, "secrets": 2,
  "major": 1, "minor": 0, "dialect_hash": 1234,
  "canonical": true,
  "schema_hash": "<64 hex>" | null
}
```

- `Proof::issue(image)` requires a canonical image (`validate_canonical`) and
  records the metadata the validator computed.
- `Proof::issue_with_schema(image, schema)` additionally requires the companion
  schema (ADR of the schema class) to accept the instance, and records the
  schema's own content hash.
- `Proof::verify(image)` recomputes everything and refuses any difference with
  `infinity/proof`. When the proof carries a schema hash, the verifier must
  supply the exact schema bytes; a missing or different schema is refused.
- `requires_redaction()` reports the secret-table count so a consumer knows
  whether projections must be redacted.

Properties:

1. **No new trust root.** The sidecar is a claim checked against the image's own
   canonical form; it is not a signature. Signing stays in the signature
   envelope (ADR-0009).
2. **No secrets leave.** The proof carries counts and hashes only.
3. **Optional.** Producers that do not ship a sidecar lose nothing; verifiers
   that ignore it still validate the image.

## Consequences

- `infinity/proof` joins the error vocabulary.
- `active-infinity-cli proof issue|verify` writes and checks sidecars.
- A future signed proof composes the signature envelope; that is a new ADR.
