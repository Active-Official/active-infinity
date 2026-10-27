# ADR-0010 - No public secret accessor

**Status:** accepted (2026-10-27)

## Context

Active Infinity's secrets are structural: a secret is a node whose bytes live in a
dedicated heap, equality is always false, and every export path redacts against
the module's secret literals. The redaction machinery needs the plaintext to do
its job, so early versions exposed helpers that returned it:

- `interop::secret_texts` — every secret as `Vec<String>`;
- `interop::secret_bytes` (added in 1.2.5 for the byte-level extension check);
- `interop::secret_literals` — the same plaintext behind the JSON feature;
- `interop::secret_table` — the same text table, used by the projections;
- `Validated::secret` — raw secret bytes straight out of a validated image, with
  a doc comment that claimed to be crate-internal while the signature was `pub`.

Adversarial verification pointed out the obvious: a public function that returns
secret plaintext *is* an unlock API. A caller can walk a module it received and
read every secret, which contradicts the threat model in
`docs/spec/security.md` and the guarantee the projections make.

## Decision

1. **No public API returns secret material.** All five helpers above are
   `pub(crate)`. The public secret-related surface is limited to items that carry
   no secret bytes:
   - `SECRET_MARKER` — a literal string;
   - `interop::secret_tainted_paths` — redacted dotted labels of the tainted
     cone (allowlisted in the gates, with a test that proves the labels are
     redacted);
   - `InfinityModule::has_secret` and `Inode::is_secret` — booleans;
   - `Inode::Secret(SecretBytes)` — the container itself, whose payload has no
     public read path and a redacting `Debug`/`Display`.
2. **There is no exported replacement.** A consumer that needs to display a
   module uses `to_redacted_json` or `to_protobuf`; a consumer that needs to
   recognize a redacted value compares with `SECRET_MARKER`.
3. **The rule is enforced at two layers.**
   - **Authoritative:** `scripts/api_surface.py` reads the rustdoc JSON
     (`cargo +nightly rustdoc -- -Zunstable-options --output-format json`) and
     walks the *resolved* public API — free functions, inherent methods, trait
     methods and re-exports. It fails when a public item's name is blacklisted or
     mentions secrets and its return type resolves to raw text or bytes
     (`String`, `str`, `char`, `u8`, in any container, through any chain of
     crate-local type aliases). A glob re-export is refused as unauditable, and an
     alias whose public name mentions secrets is checked against the target's
     shape (or refused when the target cannot be resolved). The gate fails closed
     on schema drift: it pins the rustdoc `format_version`, requires a non-empty
     item index, requires `inner`/`visibility` on every item, and fails when the
     number of recognised functions drops to a suspicious level. CI runs it in
     the `api-surface` job.
   - **Tripwire:** `tests/api_surface.rs` runs with plain `cargo test` and no
     nightly toolchain. It catches the realistic textual forms — the blacklist, a
     shape rule over the text after the last `->`, attributes, modifier chains,
     glob re-exports and aliased re-exports with a secret name — and documents the
     policy. It is deliberately *not* the guarantee: a text scan can be spelled
     around, which is why the semantic gate exists.
4. **This is a breaking change, released as 2.0.0 (2.0.1-2.0.6 fixed the last
   accessor and hardened the checks).** The wire format is unchanged; only the
   crate API shrank.

## What is not a leak

Some public accessors return bytes on purpose:

- `Validated::buf()`, `Validated::section()`, `decode()` and `encode()` return or
  reproduce the caller's own buffer. The caller already holds those bytes;
  reading them out adds no authority.
- `Inode::Secret(SecretBytes)` carries the secret as a node the caller
  constructed, and `SecretBytes` has no public accessor (`expose` is crate-only)
  and a redacting `Debug`/`Display`.
- The redaction helpers take secret literals as *input* (`redact_text`,
  `provenance_json`); they return redacted text, never secret text.

## Scope of the gate

The gate is name-scoped: it flags a *public function-like item whose name mentions
secrets* and whose resolved return is raw text or bytes. It deliberately does not
model:

- public associated constants and associated types (no such item exists in the
  crate today);
- public struct fields and enum-variant fields (the only secret-carrying type is
  `SecretBytes`, whose field is private);
- macro-generated items (`macro_export`), of which the crate has none;
- an accessor with an unrelated name that returns `Vec<u8>`.

Those are reviewed decisions, not scanner blind spots that a rename can open: a
new item in any of those categories is visible in the diff, and the ADR is the
place the reviewer has to argue against.

## Residual risk

A deliberately obfuscated accessor — an unrelated name returning raw bytes — can
evade both checks, because both are name-scoped. That is a reviewed decision
rather than an accident: the blacklist and the shape rule catch the realistic
forms, the schema-drift guards keep the authoritative gate honest, and a reviewer
adding such a function would have to argue against this document.

## Consequences

- Callers that used the accessors must migrate to the projections. None of the
  repository's own code, tests, examples or benches needs them, which is itself
  evidence that the API was accidental rather than required.
- A future feature that genuinely needs plaintext inside the crate (for example a
  new redaction path) adds a `pub(crate)` helper, not a public one.
- The public surface is now auditable: the only way out of the crate with data is
  a projection that redacts.
