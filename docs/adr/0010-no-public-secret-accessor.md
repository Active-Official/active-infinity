# ADR-0010 - No public secret accessor

**Status:** accepted (2026-10-27)

## Context

Active Infinity's secrets are structural: a secret is a node whose bytes live in a
dedicated heap, equality is always false, and every export path redacts against
the module's secret literals. The redaction machinery needs the plaintext to do
its job, so early versions exposed helpers that returned it:

- `interop::secret_texts` — every secret as `Vec<String>`;
- `interop::secret_bytes` (added in 1.2.5 for the byte-level extension check);
- `interop::secret_literals` — the same plaintext behind the JSON feature.

Adversarial verification pointed out the obvious: a public function that returns
secret plaintext *is* an unlock API. A caller can walk a module it received and
read every secret, which contradicts the threat model in
`docs/spec/security.md` and the guarantee the projections make.

## Decision

1. **No public API returns secret material.** The three helpers are
   `pub(crate)`; the only public secret-related item is `SECRET_MARKER`, a
   literal string that carries no secret.
2. **There is no exported replacement.** A consumer that needs to display a
   module uses `to_redacted_json` or `to_protobuf`; a consumer that needs to
   recognize a redacted value compares with `SECRET_MARKER`.
3. **The rule is enforced, not just documented.** `tests/api_surface.rs` fails the
   build when an accessor reappears. It applies three rules over every file under
   `src/`:
   - a blacklist of the names this crate ever exported (`secret_texts`,
     `secret_bytes`, `secret_literals`, `secret_values`, `secret`);
   - a **shape rule**: a public function whose name mentions secrets and whose
     return type is `String`, `Vec<String>`, `Vec<u8>`, `Vec<Vec<u8>>` or
     `&[u8]` is a leak. The return type is read only after the last `->`, so an
     array length such as `[u8; 32]` in the parameter list cannot confuse the
     scan; the body is cut off at `{`, so a one-line body cannot hide the type;
     declarations whose return type starts on its own line are joined;
     `const`/`async`/`unsafe` modifiers are stripped in any order before the name
     is read;
   - an allowlist with a written reason, currently only `secret_tainted_paths`
     (it returns redacted labels, never bytes), plus a check that fails if an
     allowlist entry goes stale.
4. **This is a breaking change, released as 2.0.0 (2.0.1 fixed the last
   accessor).** The wire format is unchanged; only the crate API shrank.

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

## Residual risk

A deliberately obfuscated accessor — an unrelated name returning `Vec<u8>` — can
evade a textual guard. That is a reviewed decision rather than an accident: the
blacklist and shape rule catch the realistic forms, ADR-0010 states the policy,
and a reviewer adding such a function would have to argue against this document.

## Consequences

- Callers that used the accessors must migrate to the projections. None of the
  repository's own code, tests, examples or benches needs them, which is itself
  evidence that the API was accidental rather than required.
- A future feature that genuinely needs plaintext inside the crate (for example a
  new redaction path) adds a `pub(crate)` helper, not a public one.
- The public surface is now auditable: the only way out of the crate with data is
  a projection that redacts.
