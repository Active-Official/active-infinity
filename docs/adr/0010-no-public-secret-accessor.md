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
   build if a `pub fn secret_*` accessor or a `pub use` of one reappears. The
   forbidden list is explicit, so adding a new accessor requires a visible edit.
4. **This is a breaking change, released as 2.0.0.** The wire format is
   unchanged; only the crate API shrank.

## Consequences

- Callers that used the accessors must migrate to the projections. None of the
  repository's own code, tests, examples or benches needs them, which is itself
  evidence that the API was accidental rather than required.
- A future feature that genuinely needs plaintext inside the crate (for example a
  new redaction path) adds a `pub(crate)` helper, not a public one.
- The public surface is now auditable: the only way out of the crate with data is
  a projection that redacts.
