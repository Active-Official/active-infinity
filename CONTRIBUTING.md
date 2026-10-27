# Contributing to Active Infinity

## Before you start

1. Read `docs/spec/layout.md` (normative) and `docs/adr/`.
2. Read `PROPOSAL.md` for context and `CHECKLIST.md` for the work plan.
3. Run the gates: `cargo fmt --all --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`.

## The rules that are not negotiable

- **Canonical form.** Any change to encoding must keep equal modules
  byte-identical and re-encoding idempotent. Update the vectors with
  `cargo run --example generate_vectors` and review the diff.
- **Fail closed.** New fields or kinds need validation, limits and a stable error
  code before they need documentation.
- **Secrets.** No new code path may read, print, serialize, compare or export
  secret bytes. `SecretBytes::expose` is crate-private for a reason.
- **No `unsafe`.** If a feature seems to need it, write an ADR first.
- **Bounded work.** Every traversal is iterative and every count is checked
  against the bytes before allocation.

## Change shape

- One behaviour per change, with a test that fails before it and passes after.
- New wire-visible constants go in `docs/spec/layout.md` in the same commit, and
  `tests/doc_gate.rs` must stay green.
- A structural decision gets an ADR; a superseding ADR says so.

## Tests

| Suite | What it must prove |
|---|---|
| `tests/unit_tests.rs` | the API contract, per kind and per failure class |
| `tests/integration_tests.rs` | text → Infinity → evaluate, with real modules |
| `tests/conformance_tests.rs` | the checked-in vectors still match |
| `tests/property_tests.rs` | round-trip, hash sensitivity, no panics |
| `tests/redteam_tests.rs` | the threat model's controls |
| `fuzz/fuzz_targets/decode.rs` | arbitrary bytes never crash or hang |

A test that passes while the shipped path is broken is worse than no test: drive
the public entry point, never a copy of the implementation.

## Commits and releases

- Subject line in the imperative ("add", not "added"), body explains *why*.
- Version bumps and changelog entries happen at release time (ADR-0003).
- Releases are signed tags, published to crates.io, then pushed to both
  organization remotes.

## Security reports

Do not open a public issue. Follow `SECURITY.md`.
