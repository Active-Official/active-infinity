# Agent rules for active-infinity

You are working on the canonical binary form of Active. Correctness and security
come before speed; every claim must be backed by a test on the shipped path.

## Read first

1. `docs/spec/layout.md` — normative byte layout, error codes, canonical form.
2. `docs/spec/streaming.md` — frames and deltas.
3. `docs/spec/security.md` — threat model and controls.
4. `docs/adr/` — why the layout is what it is.
5. `CHECKLIST.md` / `PROPOSAL.md` — plan and context.

## Non-negotiable invariants

- Equal modules ⇒ identical bytes ⇒ identical Blake3 address.
- Secrets are a kind; never compared, never printed, never exported.
- Validation is fail-closed: no panic, no unbounded allocation, no unbounded
  traversal, no stable-free error.
- A view is only constructible from a validated buffer.
- `#![forbid(unsafe_code)]` stays.

## Workflow

- Change one behaviour at a time; add the test that would fail without it.
- Regenerate conformance vectors and review the diff.
- Keep `docs/spec/layout.md` in step with the code (`tests/doc_gate.rs` enforces
  the facts that matter).
- Run: `cargo fmt --all --check`, `cargo clippy --all-targets --all-features -- -D
  warnings`, `cargo test --all-features`, `cargo doc --no-deps`.

## Remotes

`origin` is `Active-Official/active-infinity`; `ratio` is
`RatioArtificiosa/active-infinity`. A release tag goes to both.

## Stubs

A stub is allowed only when a later checklist item completes it, and it must carry
a `TODO(CHECKLIST <id>)` marker with the reason. An undocumented stub is a bug.
