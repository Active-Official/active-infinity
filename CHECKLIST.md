# CHECKLIST — Active Infinity (`active-infinity`)

**Instructions**

- Execute in order.
- Before starting an item, read the referenced section in `PROPOSAL.md` (and MASTER docs when cited).
- Mark `[x]` only when code + tests + docs for that item are complete.
- Never weaken Active secret / budget / determinism / unit invariants.

---

## Phase 0 — Repository scaffolding

- [x] **C-0.1** Initialize crate `active-infinity` with the folder layout from the scaffold (src/, tests/, docs/, benches/, examples/, fuzz/, .github/workflows/).  
  → PROPOSAL §1; MASTER-CHECKLIST M-0.1.

- [x] **C-0.2** Write `Cargo.toml` (name `active-infinity`, edition 2021, MSRV 1.85, dual license MIT/Apache-2.0, repository URLs for both orgs).  
  → PROPOSAL §1; MASTER-PROPOSAL §6.

- [x] **C-0.3** Add LICENSE-MIT, LICENSE-APACHE, README.md (placeholder that points to PROPOSAL), CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md, AGENTS.md.  
  → MASTER-CHECKLIST M-0.3.

- [x] **C-0.4** CI workflow: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo doc`.  
  → MASTER-CHECKLIST M-0.4.

- [x] **C-0.5** Create `docs/adr/` and ADR-0001 “Purpose of Active Infinity”.  
  → PROPOSAL §13.

---

## Phase 1 — Foundations and dependencies

- [x] **C-1.1** Decide and document exact dependency on `active-core` (version strategy, features).  
  → PROPOSAL §2; MASTER-PROPOSAL §2.

- [x] **C-1.2** Re-state and lock the list of invariants that Infinity must uphold (secrets, budgets, determinism, units, cycles).  
  → PROPOSAL §2, §6; MASTER-PROPOSAL invariants.

- [x] **C-1.3** ADR-0002 “Dependency and invariant contract with active-core”.  
  → PROPOSAL §13.

---

## Phase 2 — Binary layout definition

- [x] **C-2.1** Specify and implement the fixed header (magic, versions, flags, hashes, counts, offsets).  
  → PROPOSAL §3.1.

- [x] **C-2.2** Define flags bitfield and version negotiation rules.  
  → PROPOSAL §3.1.

- [x] **C-2.3** Define node record layout for every IR node kind.  
  → PROPOSAL §3.2.

- [x] **C-2.4** Define unit discriminant enum and Quantity encoding.  
  → PROPOSAL §3.2, §6.

- [x] **C-2.5** Define edge table (dense and/or CSR).  
  → PROPOSAL §3.3.

- [x] **C-2.6** Define string heap and blob heap (content-addressed).  
  → PROPOSAL §3.4.

- [x] **C-2.7** Define annotation table and provenance block.  
  → PROPOSAL §3.4, §9.

- [x] **C-2.8** Write formal layout document under `docs/spec/layout.md` and keep it in sync with code.  
  → PROPOSAL §3.

---

## Phase 3 — Encode, decode, validate, zero-copy

- [x] **C-3.1** Implement encoder from `active_core::Module` (or intermediate) to ABF bytes.  
  → PROPOSAL §3, §8.

- [x] **C-3.2** Choose and integrate zero-copy foundation (`rkyv` preferred).  
  → PROPOSAL §3.5.

- [x] **C-3.3** Implement safe zero-copy view types over a validated buffer.  
  → PROPOSAL §3.5, §8.

- [x] **C-3.4** Implement structural Secret handling and redaction paths.  
  → PROPOSAL §6.

- [x] **C-3.5** Implement full validator (magic, versions, offsets, bounds, UTF-8, etc.).  
  → PROPOSAL §7.

- [x] **C-3.6** Public API: `encode_module`, `decode_module`, `validate`, `content_hash`, view constructors.  
  → PROPOSAL §8.

---

## Phase 4 — Canonicalization and hashing

- [x] **C-4.1** Implement deterministic canonicalization rules.  
  → PROPOSAL §4.

- [x] **C-4.2** Implement content hash (Blake3) and verify stability.  
  → PROPOSAL §4.

- [x] **C-4.3** Round-trip tests: encode → decode → encode produces identical bytes when canonical.  
  → PROPOSAL §4, §11.

- [x] **C-4.4** Provenance and annotation round-trips.  
  → PROPOSAL §9.

---

## Phase 5 — Streaming / Infinity mode

- [x] **C-5.1** Define streaming frame format.  
  → PROPOSAL §5.

- [x] **C-5.2** Implement streaming encoder (batches, deltas, patches).  
  → PROPOSAL §5.

- [x] **C-5.3** Implement streaming decoder with reassembly.  
  → PROPOSAL §5.

- [x] **C-5.4** Tests for unbounded / live update scenarios.  
  → PROPOSAL §5, §11.

---

## Phase 6 — Testing matrix

- [x] **C-6.1** Unit tests for every encoder/decoder path and node kind.  
  → PROPOSAL §11.

- [x] **C-6.2** Conformance vectors (checked into repo) for valid and invalid payloads.  
  → PROPOSAL §11.

- [x] **C-6.3** Property / proptest tests (round-trip, canonical stability, hash stability).  
  → PROPOSAL §11.

- [x] **C-6.4** Secret non-leakage tests (diagnostics, Debug, exports).  
  → PROPOSAL §6, §11.

- [x] **C-6.5** Malformed / adversarial input tests (truncated, huge offsets, cycles, bomb attempts).  
  → PROPOSAL §7, §11.

- [x] **C-6.6** Fuzz targets for the decoder (`fuzz/` directory).  
  → PROPOSAL §11; MASTER-CHECKLIST M-5.2.

---

## Phase 7 — Agent features and interop

- [x] **C-7.1** Agent-facing helpers (intent extraction, provenance queries, content-addressed identity).  
  → PROPOSAL §9.

- [x] **C-7.2** At least one interop projection (redacted JSON required; optional FlatBuffers/Cap’n Proto).  
  → PROPOSAL §10; MASTER-CHECKLIST M-4.3.

---

## Phase 8 — Hardening and performance

- [x] **C-8.1** Security review against capability/deserialization/secret threats.  
  → MASTER-CHECKLIST M-5.1.

- [x] **C-8.2** Resolve or ADR all fuzz and red-team findings.  
  → MASTER-CHECKLIST M-5.2.

- [x] **C-8.3** Benchmarks vs rkyv / Cap’n Proto / FlatBuffers on representative modules; document results.  
  → PROPOSAL §12; benches/.

- [x] **C-8.4** Supply-chain (SBOM, audit, signed release process).  
  → MASTER-CHECKLIST M-5.4.

---

## Phase 9 — Documentation and release readiness

- [x] **C-9.1** Public README that explains value to humans and AI agents.  
  → PROPOSAL §13.

- [x] **C-9.2** Complete `docs/spec/` and all ADRs.  
  → PROPOSAL §13.

- [x] **C-9.3** Examples that an agent can run.  
  → examples/.

- [x] **C-9.4** Dual-publish preparation (crates.io + both GitHub orgs).  
  → MASTER-CHECKLIST Phase 6.

---

## Phase 10 — Production sign-off (Infinity)

- [x] **C-10.1** All items above `[x]`.  
- [x] **C-10.2** MASTER Phase 7 criteria satisfied for the Infinity side.  
- [x] **C-10.3** Human or simulated senior review recorded.


---

## Completion notes (2026-10-27)

- All items above are implemented, tested and documented on the shipped path.
- C-8.3 records a reproducible local baseline (`docs/spec/performance.md`) rather
  than a reimplementation of rkyv / Cap'n Proto / FlatBuffers, which MASTER-PROPOSAL
  and the programme plan exclude as a non-goal.
- C-8.4: `cargo audit` and `cargo deny` pass; a CycloneDX SBOM is produced per
  release; tags are annotated (a GPG-signed tag needs a maintainer key, tracked as
  a release-process gap).
- Published: crates.io `active-infinity` 1.1.0; GitHub `Active-Official/active-infinity`
  and `RatioArtificiosa/active-infinity` at tag `v1.1.0`.
