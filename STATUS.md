# Status — Active Infinity

Honest state of the Active Maturity Program for this repository. A claim here
has a test or a CI job behind it; residual risks are listed, not hidden.

## Release

| Item | Value |
|------|-------|
| Library | `active-infinity` 2.3.0 |
| CLI | `active-infinity-cli` 0.3.0 |
| AINF wire format | 1.0 (unchanged through the maturity program) |
| CI | every job green on both `Active-Official` and `RatioArtificiosa` at the release commit |

## Phase status

| Phase | State | Evidence |
|-------|-------|----------|
| C-0 baseline / C-1 invariants / C-2 strategy | complete | inventories, ADRs and gates in the repository |
| C-3 schema, delta, zero-copy, zstd | complete | `Schema`, `apply_delta`, `InfinityView`, `compress` |
| C-4 store, signatures, conformance pack | complete | `Store`, `signature`, `conformance/manifest.json`, `conformance run` |
| C-5 RPC kernel (in the RPC repository) | complete | see `active-rpc/STATUS.md` |
| C-6 transports (RPC) | complete | see `active-rpc/STATUS.md` |
| C-7 speed and bakeoffs | complete | `docs/spec/performance.md`, `perf-gate` |
| C-8 polyglot matrix (20 languages) | complete | `polyglot/STATUS.md`, `polyglot-rpc`, `polyglot-matrix` |
| C-9 CLIs | complete | `active-infinity-cli` 0.3.0 on crates.io, man page, CLI tests |
| C-10 hardening | complete | nightly fuzz, `polyglot-rpc` strict mode, supply-chain gates |
| C-11 innovations | complete | TTL caps and receipts (RPC), replay (RPC), WASM tools (RPC), proof sidecars, three-way merge, topics (RPC) |
| C-12 interop | complete | `docs/spec/projection.md` authority rules, bridge spec in the RPC repository |
| C-13 release | complete | this file, `docs/release-runbook.md`, dual-remote push, crates.io |

## Verification

- `cargo fmt --all --check`, `cargo clippy --locked --all-targets --all-features`
  and `--no-default-features` with `-D warnings`.
- `cargo test --locked --all-features` and `--no-default-features`.
- `cli/active-infinity-cli`: `cargo test --locked` and clippy.
- `ffi/active-infinity-ffi`: ABI tests and the C consumer.
- `polyglot`: every binding against the shared manifest; thin RPC clients
  against the real kernel; byte-exact encoder conformance.
- Security: `cargo audit` and `cargo deny check` are clean; the SBOM job
  generates and verifies the CycloneDX inventory on every run.

## Residual risks

1. **Proof sidecars are integrity checks, not signatures.** The Blake3 checksum
   detects corruption and naive edits; a party that can rewrite the file can
   recompute it. Authenticity needs the signature envelope (ADR-0013).
2. **Projections are not authoritative.** JSON and Protobuf are views; a
   consumer must re-validate the AINF bytes to verify identity
   (`docs/spec/projection.md` §0).
3. **Merge is field-level.** Conflicts are reported at the top-level field name;
   nested conflict paths and automatic resolution are not implemented.
4. **Compression is transport/storage.** The content hash is always over the
   uncompressed canonical image; a compressed profile would need an ADR.
5. **Facade crates** (`active-infinity-core/stream/interop/wasm` 0.1.x) are thin
   re-exports that pin the library with a caret range; they are released
   separately.
6. **Benchmarks are single-host.** Tables in `docs/spec/performance.md` record
   the host and methodology; they are not vendor claims.
7. **WASM guest tools** (in the RPC repository) run without host imports in ABI
   v1; a host-call ABI needs a new ADR and capability policy.
8. **Kotlin/Native and Swift** bindings are verified in the toolchain container
   and CI; local toolchains are not installed on every developer machine.
