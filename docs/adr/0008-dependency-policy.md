# ADR-0008 — Dependency policy and supply chain

**Status:** accepted (2026-10-27)

## Context

A data format is a long-lived dependency for everyone who stores bytes with it.
Every crate added to the parser path is a future advisory, a future MSRV bump and
a future supply-chain question. The encoder/decoder is also the component that
touches hostile input directly.

## Decision

1. **Runtime dependencies are minimal and pinned by major**: `blake3` (hashing)
   and `thiserror` (error ergonomics). `active-core` and `serde_json` are
   optional, behind default-on features, and can be dropped with
   `--no-default-features`.
2. **No `unsafe`**, including in dependencies reachable from the parser path
   where a safe alternative exists (`blake3` has a pure-Rust path).
3. **Dev-only**: `proptest` (property tests), `criterion` (benchmarks),
   `blake3` (vector generation), `libfuzzer-sys` (fuzz target, separate crate
   outside the published package).
4. **Supply chain**: `cargo audit` and `cargo deny` run in CI; a CycloneDX SBOM
   (`cargo cyclonedx -f json`) is produced per release and attached to the tag;
   releases are signed with `git tag -s`; the published tarball is verified by
   building it from an isolated consumer crate before the release is announced.
5. **MSRV**: 1.85, matching the Active workspace; a dependency bump that raises
   the effective MSRV is a breaking change for this crate.
6. **Fuzzing**: the decoder target is part of the repository and its corpus is
   checked in; a crash blocks release.

## Consequences

- The published crate builds on a bare toolchain with two dependencies.
- Feature-gated extras keep the security surface of the codec path small: the
  validator never sees `serde_json`, and the `active-core` bridge is a
  conversion layer, not a parser.
- SBOM and signed tags make the release auditable after the fact.
