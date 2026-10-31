# Baseline inventory — active-infinity

Recorded: 2026-10-29, maturity program AIM-PROP-2026-10.
Baseline commit: `249a4e7179af0fab8dca4c1130a1c111ae931a85` (branch `main`).

## Package

| Field | Value |
|---|---|
| Crate | `active-infinity` 2.1.0 |
| Edition / MSRV | 2021 / 1.85 |
| License | MIT OR Apache-2.0 |
| Wire format | AINF 1.0 |
| Default features | `active-core`, `json` |
| Dependencies | `blake3`, `thiserror`; optional `active-core` 1.4.0, `serde_json` |
| Dev dependencies | `proptest`, `sha2`, `criterion`, `blake3` |
| Bench | `benches/codec.rs` (criterion) |

## Public surface

Modules: `canonical`, `decode`, `encode`, `error`, `interop`, `ir`, `layout`,
`protobuf`, `stream`, `unit`, `validate`, `view`.

Root functions: `encode`, `encode_with`, `encode_hashed`, `decode`,
`decode_with`, `validate`, `validate_canonical`, `validate_with`,
`content_hash`, `content_hash_hex`, `hash_image`, `to_protobuf`.

Root re-exports: `Frame`, `FrameKind`, `StreamDecoder`, `StreamEncoder`,
`UnitTag`, `InfinityModule`, `Inode`, `Edge`, `Validated`, `InfinityView`,
`NodeView`, `Error`, `Result`, `VERSION`, `MAGIC`.

Invariants represented in code: structural `Inode::Secret` with redaction across
Debug/JSON/Protobuf/Display helpers; anti-oracle equality; canonical re-encode
fixpoint; finite graph/limit validation; zero-copy `Validated`/view borrows.

## Tests and proof

- 120-test inventory in `docs/hardening/STATUS.md`; suites cover unit,
  integration, property, conformance, red-team, protobuf, API surface, doc gate,
  performance budget and README contract.
- 49 committed conformance vectors under `tests/vectors/{valid,invalid,invalid_stream}`.
- Fuzz targets: `fuzz_canonical_roundtrip`, `fuzz_decode_infinity`,
  `fuzz_graph_cycles`, `fuzz_layout_sections`, `fuzz_projection_agreement`,
  `fuzz_secret_positions`, `fuzz_stream_reassembly`, `fuzz_unit_discriminants`.
- 8 target-specific seed corpora under `fuzz/corpus/`.
- ADRs 0001–0010; specs `layout`, `streaming`, `security`, `projection`,
  `performance`; hardening pack and signed release records.

## Facades and registry

`facades/` contains `active-infinity-core`, `active-infinity-stream`,
`active-infinity-interop`, `active-infinity-wasm`, all 0.1.1 on crates.io.
`active-infinity` 2.1.0 and `active-infinity-cli` 0.1.0 (reserved) are on
crates.io. `REGISTRY.md` maps the family.

## Control-plane coupling

The dashboard service lives in `Active-RPC/control-plane`; it depends on
`active-infinity` 2.1.0 for real encode/decode/validate/hash timings, the status
module, streaming reassembly, redaction proof and the L0–L6 codec scenarios.
No Infinity source depends on the control plane.

## Gaps against AIM-PROP-2026-10

- No schema-class annotation/validation product.
- No incremental canonicalization API after patch.
- Zero-copy is documented and tested, but no explicit benchmark against
  JSON/Protobuf/FlatBuffers/rkyv.
- No zstd compression feature or dictionary training hook.
- No content-addressed module store or signature envelope.
- Conformance vectors exist as tests, but no versioned machine-readable pack or
  `active-infinity-cli conformance run` scorecard.
- No C ABI or WASM export for other languages.
- No `active-infinity-cli` implementation (name reserved only).
