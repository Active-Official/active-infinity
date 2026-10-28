# Corpus and coverage inventory — active-infinity

Baseline: 2.0.7 at commit `9b44242496568e2338c5e98b90e558d4b0999f4e`.
Measured 2026-10-27 with `cargo llvm-cov --locked --all-features --summary-only`
on Windows x86_64 (MSVC). Raw logs are kept with the hardening evidence; the
numbers below are the recorded snapshot.

## Conformance vectors (committed)

| Directory | Files | `.ainf` files | Bytes | Purpose |
|---|---|---|---|---|
| `tests/vectors/valid` | 6 (5 images + `index.txt`) | 5 | 2,808 | images that must validate and re-encode identically |
| `tests/vectors/invalid` | 36 (35 images + `index.txt`) | 35 | 35,732 | one image per declared failure code |
| `tests/vectors/invalid_stream` | 10 (9 images + `index.txt`) | 9 | 8,133 | hostile `AINS` frame sequences |
| **Total** | **52** | **49** | **46,673** | |

The `index.txt` files pin the expected size, content hash, node/string/blob
counts and (for `non_canonical`) the canonical flag. `conformance_tests.rs`
checks that the index and the files agree, that every declared code has a
vector, and that every declared invalid class appears in the spec.

Invalid classes present: bad magic, major, minor, header size, header
truncation, flags, hash, padding, section offset, section overlap, node record,
node reference, unit reference, string reference, edge, type, unit
discriminant, UTF-8, provenance, annotation, extension, extension gap,
duplicate field, duplicate binding, reserved tag, cycle, depth, count bomb,
size limit, short count, trailing bytes, not canonical, secret entry.

## Fuzz targets (baseline)

| Target | File | Lines | Corpus in repo | Semantic oracle |
|---|---|---|---|---|
| `decode` | `fuzz/fuzz_targets/decode.rs` | 90 | **no** — CI copies `tests/vectors/*/*.ainf` into an ephemeral `fuzz/corpus/decode/` | validate is total; decode of a validated image; encoder is canonical; canonical form is a fixpoint; views and projections are total; Protobuf projection is deterministic |

Gaps against H1:

- One target covers eight required attack surfaces. H1.1–H1.8 split it.
- The corpus is generated in CI and never committed, so a local
  `cargo fuzz run decode` starts empty and a crash seed cannot be reviewed in
  the pull request.
- No streaming, cycle-shape, unit-discriminant or projection-agreement target.
- `fuzz/Cargo.lock` is committed; `fuzz/target/` is gitignored.

## Almost-valid seed classes required by H1.18

| Class | Present today | Target |
|---|---|---|
| Header content hash non-zero before canonicalization | `not_canonical.ainf` | `fuzz_canonical_roundtrip` |
| Duplicate table keys | `duplicate_field.ainf` | `fuzz_decode_infinity` |
| Unsorted table keys | `not_canonical.ainf` | `fuzz_canonical_roundtrip` |
| Empty key | no | `fuzz_decode_infinity` |
| Edge to a missing node | `bad_edge.ainf` | `fuzz_graph_cycles` |
| Self-loop | `cycle.ainf` | `fuzz_graph_cycles` |
| Mutual cycle | no | `fuzz_graph_cycles` |
| Long cycle | no | `fuzz_graph_cycles` |
| Stream payload validates but differs from whole-module encode | `sequence.ainf` | `fuzz_stream_reassembly` |
| Attenuation dropping a method and raising a budget | n/a (Infinity) | RPC corpus |
| Deep leaf exceeds byte budget while shallow size looks small | `limit.ainf` | `fuzz_budget` (H2) |
| Length exactly at EOF | no | `fuzz_layout_sections` |
| Unknown unit discriminant | `bad_unit.ainf` | `fuzz_unit_discriminants` |
| Duplicate extension tag | `bad_extension.ainf` | `fuzz_layout_sections` |
| Secret in every legal node position | partly (`full.ainf`) | `fuzz_secret_positions` |

## Coverage snapshot (baseline)

| File | Regions | Lines | Functions |
|---|---|---|---|
| `canonical.rs` | 92.30% | 94.79% | 96.36% |
| `decode.rs` | 70.45% | 68.31% | 66.67% |
| `encode.rs` | 93.19% | 97.05% | 100.00% |
| `error.rs` | 77.56% | 76.72% | 50.00% |
| `interop.rs` | 63.26% | 63.94% | 73.40% |
| `ir.rs` | 59.98% | 58.79% | 68.37% |
| `layout.rs` | 87.06% | 85.67% | 73.33% |
| `lib.rs` | 26.92% | 30.77% | 25.00% |
| `protobuf.rs` | 88.08% | 89.47% | 100.00% |
| `stream.rs` | 59.38% | 63.13% | 63.83% |
| `unit.rs` | 53.24% | 50.51% | 100.00% |
| `validate.rs` | 83.96% | 75.19% | 86.59% |
| `view.rs` | **12.37%** | **17.39%** | **24.14%** |
| **Total** | **73.44%** | **71.66%** | **75.00%** |

Interpretation:

- `view.rs` is a public zero-copy surface with almost no direct test coverage.
  The fuzz target exercises it, but the unit suite does not. This is the highest
  priority gap for H1.1 and H2.
- `unit.rs` and `ir.rs` are mostly data/display code; the uncovered lines are
  constructors and formatting that the encoder does not route through. H1.7
  (unit discriminants) should raise `unit.rs`.
- `stream.rs` at 63% lines matches the known streaming gaps in H1.2.
- `lib.rs` is re-exports; coverage there is not meaningful.

## Corpus policy

1. Every fixed or crashed case gets a minimized file under
   `fuzz/corpus/<target>/` with a comment in the commit message naming the
   checklist item and the invariant.
2. The corpus is committed (remove `/fuzz/corpus` from `.gitignore` when the
   first target corpus lands) and is treated as hostile input: it runs under the
   same limits and sanitizers as external bytes.
3. Seeds are deterministic: no timestamps, no random keys, no environment
   dependence.
4. The conformance vectors stay the canonical seed source; the fuzz corpus adds
   near-miss variants, not replacements.
5. CI runs a short campaign on pull requests and a longer campaign on `main`
   and nightly (H1.20).
