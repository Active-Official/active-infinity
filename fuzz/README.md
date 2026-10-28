# Fuzzing

Eight targets cover the untrusted-input surface. Every target drives the
shipped public API and asserts a semantic invariant, not only "did not crash".

| Target | Surface | Invariant |
|---|---|---|
| `fuzz_decode_infinity` | `validate`, `decode`, `encode`, `validate_canonical`, `InfinityView`, projections | a validated image decodes; encoder output is canonical; the canonical proof is a fixpoint |
| `fuzz_stream_reassembly` | `encode_stream`, `StreamDecoder`, `decode_stream` | any byte split reassembles to the whole-module image; hostile frames fail closed |
| `fuzz_canonical_roundtrip` | mutate → encode/decode | construction order and arena order do not change bytes or hash |
| `fuzz_layout_sections` | header section offsets, counts, total size | malformed layout is refused with a stable `infinity/*` code before allocation |
| `fuzz_graph_cycles` | `Ref` chains repointed backwards | every cycle shape surfaces as `infinity/cycle` |
| `fuzz_secret_positions` | secrets in binding names, keys, annotations, provenance | no export path carries the literal |
| `fuzz_unit_discriminants` | unit table and quantity unit index | unknown units are `infinity/unknown-unit`; out-of-range is `infinity/unit-ref` |
| `fuzz_projection_agreement` | JSON and Protobuf projections | both redact, both carry the marker, both are deterministic, protobuf advertises the hash |

## Running

`cargo-fuzz` does not launch on Windows MSVC: libFuzzer reports
`STATUS_DLL_NOT_FOUND`. The supported lane is the Linux container, which carries
clang, nightly and cargo-fuzz:

```bash
python scripts/fuzz_docker.py --build          # once
python scripts/fuzz_docker.py --all --runs 20000
python scripts/fuzz_docker.py --target fuzz_graph_cycles --runs 100000
```

The scripts mount the repository at `/work`, so the corpus grows in place.

On a native Linux host, the same commands work through cargo-fuzz directly:

```bash
cargo +nightly fuzz run fuzz_decode_infinity -- -runs=200000
```

## Corpus

Seeds are committed under `fuzz/corpus/<target>/`:

- all 49 conformance vectors for the decoder;
- the valid corpus plus `not_canonical.ainf` for the canonical target;
- the layout-fault vectors for the section target;
- `cycle.ainf`, `too_deep.ainf` and a generated long cycle for the graph target;
- `full.ainf`, `secret_entry.ainf` and a generated metadata-copy module for the
  secret target;
- `bad_unit.ainf`, `unit_ref.ainf` and a generated unknown-unit image;
- a generated stream (`valid-stream.bin`) and the invalid stream vectors.

Every fixed bug adds a minimized seed named after the checklist item. Seeds are
deterministic, contain no customer data, and are treated as hostile input.

`fuzz/target` and `fuzz/artifacts` stay ignored.

## Budgets

Pull requests run a short campaign per target; `main` and the nightly lane run
a longer one. A crash, an assertion failure, or a new artifact fails the lane;
the artifact is attached to the issue with the input that produced it.
