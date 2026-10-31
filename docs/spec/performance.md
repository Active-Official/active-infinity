# Performance baselines (Active Infinity)

`cargo bench --locked --bench codec` (criterion; `bench` profile = optimized).
Baseline machine: Windows 11, x86-64, Rust stable, 20 samples with a 1 s warm-up
and 2 s measurement per point, run on an otherwise idle machine (2026-10-27).
Ratios and growth are the durable claim; absolute numbers move with the host.

The matrix is checked in and run by `cargo bench`; CI runs the same benchmark
binary with `--no-run` so a benchmark that stops compiling is a build failure
(H4.1, H4.5). Regression policy is at the end of this file.

## Matrix

| Shape | Nodes | Bytes | encode | decode | validate | view + hash |
|---|---|---|---|---|---|---|
| wide-64 | 642 | 34,456 | 716 µs | 299 µs | 132 µs | 147 µs |
| wide-256 | 2,562 | 135,832 | 2.08 ms | 1.33 ms | 458 µs | 452 µs |
| wide-1024 | 10,242 | 541,336 | 9.92 ms | 5.42 ms | 1.81 ms | 1.74 ms |
| deep-32 | 66 | 4,632 | 101 µs | 53 µs | 18.9 µs | 17.1 µs |
| deep-128 | 258 | 16,728 | 373 µs | 191 µs | 47.8 µs | 56.0 µs |
| deep-512 | 1,026 | 65,112 | 1.20 ms | 788 µs | 174 µs | 213 µs |

Wide shapes are sibling service tables (string, int, quantity, array per row);
deep shapes are a chain of two-field tables. Both carry a secret, annotations
and provenance, so the redaction path is measured with the codec.

Throughput at wide-256: encode ~65 MB/s, decode ~102 MB/s, validate ~296 MB/s,
view ~300 MB/s.

## Growth

Validation and decode scale linearly with node count on the wide axis
(2,562→10,242 nodes, 4× the input: validate 4.0×, decode 4.1×, encode 4.8×).
Depth costs a bounded DFS, not recursion: deep-512 (8× deep-32 nodes) is 9.3×
the validate time and 12× the view time, and the validator still stops at
`Limits::max_depth` before the stack is at risk.

`tests/perf_budget.rs` enforces the shape, not the machine:

- `validation_scales_linearly` — 20k-field table at most 60× the 1k-field
  validation time plus 100 ms.
- `hostile_rejection_is_bounded` — 1,000 count-bomb validations complete in
  under 2 s.
- `repeated_validation_does_not_grow_rss` (Linux) — 20,000 validations grow RSS
  by less than 64 MiB.

## Where the time goes (and why the shape is right)

- **Encode is not a memcpy, by design.** It normalizes (sorts table fields,
  canonicalizes floats), renumbers nodes by DFS, deduplicates every symbol table
  and derives the edge table. That work is what makes equal modules byte-equal
  and content addressing real (ADR-0005). A raw writer would be faster and wrong.
- **Validate is the gate.** Hundreds of MB/s of bounded, allocation-light
  checking: every offset, count, reference, string, unit, edge, annotation,
  provenance entry, reachability and depth. A caller that trusts a buffer pays
  this once.
- **Views are free after validation.** Constructing a view is validation plus
  header decoding; reading a string or a blob afterwards is a slice, not a copy
  (ADR-0004).
- **Decode allocates the owned IR** (strings, tables, arena). A consumer that
  only needs to read should use the view instead.

## Hostile-input DoS budget

Budgets, not wall-clock luck, bound the work:

| Attack | Bound | Evidence |
|---|---|---|
| count bomb | declared counts checked against the buffer before allocation | `redteam_battery` H2.1, H2.5 |
| overlapping sections | rejected by offset arithmetic | H2.2 |
| deep nesting | `Limits::max_depth`, iterative traversal | H2.3 |
| shared-DAG expansion | `PROJECTION_NODE_BUDGET = 100_000` materialised nodes | H2.4, `projection_budget_refuses_an_exponential_dag` |
| slowloris stream | per-frame and total byte ceilings | H2.7 |
| repeated validation | no per-call state; RSS non-growth test | H4.4 |
| 32-bit `usize` | full suite under i686 | `scripts/check_32bit.sh` |

No hostile input in the battery reaches host OOM: each fails closed with an
`infinity/*` code before the allocation or traversal that would be unbounded.

## Honest comparison

`rkyv` and Cap'n Proto are *zero-copy deserializers*: their read path is measured
in nanoseconds because they do not validate and do not canonicalize. Infinity
makes the opposite trade:

- it validates before anything is trusted (bounded, fail-closed);
- it canonicalizes so that one logical module has exactly one address;
- it refuses slack, forged edges and unreachable nodes.

A benchmark that compared only the read path would favour rkyv and would be
measuring a different guarantee. What this repository claims is: bounded
validation at hundreds of MB/s, zero-copy reads after validation, and a
canonical identity no zero-copy format offers.

## Known optimization headroom

- `prepare` clones the arena to normalize it; a mutating path that normalizes in
  place would remove one full copy.
- The string index uses `HashMap<String, u32>`; a sorted slice with binary
  search would cut allocations on large heaps.
- Encoding writes section-by-section into one `Vec`; a size-precomputed
  allocation would avoid reallocation.

These are tracked as follow-up work, not correctness gaps.

## Regression policy

A change that makes `validate` or `encode` more than 20% slower on the same
machine needs a note here and a new baseline in the same commit. CI must keep
the benchmark binary compiling and the shape tests (`tests/perf_budget.rs`)
green; it does not gate on cross-machine absolute time.

## Bakeoff (C-7, 2026-10-30)

Host: Intel Xeon E5-1650 v4 @ 3.60 GHz, Windows 10 Pro, 64 GiB RAM,
`rustc 1.99.1`. Criterion, 20 samples, 1 s warm-up, 2 s measurement, otherwise
idle. Reproduce:

```text
cargo bench --all-features --bench bakeoff -- "competitors_encode"
cargo bench --all-features --bench bakeoff -- "infinity_batch"
cargo run --release --example bakeoff_sizes --all-features
cargo run --release --example perf_matrix --all-features
python scripts/perf_gate.py perf-matrix.json
```

### Encoded size on one logical table

A table of N string-to-integer fields plus a name, encoded by Active Infinity
and three real competitors. `serde_json`, `prost` (a protobuf map) and `rkyv`
measure the same data; none of the three is canonical, validating or graph-aware
(rkyv is zero-copy, but it neither validates on read nor canonicalizes).

| Fields | Infinity | serde_json | prost | rkyv |
|---|---|---|---|---|
| 8 | 880 B | 114 B | 111 B | 224 B |
| 1,000 | 69,240 B | 15,798 B | 15,769 B | 28,560 B |
| 10,000 | 699,240 B | 177,798 B | 168,769 B | 307,760 B |

rkyv's numbers are from rkyv 0.8.18 (the 0.7 line is affected by
RUSTSEC-2026-0235); its framing overhead is larger than 0.7's, so its size row
grew relative to earlier revisions of this table.

Infinity is about 4x the JSON size on this shape. The bytes buy a fixed 48-byte
node record per value (`kind`, inline scalar, auxiliary index), an 8-byte edge
per table entry, a symbol table that deduplicates repeated names, canonical
field order, unit and type tables, and structural secret separation. A format
that stores only the values cannot offer those properties. Where bandwidth is
the binding constraint, the `zstd` feature compresses the image for transport
while the content hash stays over the uncompressed bytes.

### Encode latency (median)

| Fields | Infinity | serde_json | prost | rkyv |
|---|---|---|---|---|
| 8 | 14.8 µs | 2.86 µs | 2.10 µs | 1.55 µs |
| 1,000 | 688 µs | 261 µs | 201 µs | 181 µs |
| 10,000 | 9.32 ms | 3.48 ms | 2.42 ms | 1.73 ms |

Re-measured after the rkyv 0.8 upgrade; the competitor rows move with machine
load, so treat them as one snapshot rather than a fixed ratio.

Encode is not a memcpy by design: it normalizes, renumbers by DFS, deduplicates
every symbol table and re-derives the edge table so equal modules are byte-equal.
The C-7 profiling work removed one full clone of every node from that path:
canonicalization now moves each owned node into its final position and rewrites
its references in place (`canonical::remap_node_in_place`). On the 10k shape the
same benchmark moved from **16.9 ms to 9.3 ms (−45%)**.

### Read side

| Shape | Bytes | validate (p50) | decode (p50) | content hash |
|---|---|---|---|---|
| 1k fields | 69,240 | 0.18 ms | 0.61 ms | — |
| 10k fields | 699,240 | 1.63 ms | 3.52 ms | 1.70 ms |

Validation is the gate a consumer pays once; it is roughly 2x faster than decode
because it never allocates the owned IR. These rows come from
`examples/perf_matrix` (p50 over 200 samples); the competitor table above comes
from the criterion bench, which reports a mean over a shorter run. Run-to-run
variation on this host is about 20%.

### Batch encode

`encode_into` writes into a caller-owned buffer and `encode_many` reuses one
buffer per module. On 32 modules of 1,000 fields:

| Path | Time |
|---|---|
| `encode` per module (`Vec` per image) | 19.9 ms |
| `encode_many` with reused buffers | 17.9 ms (−10%) |

The batch path matters for a server that encodes many modules per tick; the
bytes are identical and `tests/encode_batch_tests.rs` proves it.

### The gate

`scripts/perf_gate.py` enforces tail stability (p95 ≤ 4× p50 plus slack for one
scheduler hiccup), linear scaling (10k/1k ≤ 24x for encode, 20x for
validate/decode) and encoded-size growth. Encode gets the widest band because
its 10k working set leaves the runner's L2 cache; a quadratic encoder would be
near 100x. CI runs the ratio gate in the `perf-gate` job
and uploads the matrix as an artifact; `--baseline docs/spec/perf-baseline.json`
adds an absolute comparison (p50 ≤ 1.6x, p99 ≤ 3.0x) for a release machine.

## Multi-host methodology (M-2.4)

Every number above comes from one machine. A single host cannot tell a cache
effect from an algorithm, so the protocol below is what a multi-host claim
requires; the tables in this file stay labelled as single-host until it is run.

### Protocol

1. **Pin the environment.** Same commit, same `Cargo.lock`, same toolchain
   (`rustc -Vv` recorded), release profile, no turbo/undervolt toggles, and a
   fixed CPU affinity for the measured process (`taskset -c 2` or equivalent).
2. **Record the host.** CPU model, physical cores, base/boost frequency, L1/L2/L3
   sizes, RAM type and speed, kernel (`uname -a`), filesystem and governor. The
   matrix runner prints a machine-readable header; attach it to the run.
3. **Warm up, then sample.** One untimed warmup pass, then at least 200 samples
   per cell; report p50, p95 and p99, never a single run.
4. **Run each host at least twice**, on different days, and report both runs.
   A cell whose two runs differ by more than 25% is reported with the spread and
   does not become a headline number.
5. **Compare shapes, not absolutes.** Cross-host comparisons use ratios
   (10k/1k scaling, encode/validate, this crate/competitor on the same host),
   because ratios survive clock and cache differences that absolutes do not.
6. **Publish per-host tables** with the host record, plus one summary table that
   states the range across hosts. Never average hosts into a single number.
7. **Archive the raw output.** The CI `perf-gate` job already uploads the matrix
   artifact; a multi-host campaign archives one artifact per host under the same
   run id.

### What the harness gives you

```text
cargo run --release --locked --quiet --example perf_matrix --all-features
python scripts/perf_gate.py --matrix perf-matrix.json --baseline docs/spec/perf-baseline.json
```

`perf_matrix` emits the JSON the gate consumes, so a second host is a matter of
running the same command there and keeping both files. The gate's absolute
baseline is host-specific by construction: regenerate
`docs/spec/perf-baseline.json` on a new host and record that you did.

### Status

- Single-host: measured and published above (this document).
- Multi-host: not yet run. The checklist item records that this section is the
  methodology and the tables remain single-host by design.
