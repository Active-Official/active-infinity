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
