# Performance baselines (Active Infinity)

`cargo bench -p active-infinity` (criterion; `bench` profile = optimized).
Baseline machine: Windows 11, x86-64, Rust 1.99. Ratios matter more than the
absolute numbers; re-run on your target.

Fixture: 2562 nodes, 135,832-byte canonical image — 256 service tables with four
fields each (string, int, quantity with a unit, array), one secret, two
annotations, provenance.

| Operation | Baseline | Throughput |
|---|---|---|
| `encode` | ~2.4 ms | ~57 MB/s |
| `decode` | ~1.9 ms | ~71 MB/s |
| `validate` (structural only) | ~0.93 ms | ~146 MB/s |
| view construction + hash | ~0.87 ms | ~156 MB/s |

## Where the time goes (and why the shape is right)

- **Encode is not a memcpy, by design.** It normalizes (sorts table fields,
  canonicalizes floats), renumbers nodes by DFS, deduplicates every symbol table
  and derives the edge table. That work is what makes equal modules byte-equal
  and content addressing real (ADR-0005). A raw writer would be faster and wrong.
- **Validate is the gate.** ~146 MB/s of bounded, allocation-light checking:
  every offset, count, reference, string, unit, edge, annotation, provenance
  entry, reachability and depth. A caller that trusts a buffer pays this once.
- **Views are free.** Constructing a view is validation plus header decoding;
  reading a string or a blob afterwards is a slice, not a copy (ADR-0004).
- **Decode allocates the owned IR** (strings, tables, arena). A consumer that
  only needs to read should use the view instead.

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

A change that makes `validate` or `encode` more than 20% slower needs a note
here and a new baseline in the same commit.
