# ADR-0005 — Canonical form and content addressing

**Status:** accepted (2026-10-27)

## Context

Content addressing only works if equal content has equal bytes. The naive
encoder writes nodes in arena order, strings in first-use order and edges in
traversal order — all of which depend on *how* a module was built. Two agents
that build the same configuration produce different hashes, and delta
negotiation ("I already have hash H") never fires.

## Decision

The encoder canonicalizes before writing (spec §6):

1. sort table fields; normalize floats (`-0.0` → `+0.0`, one quiet NaN);
2. number nodes by pre-order DFS from the roots, with table fields in key order;
3. drop nodes unreachable from the roots;
4. sort and deduplicate strings, units, types, blobs, hashes, numbers,
   annotations, provenance entries, extensions and edges;
5. derive the edge table from node children and store exactly that;
6. lay out sections in a fixed order with zero padding;
7. hash the whole image with the hash field zeroed.

Validation enforces the same shape: unsorted tables, non-zero slack, a forged
edge table and unreachable nodes are all rejected. A `canonical` header flag
additionally lets a reader prove re-encoding equality.

## Consequences

- Equal modules ⇒ identical bytes ⇒ identical Blake3 address, across builds,
  machines and processes.
- Canonicalization is not free (sorting plus one extra traversal); benchmarks
  record the cost and it stays a small constant factor over raw writing.
- The format cannot preserve "the order the user wrote keys in". That order lives
  in the text formatter's trivia, not in the data model; the binary form is a
  value tree, and value trees are unordered maps.
- Dropping unreachable nodes means a valid image cannot carry hidden data — a
  security property as much as a determinism one.
