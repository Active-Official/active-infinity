# ADR-0007 — Streaming as canonical section transport plus semantic deltas

**Status:** accepted (2026-10-27)

## Context

"Infinity mode" means a module can be unbounded or live-updating: a producer
ships it in pieces, and a consumer applies updates without re-downloading it.
The proposal asks for frames carrying node/edge/string/blob batches and patches.

A second, hand-written node encoder for streaming would be a second source of
truth: the streamed module could differ from the file in subtle ways, and every
format change would have to be made twice.

## Decision

1. A generation is `Begin` + `Batch`* + `End`, where the batches carry the
   canonical *section bytes* of the exact image the encoder would write. The
   reassembler rebuilds the header from the declared counts and flags and
   validates the result like any other buffer. "The stream equals the file"
   therefore holds by construction, not by a second implementation.
2. Batches are chunked (default 64 KiB) so a producer can stream a large section
   with back-pressure from the transport. A zero-byte section still emits one
   empty batch, which keeps the section order unambiguous.
3. Incremental updates are semantic `Delta` frames: set root, put/push a node
   fragment (a fragment is itself a complete canonical image), bind/unbind a
   name, set/clear annotations, set provenance. Applying a delta re-canonicalizes
   and re-encodes, then compares the closing `End` hash. Deltas never invent a
   third representation.
4. Frames are self-delimiting with a per-frame Blake3 prefix, so corruption is
   caught at the boundary and partial reads are buffered.

## Consequences

- Streaming adds framing overhead only; there is no second encoder to drift.
- A delta costs a re-encode on the receiver. For modules that fit comfortably in
  memory (the target workload) that is a millisecond-scale operation; for
  very large live modules the section-batch path remains available.
- The stream is not self-describing beyond the header flags: a consumer must
  know the dialect, which `Begin` carries.
