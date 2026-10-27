# Changelog — Active Infinity

## 1.1.1 — 2026-10-27

Security and correctness fixes from the independent review. No wire-format
change: images written by 1.1.0 remain valid and canonical.

- **Streaming bounds.** A stream may no longer accumulate more section bytes than
  the size declared by `Begin` (or `Limits::max_total_bytes`), and pending delta
  operations are capped by `Limits::max_aux`. Both report `infinity/limit`. A run
  of batches could previously exhaust memory before `End`.
- **Stream decoder limits.** `StreamDecoder::with_limits` lets a caller apply its
  own `Limits` to the reassembled image; the decoder no longer silently uses the
  defaults.
- **Truncated `finish()`.** `StreamDecoder::finish` no longer indexes past a
  partial frame; it reports `infinity/truncated`.
- **Depth over every root.** The depth ceiling is measured from every root
  (module root, bindings, annotation subjects), not just node 0, so a second
  shallow root cannot hide a deep chain.
- **Total-byte and string-heap ceilings** are enforced before decoding.
- **Provenance is a map.** `set_provenance` keeps the last value per key, so the
  encoder can never emit duplicate keys that validation rejects. Reserved entry
  kinds (4+) are refused instead of decoded as a different kind.
- **Projection guards.** Redacted JSON refuses cyclic/dangling modules and bounds
  recursion depth; `value_paths` is cycle-safe.
- **Retired `DeltaOp::PushNode`.** The variant produced unreachable nodes and was
  dropped after canonicalization; tag 2 is refused. Use `PutNode`/`SetBinding`.

## 1.1.0 — 2026-10-27

First production release: canonical `AINF` codec, fail-closed validator,
zero-copy views, streaming frames and deltas, `active-core` bridge, agent graph
queries, redacted JSON projection, conformance vectors, fuzz target.
