# Changelog — Active Infinity

## 1.1.3 — 2026-10-27

- **Begin respects the caller's ceilings.** The declared stream size is compared
  with the decoder's own max_total_bytes, not the defaults.
- **Text projections redact keys and intent text.** provenance_lines redacts
  entry keys and intents() redacts intent text against the module's secret
  literals, matching the JSON projection. New helpers: secret_texts,
  edact_text.

## 1.1.2 — 2026-10-27

- **Delta fragments honour the caller's limits.** A Delta fragment is decoded
  and validated under StreamDecoder's Limits, so a strict consumer cannot be
  handed a larger module through a delta than through a generation.
- **Projection redaction covers metadata.** Table keys, unit names, environment
  names, blob media types and every provenance text field are redacted against
  the module's secret literals, not only values; provenance_json takes the
  secret table and provenance_json_for(module) supplies it.

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
