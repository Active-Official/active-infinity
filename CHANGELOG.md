# Changelog — Active Infinity

## 1.2.0 — 2026-10-27

No wire-format change: images written by 1.1.x remain valid and canonical. This
release adds a binary interop projection, first-class extension blocks, and a
conformance suite that covers every byte-reachable failure class in the
specification.

- **Protobuf projection.** `to_protobuf` renders a module as Protobuf wire
  format for consumers in other languages: root value, bindings, annotations,
  provenance, extensions, and the canonical image's Blake3 hash and size. The
  encoding is deterministic and redacted, uses no new dependency, and is
  documented in `docs/spec/projection.md` and ADR-0009. An independent reader in
  `tests/protobuf_tests.rs` checks the bytes.
- **One redacted tree for both projections.** `interop::Projected` is built once
  and rendered to JSON or Protobuf, so the two projections cannot disagree about
  what is safe to expose. `to_redacted_json` output is unchanged.
- **Extension blocks are first-class in the API.** `InfinityModule::add_extension`,
  `extensions` and `set_extensions` carry application-defined `(tag, payload)`
  blocks; encoding sorts them by tag and refuses duplicates, decoding returns
  them, and the validator checks the directory, payload order and the section's
  end.
- **Acyclicity is its own validation step.** A cycle is reported as
  `infinity/cycle` after reachability instead of surfacing as a depth failure,
  so a peer can tell "too deep" from "cyclic". The check is iterative.
- **Duplicate table fields name their node.** A repeated field key reports
  `infinity/duplicate-field { node }`; an unsorted key still reports
  `infinity/node`.
- **Conformance vectors cover the specification.** 34 invalid images and 9
  invalid streams, one per byte-reachable failure class, plus a
  specification-to-vector test: a new error code fails the suite until it has a
  vector or an explicit, justified waiver.

## 1.1.3 — 2026-10-27

- **Begin respects the caller's ceilings.** The declared stream size is compared
  with the decoder's own max_total_bytes, not the defaults.
- **Text projections redact keys and intent text.** provenance_lines redacts
  entry keys and intents() redacts intent text against the module's secret
  literals, matching the JSON projection. New helpers: `secret_texts` and `redact_text`.

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
