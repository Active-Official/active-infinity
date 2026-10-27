# Changelog — Active Infinity

## 1.2.3 — 2026-10-27

Third review pass. No wire-format change. Two of these are regressions introduced
by 1.2.2 and are the reason 1.2.2 is yanked.

- **Redaction is a fixpoint for every secret, including one that contains the
  marker.** A replacement can join the text around it into a new secret
  (`"hid" + marker + "den"`), so the pass now repeats until the text is clean and
  falls back to the marker, with matches applied longest-first so the result is
  independent of the secret table's order. Property-tested over random secrets
  and texts.
- **An empty module is valid again.** `InfinityModule::check_depth` returned
  `infinity/cycle` for a module with no nodes; it now returns `Ok`, and
  `check_depth(0)` still runs the cycle check.
- **Agent-facing labels are redacted.** `value_paths` and `node_label` returned
  raw binding and field names, so a name containing a secret copy could reach a
  log or a model. Keys are now redacted like every other label.
- **Provenance key collisions are refused, not silently merged.** When redaction
  maps two keys onto one, the encoder reports `infinity/encode`
  (`provenance keys collide after redaction`) instead of dropping an entry; an
  image with duplicate provenance keys was never valid.
- **Projections agree on duplicate provenance keys** (first entry wins) for a
  hand-built module that never went through the encoder.
- **Labels and data text follow one documented rule**: data text that contains a
  secret becomes the marker, labels have each occurrence replaced. Unit names and
  environment names are labels; `docs/spec/projection.md` states the rule and the
  reason structural names are not rewritten in the image.
- **Cycle reports agree** between the depth and acyclicity sweeps (lowest node
  that could not be ordered).

## 1.2.2 — 2026-10-27

Second review pass over the 1.2.1 fixes. No wire-format change; the fixes make
redaction a true fixpoint and close the last copy path.

- **Redaction is a fixpoint for every secret.** The 1.2.1 rule only avoided
  injecting the marker when a *matching* secret was itself part of the marker; a
  second secret could still introduce it later, so a 1–3-byte secret such as `S`
  changed the text on every pass. The rule is now decided once per text: if any
  secret occurs inside `***SECRET***`, a text that needs redaction collapses to
  the marker. `interop::redact_text` and the canonicalizer share one
  implementation, and `SECRET_MARKER` has one definition.
- **Provenance keys are redacted.** `redact_provenance` rewrote values but not
  keys, so a copy embedded in a provenance key stayed in the string heap. Keys are
  now redacted like values, and entries that collapse onto the same key are
  deduplicated (provenance is a map), so the encoder cannot emit duplicate keys.
- **Projection value and key rules are consistent.** Value positions
  (`intents`, provenance producer/model/tool/text entries, Protobuf text fields)
  use the whole-value marker; key positions use occurrence replacement. The spec
  says the same, and `docs/spec/projection.md` now also states that structural
  names (field, binding, env, identifier names, media types) are *not* rewritten
  in the image — they are identity — while projections redact them and may merge
  two keys.
- **`InfinityModule::check_depth(0)` still checks cycles.** Zero means "no depth
  ceiling", not "skip validation"; a direct caller no longer gets `Ok` for a
  cyclic module.
- **Documentation matches the code.** `infinity/cycle` is documented as "a node
  on a cycle or depending on one" (the Kahn sweep reports the lowest such node),
  and the same wording appears in the error message.

## 1.2.1 — 2026-10-27

Independent review of the 1.2.0 candidate found eight issues; all are fixed here.
No wire-format change: every previously valid image stays valid, and every
previously canonical image stays canonical.

- **The Protobuf projection is canonical.** It is built from the canonical module
  (the decode of its own image), so logically equal modules — same AINF bytes and
  hash — project to identical bytes, and bindings, annotations and extensions come
  out in canonical order. Before, a table built with fields in a different order
  produced a different projection.
- **A projection cannot copy a secret through an opaque payload.** `to_protobuf`
  refuses an extension whose payload contains a secret literal instead of emitting
  it (`infinity/encode`, reason `extension payload carries secret material`).
- **Validation is linear in edges, not quadratic.** Acyclicity and depth use a
  Kahn topological sweep, with one child-list derivation per node; a wide table no
  longer turns validation quadratic.
- **Extension payloads must be packed.** Each payload now has to start exactly at
  `align8(previous end)` and the padding between payloads must be zero, so a
  directory cannot hide slack. New conformance vector `bad_extension_gap`.
- **One canonical proof.** `DecodeOpts::verify_canonical` now proves canonicality
  unconditionally, exactly like `validate_canonical` (which no longer encodes
  twice). An unflagged image fails the proof, because the canonical encoding of
  its content carries the flag.
- **One redaction rule.** `redact_text` (annotations, provenance, intents) no
  longer has a four-byte threshold, matching the projections: a one- or two-byte
  secret is replaced wherever it appears.
- **Taint follows references.** An interpolation whose expression is a `Ref` (or
  `Semantic` wrapper) around a secret redacts the whole string instead of
  rendering `"prefix ${}"`.
- **Tests and fuzzing cover the projections.** The independent Protobuf reader now
  checks ascending field numbers and minimal varints; new tests cover
  `i64::MIN`/`i64::MAX`, NaN, `-0.0`, empty text, canonical-envelope equality,
  secret-bearing extensions and short secrets; the decoder fuzz target exercises
  both projections and asserts the projection is deterministic.

CI also tests the locked graph with `--locked`, builds every target and feature on
the declared MSRV (1.85) with and without default features, verifies the package
tarball, and fuzzes on pushes as well as pull requests.

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
