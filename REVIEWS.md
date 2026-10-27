# Review record

Independent reviews and the disposition of every finding. Transcripts are kept
with the release evidence (`review-infinity-*.log`).

Serve path: the Copilot subscription returned a monthly quota error, so every
round ran through the Copilot CLI routed at the Meta Muse proxy
(`muse-spark-1.3-contributor`), which reads the repository directly.

## Round 1 — 2026-10-27

| Finding | Severity | Disposition |
|---|---|---|
| `StreamDecoder::finish` indexed past a partial frame | high | fixed in 1.1.1; `review_stream_finish_on_a_truncated_frame_does_not_panic` |
| Unbounded batch/delta accumulation in a stream | high | fixed in 1.1.1 (declared size + `Limits`); `review_stream_bounds_reject_unbounded_batches` |
| Depth ceiling measured from node 0 only | high | fixed in 1.1.1 (every root); `review_depth_ceiling_applies_to_every_root` |
| `max_total_bytes` / `max_string_bytes` unenforced | high | fixed in 1.1.1; `review_limits_cover_total_bytes_and_string_heap` |
| Stream decoder ignored caller limits | high | fixed in 1.1.1 (`with_limits`) |
| Duplicate provenance keys could reach the wire | medium | fixed in 1.1.1 (provenance is a map); `review_provenance_is_a_map_and_reserved_kinds_are_refused` |
| Retired `PushNode` produced unreachable nodes | medium | removed in 1.1.1; tag 2 refused |
| Reserved provenance kind 4 decoded as kind 3 | medium | fixed in 1.1.1 (refused) |
| Unbounded recursion in the JSON projection | medium | fixed in 1.1.1 (validation + depth guard); `review_json_projection_refuses_cycles_instead_of_recursing` |

## Round 2 — 2026-10-27

All nine fixes verified. One new finding:

| Finding | Severity | Disposition |
|---|---|---|
| Delta fragments decoded with default limits | high | fixed in 1.1.2; `review_delta_fragments_honor_the_stream_limits` |

## Round 3 — 2026-10-27

Confirmed (a) no validator/decode mismatch, (b) no panic or unbounded recursion on
untrusted bytes, (c) no leak through the value projection. One new finding:

| Finding | Severity | Disposition |
|---|---|---|
| Projection did not redact table keys, unit names, env names, media types or provenance text | medium | fixed in 1.1.2; `review_projection_redacts_secret_copies_in_keys_and_metadata` |

## Round 4 — 2026-10-27

Three new findings, all fixed in 1.1.3:

| Finding | Severity | Disposition |
|---|---|---|
| `Begin` size compared with default limits, not the caller's | medium | fixed; `review_stream_begin_uses_the_caller_limits` |
| `provenance_lines` emitted entry keys unredacted | low | fixed; `review_text_projections_redact_secret_copies` |
| `intents()` returned intent text unredacted | low | fixed; same test |

## Round 5 — 2026-10-27

Verification round: **NO NEW FINDINGS**.

## Round 6 - 2026-10-27 (1.2.0 release candidate)

Review of `v1.1.3..HEAD` through the Muse proxy. Eight findings, all fixed
before the release candidate was tagged:

| Finding | Severity | Disposition |
|---|---|---|
| Extension payloads were emitted verbatim by `to_protobuf`, so a secret copy inside an opaque payload could leave through the projection | high | fixed: `to_protobuf` refuses a payload containing a secret literal (`infinity/encode`); `projection_refuses_an_extension_that_copies_a_secret` |
| Protobuf bindings/annotations/extensions were emitted in insertion order, so logically equal modules projected to different bytes | high | fixed: the projection is built from the canonical module (decode of its own image); `projection_is_canonical_for_logically_equal_modules` |
| `check_acyclic` / `check_depth` re-derived a node's children once per edge — quadratic on wide tables | medium | fixed: Kahn topological sweep, O(V+E), one child-list derivation per node |
| Extension payloads could leave gaps (only an `align8` lower bound was checked) and the trailing-bytes comparison was derived from the payloads themselves | medium | fixed: payloads must start exactly at `align8(previous end)`, padding must be zero, and the end is compared with the packed end; new vector `bad_extension_gap`; `extension_payloads_must_be_packed` |
| `DecodeOpts::verify_canonical` only proved when the header declared canonical, while `validate_canonical` always proved (and encoded twice) | medium | fixed: the option proves unconditionally; `validate_canonical` is the same path with one encode; `canonical_proof_is_unconditional` |
| Redaction used a length threshold in `redact_text` but not in the projections, so 1–3-byte secret copies could survive canonicalization and appear in the image | medium | fixed: one unconditional rule in both places; `short_secrets_are_redacted_in_metadata_text` |
| Interpolation taint did not follow `Ref`/`Semantic`, so `${ref_to_secret}` laundered to `"prefix ${}"` | medium | fixed: `resolves_to_secret` follows wrappers and fails closed past the depth guard; `taint_follows_references_in_interpolations` |
| Test gaps: the wire reader did not check field order or minimal varints; no scalar extremes, no projection determinism across construction orders, no secret-in-extension case, projections never fuzzed | low | fixed: reader asserts ascending fields and minimal varints; new tests for `i64::MIN/MAX`, NaN, `-0.0`, empty text, canonical-envelope equality, and the fuzz target now exercises both projections |

Verified unchanged: JSON projection output, canonical bytes of every existing
vector, the decoder's totality, and the stream layer.
