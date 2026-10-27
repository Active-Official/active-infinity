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
