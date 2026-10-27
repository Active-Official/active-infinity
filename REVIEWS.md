# Review record

Independent reviews and the disposition of every finding. Evidence transcripts
are stored with the release (not in the repository): `review-infinity-*.log`.

## Round 1 — 2026-10-27 (serve path: muse proxy, `muse-spark-1.3-contributor`)

The Copilot subscription path returned a monthly quota error; the review ran on
the Meta Muse proxy through the Copilot CLI (BYOK routing), which reads the
repository directly.

| Finding | Severity | Disposition |
|---|---|---|
| `StreamDecoder::finish` indexed past a partial frame | high | fixed in 1.1.1; regression `review_stream_finish_on_a_truncated_frame_does_not_panic` |
| Unbounded batch/delta accumulation in a stream | high | fixed in 1.1.1 (declared-size and `Limits` bounds); `review_stream_bounds_reject_unbounded_batches` |
| Depth ceiling measured from node 0 only | high | fixed in 1.1.1 (all roots); `review_depth_ceiling_applies_to_every_root` |
| `max_total_bytes` / `max_string_bytes` unenforced | high | fixed in 1.1.1; `review_limits_cover_total_bytes_and_string_heap` |
| Stream decoder ignored caller limits | high | fixed in 1.1.1 (`with_limits` threaded through) |
| Duplicate provenance keys could reach the wire | medium | fixed in 1.1.1 (provenance is a map); `review_provenance_is_a_map_and_reserved_kinds_are_refused` |
| Retired `PushNode` silently produced unreachable nodes | medium | removed in 1.1.1; tag 2 refused and documented |
| Reserved provenance kind 4 decoded as kind 3 | medium | fixed in 1.1.1 (refused) |
| Unbounded recursion in the JSON projection | medium | fixed in 1.1.1 (validation + depth guard); `review_json_projection_refuses_cycles_instead_of_recursing` |

## Round 2 — 2026-10-27 (same path)

Verification of round 1: all nine fixes confirmed present. One new finding:

| Finding | Severity | Disposition |
|---|---|---|
| Delta fragments decoded with default limits | high | fixed in 1.1.2; `review_delta_fragments_honor_the_stream_limits` |

## Round 3 — 2026-10-27 (same path)

Verification of rounds 1–2 plus a leak sweep. Confirmed (a) no validator/decode
mismatch, (b) no panic or unbounded recursion on untrusted bytes, (c) no secret
leak through the value projection. One new finding:

| Finding | Severity | Disposition |
|---|---|---|
| Projection did not redact table keys, unit names, env names, media types or provenance text | medium | fixed in 1.1.2; `review_projection_redacts_secret_copies_in_keys_and_metadata` |

Round 4 (final): no new findings.
