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

## Round 7 - 2026-10-27 (1.2.2)

Verification of round 6 found that two of the fixes were incomplete. Both are
fixed, with tests:

| Finding | Severity | Disposition |
|---|---|---|
| Redaction was order-dependent: a marker-substring secret (`S`) that did not occur in the original text was reintroduced by another secret's replacement, so the second pass changed the text again | high | fixed: the marker-substring case is decided once per text, before any replacement; `redaction_is_idempotent_when_a_secret_is_part_of_the_marker` covers three secret orders |
| `redact_provenance` rewrote values but not keys, so a copy in a provenance key stayed in the string heap | high | fixed: keys are redacted, and entries that collapse are deduplicated so no duplicate key reaches the encoder; `provenance_keys_do_not_carry_secret_copies` |
| `InfinityModule::check_depth(0)` skipped the cycle check for a direct caller | medium | fixed: zero disables the ceiling, not validation |
| Projection value/key rules disagreed (`intents`, `provenance_lines`, Protobuf text fields) | medium | fixed: value positions use the whole-value marker, key positions occurrence replacement; `docs/spec/projection.md` states both and documents structural names |
| Unchecked `redact_text`/`redacted_key` duplication and two `SECRET_MARKER` constants | low | fixed: one implementation in `canonical`, re-exported |
| Cycle semantics in `docs/spec/layout.md` described a bare "dependency cycle" | low | fixed: the table and the error message say the node is on a cycle or depends on one |

Verified unchanged: JSON projection output for secret-free modules, every
previously valid vector, and the stream layer.

## Round 8 — 2026-10-27 (1.2.3)

Verification of round 7 found three medium and two low items; all fixed in
1.2.4:

| Finding | Severity | Disposition |
|---|---|---|
| `intents()` used the projection rule while the image stores the occurrence form, so pre-encode and post-encode answers differed | medium | fixed: `intents()` uses the storage rule; the spec states both rules |
| `Ident` nodes used the data rule while every other name used the label rule | medium | fixed: labels by occurrence |
| `provenance_pairs` returned raw keys and values with no warning | medium | fixed: documented as a raw accessor |
| The property generator could not reach `SECRET` or a marker-containing secret | low | fixed: uppercase alphabet plus explicit edge cases |
| The spec did not say where a post-redaction provenance collision is reported | low | fixed: `layout.md` §9 |

## Round 9 — 2026-10-27 (1.2.4)

Verification round: **NO NEW FINDINGS**.

## Round 10 — 2026-10-27 (adversarial verification, 1.2.5)

An external adversarial pass over the released 1.2.4 found two issues the review
rounds had missed. Both are fixed in 1.2.5.

| Finding | Severity | Disposition |
|---|---|---|
| The extension check compared payloads against the *lossy text* form of each secret, so `SecretBytes::new(vec![0xff, 0xfe, 0x00])` copied into an extension was emitted instead of refused | high | fixed: `interop::secret_bytes` feeds the byte-level check; `projection_refuses_an_extension_that_copies_a_non_utf8_secret` covers a direct copy and an embedded one, and the exact probe was re-run against the published crate (refused, `infinity/encode`) |
| `cargo doc` accepted a rustdoc warning (ambiguous intra-doc link to `crate::validate`, both a module and a function), while the release criteria require warning-free docs | gap | fixed: the link targets `crate::validate::validate`; both repositories run `cargo doc` with `RUSTDOCFLAGS=-D warnings`, locally and in CI |

Lesson recorded: a byte-level surface needs the raw secret bytes, and documentation
warnings are defects that a gate must fail on rather than print.

## Round 11 — 2026-10-27 (verification of 1.2.5)

Verification round over the 1.2.5 diff: **NO NEW FINDINGS**. The reviewer
confirmed the raw-byte scan is panic-free for any secret length, runs on the
canonical module, that no other byte-level surface still uses the lossy text
form, that the regression test drives `to_protobuf` and asserts the exact code
for a direct and an embedded copy, and that `cargo doc` with
`RUSTDOCFLAGS=-D warnings` is clean.

## Round 12 — 2026-10-27 (re-run of the 1.2.5 verification)

The verification round was re-run after the session resumed. It confirmed the
raw-byte check, the doc gate, the absence of placeholder markers and the
conformance coverage, and found one low test-strength gap:

| Finding | Severity | Disposition |
|---|---|---|
| The embedded-copy case in `projection_refuses_an_extension_that_copies_a_non_utf8_secret` asserted only `is_err()`, while round 11 says it asserts the exact code | low | fixed in 1.2.6: both copies now assert `infinity/encode` and the reason |

Everything else was re-confirmed: `cargo fmt`, `clippy -D warnings`,
`cargo test` (both feature sets), `cargo doc` with `RUSTDOCFLAGS=-D warnings`,
and the clean-clone gate suites for both tags.

## Round 13 — 2026-10-27 (adversarial panel, 2.0.0)

The panel rejected the 1.2.6 candidate because three public helpers still returned
secret plaintext. The gap was real and had been missed by every earlier round
(rounds 10-12 fixed the *use* of secrets in one check but never asked whether the
accessors themselves should be public).

| Finding | Severity | Disposition |
|---|---|---|
| `interop::secret_texts` was public and returned every secret as plaintext | high | fixed in 2.0.0: `pub(crate)` |
| `interop::secret_bytes` was public and returned exact secret bytes | high | fixed in 2.0.0: `pub(crate)` |
| `interop::secret_literals` was public and re-exported from the JSON module | high | fixed in 2.0.0: `pub(crate)`, removed from the re-export |
| `tests/protobuf_tests.rs` drove the unlock API to assert the literal, so the test proved the leak existed rather than that the projection is safe | high | fixed: the test asserts the literal is absent from **both** the Protobuf bytes and the JSON document, and that the marker is present |
| No regression guard against reintroducing the accessors | gap | fixed: `tests/api_surface.rs` is a static policy check over `src/`, with an explicit forbidden list and an exception only for `SECRET_MARKER` |
| The removal was undocumented and unreleased | gap | fixed: ADR-0010, CHANGELOG 2.0.0, and a new signed release on crates.io and both organizations with regenerated gate logs |

The remaining public secret-related item is `SECRET_MARKER`, a literal string with
no secret material. The crate's own code, tests, examples and benches never needed
the accessors, which is evidence they were accidental rather than load-bearing.

## Round 14 — 2026-10-27 (verification of 2.0.0, 2.0.1)

Verification of the 2.0.0 removal found that one public accessor survived and
that the guard was too narrow. Both fixed in 2.0.1; 2.0.0 is yanked.

| Finding | Severity | Disposition |
|---|---|---|
| `Validated::secret` was `pub` and returned raw secret bytes from a validated image (its doc claimed crate-internal) | high | fixed: `pub(crate)`; the decoder is the only caller |
| The API-surface guard scanned a fixed file list that omitted `src/validate.rs` - the file with the leak - and missed `pub const fn`/`pub unsafe fn`/`pub async fn`, multi-line signatures and differently named accessors | medium | fixed: the guard walks all of `src/`, joins multi-line declarations, handles the modifiers, and adds a shape rule on the return type with a written allowlist |
| `View::provenance_entries` returned unredacted entries with no "raw" note | low | fixed: documented as a raw accessor; the stored form is already redacted |

The widened guard was probed adversarially: `pub fn secret_values` (blacklisted
name), `pub fn secret_names` (new name, raw return) and `pub fn secret_raw` as a
method on `Validated` each failed the suite, and each probe was reverted.

## Round 15 — 2026-10-27 (verification of 2.0.1, 2.0.2)

Verification of 2.0.1 confirmed the secret surface is closed (`Validated::secret`
and `SecretBytes::expose` are crate-only, projections and Debug/Display redact,
no doc or example tells a caller to read a secret) and found two low items, both
fixed in 2.0.2:

| Finding | Severity | Disposition |
|---|---|---|
| The shape rule used the last `)` of the whole line, so a one-line body (`pub fn secret_x() -> Vec<u8> { Vec::new() }`) hid its return type | low | fixed: the signature is cut at `{`/`;` before the return-type check; a probe with an inline body now fails the suite |
| ADR-0010 did not describe the shape rule, the allowlist, its staleness check or the obfuscation residual, and did not explain why `buf()`/`section()`/`encode()` are not leaks | low | fixed: the ADR now documents all of it, plus the "caller's own bytes" distinction |

The reviewer re-ran fmt, clippy `-D warnings`, tests in both feature sets,
`cargo doc` with `RUSTDOCFLAGS=-D warnings` and `cargo deny`; all clean.

## Round 16 — 2026-10-27 (verification of 2.0.2, 2.0.3)

The reviewer live-proved three ways past the API-surface guard. All are closed in
2.0.3, and each bypass is now a probe that fails the suite when injected.

| Finding | Severity | Disposition |
|---|---|---|
| `pub fn secret_x(x: [u8; 32]) -> Vec<u8>` passed: the scan split on `;`, cutting the parameter type and leaving the wrong tail | high | fixed: the return type is read only after the last `->`, so nothing in the parameter list can interfere |
| A return type on its own line (`pub fn secret_x(...)` then `-> Vec<u8>`) passed: the joiner split on balanced parentheses | high | fixed: the joiner continues while the next line starts with `->` or `where` |
| `pub const unsafe fn` passed: only one modifier was stripped | medium | fixed: `const`/`async`/`unsafe` are stripped in a loop, in any order; ADR-0010 updated |

Guard probes now cover: blacklisted name, new name with raw return, a method on
`Validated`, one-line body, array-length parameter, split return type, and
`const unsafe`. Each fails the suite; each probe is reverted.

## Round 17 — 2026-10-27 (verification of 2.0.3, 2.0.4)

The reviewer live-proved seven more ways past the *textual* guard. Rather than
patch a text scanner indefinitely, 2.0.4 adds a semantic gate over rustdoc JSON
as the authoritative check and keeps the text scan as a documented tripwire.

| Finding | Severity | Disposition |
|---|---|---|
| A public trait method (`fn secret_values(&self) -> Vec<u8>;`) evaded the text scan | high | the semantic gate walks trait items and catches it (probe proven) |
| `rfind("->")` ran before cutting the body, so `-> Vec<u8> { let g: fn() -> i32 = ...; }` and a `// -> i32` comment evaded | high | tripwire cuts the body and strips `where` before locating the arrow; the semantic gate is unaffected |
| A return type after a trailing `->` on the next line evaded | high | tripwire joins while the buffer ends with `->` |
| `pub extern "C" fn ... -> Vec<u8>` evaded | medium | tripwire strips `extern "..."` (semantic gate unaffected) |
| `&str` / `Box<str>` returns evaded the raw-type check | medium | both layers include `str` and `char` |
| A method inside `impl` and an attribute-prefixed `pub fn` evaded | low | tripwire strips attributes and looks for `pub fn` after them; methods were already covered by the semantic gate |
| `pub use ...::*` evaded the token check | low | both layers flag a glob re-export as unauditable |

Evidence: `guard-probe-matrix.log` (tripwire), `tripwire-probe.log` (six shapes),
`semantic-gate-probe.log` (free function), `semantic-gate-trait-probe.log` (trait
method and glob). Each probe fails the relevant gate and is reverted; the working
tree is clean afterwards.

## Round 18 — 2026-10-27 (verification of 2.0.4, 2.0.5)

The reviewer audited the semantic gate's blind spots (public fields, consts,
aliases, `doc(hidden)`, macros, traits, the allowlist, `SecretBytes`) and found
no active leak: `SecretBytes`'s field is private, `expose` is crate-only,
Debug/Display redact, equality is always false, and the only raw-byte fields are
the caller's own image, hashes, or redacted metadata. One hardening item:

| Finding | Severity | Disposition |
|---|---|---|
| `scripts/api_surface.py` did not resolve crate-local type aliases, so `pub type Bytes = Vec<u8>` plus `pub fn secret_x() -> Bytes` would have passed | low | fixed in 2.0.5: the resolver reads `inner.type_alias.type`; a probe that injects exactly that pair makes the gate fail, and is reverted |

No such alias existed in the crate at the time (only `Result<T>`), so the gap was
latent rather than exploitable.

## Round 19 — 2026-10-27 (final independent review of 2.0.5, 2.0.6)

The reviewer confirmed the panel's stale items against the tagged tree:
`secret_texts`, `secret_bytes`, `secret_table`, `secret_literals` and
`Validated::secret` are all `pub(crate)` in `v2.0.5`; the JSON re-export does not
name `secret_literals`; `SecretBytes::expose` is crate-only; and
`tests/protobuf_tests.rs` imports only `to_redacted_json`, `intents` and
`SECRET_MARKER`. Evidence: `secret-surface-audit.log`, captured from a clean
clone of the tag.

It then found six problems in the new policy machinery itself, all fixed in
2.0.6:

| Finding | Severity | Disposition |
|---|---|---|
| The semantic gate failed **open** on schema drift: no `format_version` check, `doc.get("index", {})` default, unknown `inner` kinds skipped, so a renamed key printed "clean" | high | fixed: pins `format_version == 61`, requires a non-empty index, the crate root, `inner`/`visibility` per item, and a minimum recognised-function count; four synthetic probes (wrong format, empty index, alias laundering, unresolvable alias) fail as expected |
| `pub use innocent as secret_x` passed: the shape rule used the target's name, not the public alias | medium | fixed: the alias name is checked, and an unresolvable target under a secret-named alias is refused |
| The allowlist could rot: only existence and reason length were checked, never the return | medium | fixed: `the_allowlisted_label_helper_never_returns_secret_material` builds a module with a secret copy in a binding name and proves the labels are redacted |
| ADR-0010 over-claimed (three helpers, "only SECRET_MARKER", aliased re-exports, textual-only residual) | medium | fixed: four helpers plus `Validated::secret`, the real public item list, alias/glob rules, schema-drift guards, scope limits and name-scoped residual risk |
| Documented scope gaps (assoc consts/types, public fields, enum variants, macros) | low | documented in ADR-0010; no such item exists today |
| Duplicate findings and an unpinned rustdoc invocation | low | fixed: findings are deduplicated, and the CI rustdoc step runs `--locked` |

The reviewer also re-ran fmt, clippy `-D warnings` (both feature sets), tests in
both configurations, `cargo doc` with `RUSTDOCFLAGS=-D warnings`, and `cargo deny`;
all clean.
