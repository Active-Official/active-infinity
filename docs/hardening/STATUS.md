# Hardening status — active-infinity

Program: `ACTIVE-HARDENING-GUIDE-AND-CHECKLIST.md` v1.0.0, phases H0–H9 plus
Addendum A (research) and Addendum B (fix-and-test loop).

This file is the public status surface required by H0.6 and H9.3. The matrix at
the bottom is generated from `docs/hardening/invariant-map.toml` by
`scripts/hardening_status.py`; editing the matrix by hand is a check failure.

## Baseline

| Field | Value |
|---|---|
| Crate | `active-infinity` 2.0.7 |
| Baseline commit | `9b44242496568e2338c5e98b90e558d4b0999f4e` |
| Baseline tag | `hardening-baseline` (annotated, SSH-signed) |
| Released tag | `v2.0.7` on `8e83550075d35a6e1d564b61bc788d8177946e3e` |
| MSRV | 1.85 |
| Wire format | AINF 1.0 |

## H0 findings

### H0.1 Test inventory

94 test functions across 8 integration-test binaries, plus the doctest suite:

| Suite | Tests | What it proves |
|---|---|---|
| `tests/unit_tests.rs` | 28 | round-trip, every node kind, canonical identity, stream reassembly, redaction (including Debug metadata), validator classes, extension rules |
| `tests/integration_tests.rs` | 8 | real modules through `active-core`, hash stability, evaluation/why/impact, fail-closed malformed input |
| `tests/property_tests.rs` | 8 | arbitrary bytes, byte flips, canonical fixpoint, redaction fixpoint, generator sanity |
| `tests/conformance_tests.rs` | 6 | 49 committed vectors, declared codes, index agreement, spec agreement |
| `tests/redteam_tests.rs` | 22 | count bombs, overlap, forged graphs, string faults, deep/wide limits, secret export, anti-oracle, stream splicing, plus nine review regressions |
| `tests/protobuf_tests.rs` | 13 | independent reader, determinism, secret refusal, extension refusal, scalar extremes, taint through interpolation |
| `tests/api_surface.rs` | 4 | no public plaintext secret accessor; allowlist is argued and behaviorally tested |
| `tests/doc_gate.rs` | 5 | spec sections, constants, error-code catalog, README guarantees, ADR index |

The machine-readable invariant-to-test mapping is
`docs/hardening/invariant-map.toml`. Every row resolves to a `#[test]` that the
validator parses out of the named file.

Invariants discovered in code comments and tests during the audit (now mapped):

- `ir.rs::validate_structure`: every referenced node exists, table fields and
  bindings are unique, the graph is acyclic, and depth stays within budget
  (mapped to I-10 and I-8).
- `ir.rs::SecretBytes`: no `Display`, `Debug`, `Serialize`, equality or ordering
  path (mapped to I-2 and I-3).
- `decode.rs`: a buffer is never trusted before validation; views borrow only
  validated bytes (I-10).
- `canonical.rs`: a tainted blob carries no payload, and free-text metadata must
  not carry secret copies (I-1, I-3).
- `interop.rs`: a cyclic hand-built module must not hang a query (I-10).

Benchmarks: `benches/codec.rs` (111 lines, criterion) measures encode, decode,
validate and view across module sizes. It is a benchmark, not a gate; no
checked-in numbers exist yet (H4.2, H4.5).

### H0.2 Fuzz, corpus and coverage

- Eight targets cover validate/decode/encode/view, stream reassembly, canonical
  round-trips, section layout, graph cycles, secret positions, unit
  discriminants and projection agreement. Each asserts a semantic invariant.
- Conformance corpus: 49 `.ainf` images, 46,673 bytes. Fuzz corpora are
  **committed** under `fuzz/corpus/<target>/` (all targets, 94 seeds total) and
  are documented in `docs/hardening/CORPUS.md`.
- Coverage (all features, Windows x86_64): 73.44% regions, 71.66% lines,
  75.00% functions. Full table in `docs/hardening/CORPUS.md`.
- Weakest surfaces: `view.rs` 12.37% regions, `unit.rs` 50.51% lines,
  `ir.rs` 58.79% lines, `stream.rs` 63.13% lines.

### H0.3 Documentation inventory

- 10 ADRs (0001–0010) plus index: purpose, active-core relationship, versioning,
  zero-copy, canonical form, secrets, streaming, dependency policy, Protobuf
  projection, no public secret accessor.
- Specs: `layout.md`, `streaming.md`, `security.md`, `projection.md`,
  `performance.md`.
- `SECURITY.md` (scope, reporting, hardening expectations), `REVIEWS.md`
  (rounds 1–21, final round NO NEW FINDINGS), `CHANGELOG.md`,
  `docs/release-signing.md`.

### H0.4 Supply chain and release

- Dual license MIT OR Apache-2.0, both license files present.
- MSRV 1.85 verified by the CI `msrv` job.
- `cargo audit`: pass; one allowed unmaintained warning (`unsafe-libyaml`,
  RUSTSEC-2024-0449, via `active-core` → `serde_yaml`, not in the parsing path;
  ADR-0008).
- `cargo deny check`: advisories, bans, licenses, sources all ok. One
  `license-not-encountered` warning for the unused `ISC` allowance.
- Tags are SSH-signed with the key in `release-signing.allowed_signers`;
  `v2.0.7` verifies.
- crates.io 2.0.7 is published and not yanked.
- Tags are identical on `Active-Official` and `RatioArtificiosa` (same tag
  object, same commit).

### H0.5 Baseline tag

`hardening-baseline` is an annotated, SSH-signed tag at the baseline commit.
It exists so later phases can diff behavior and evidence against a fixed point.

### H0.6 This file

The matrix below is validated in CI by `scripts/hardening_status.py --check`.
A missing test, a stale row, or a critical invariant without a negative-control
plan fails the check.

## Negative controls

`scripts/negative_controls.py` creates a throwaway git worktree at HEAD, proves
the mapped check passes unmutated, applies one precise source mutation, and
requires the check to fail with that test in the failure list. A compile error
or a different test failing is rejected as a false positive. The worktree is
removed afterwards; the working tree is never modified.

| Control | Invariant | Mutation | Check that must fail |
|---|---|---|---|
| `I-3-redaction` | I-3 | canonical redactor returns its input | `the_allowlisted_label_helper_never_returns_secret_material` |
| `I-3-debug` | I-3 | canonical redactor returns its input | `debug_redacts_secret_copies_in_metadata` |
| `I-8-depth` | I-8 | depth ceiling never fires | `threat_deep_and_wide_modules_hit_limits_not_the_stack` |
| `I-9-canonical` | I-9 | canonical proof stops comparing the re-encode | `canonical_proof_is_unconditional` |
| `I-10-trailing` | I-10 | both trailing-byte guards removed | `invalid_vectors_are_rejected_with_their_declared_code` |

Run: `python scripts/negative_controls.py --check`. CI job `negative-controls`.

## Gate results (baseline)

| Gate | Result | Evidence |
|---|---|---|
| `cargo fmt --all -- --check` | pass | local run 2026-10-27 |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | pass | local run 2026-10-27 |
| `cargo clippy --locked --all-targets --no-default-features -- -D warnings` | pass | local run 2026-10-27 |
| `cargo test --locked --all-features` | pass (93 tests) | local run + CI |
| `cargo test --locked --no-default-features` | pass | local run + CI |
| `cargo doc` with `RUSTDOCFLAGS=-D warnings` | pass | local run 2026-10-27 |
| `cargo package --locked` | pass | local run 2026-10-27 |
| `cargo audit` | pass (1 allowed warning) | local run 2026-10-27 |
| `cargo deny check` | pass | local run 2026-10-27 |
| API-surface gate | pass | CI run 40573778580 |
| Fuzz campaigns (8 targets, 20k runs) | pass | Docker run 2026-10-27; CI job `fuzz` runs 2k per target |
| Negative controls (5) | pass | local run 2026-10-27; CI job `negative-controls` |
| GitHub Actions on `9b44242` | success | run 40573778580 |

## Ordered next steps

1. **H1** The eight targets, committed corpora and the Docker lane are in
   place. Remaining: a 32-bit build/test lane, a differential encoder, and a
   longer nightly campaign.
2. **H2** Turn the red-team suite into table-driven cases over the real entry
   points, one row per attack class. The scripted negative controls are in
   place; the remaining work is breadth and the research-derived cases.
3. **H4** Record the benchmark matrix and add hostile-input DoS measurements.
4. **H5–H8** Ecosystem docs, supply-chain automation, observability rules,
   compatibility policy.
5. **H9** Wire every suite into CI plus a clean-clone gate script, and start the
   continuous fuzz lane.

## Residual risks (baseline)

- **Secret length is visible.** `SecretBytes::len` is public and is used by
  budgets. Content is not compared and never exported; length is not hidden.
  Accepted for the current threat model.
- **Name-scoped API gate.** The semantic gate refuses public functions whose
  names or resolved return types look secret-bearing; a future public function
  with an innocent name that returns secret bytes through a new type would not
  be caught by name alone. The tripwire and ADR-0010 record the limit.
- **No 32-bit lane.** All current evidence is 64-bit.
- **Corpus is a seed set, not a long campaign.** The committed corpora start
  each target from real structure; sustained fuzzing is still a nightly duty.
- **No independent encoder.** The canonical fixpoint is checked against the
  same implementation, not a second one written from the spec (H1.23).
- **`unsafe-libyaml` advisory.** Accepted, unreachable from the parsing path.
- **Dependency resolution at publish time.** The library allows semver-compatible
  patch updates of `blake3` and `thiserror`, so a consumer may resolve a build
  that this repository did not test. The CI lockfile is the tested graph.
- **Coverage of `view.rs`.** The public zero-copy surface is under-tested at the
  unit level.

## Maturity sign-off

Not signed. H0 and the main H1 surface are complete; the 32-bit and differential
extensions, H2–H9 remain. The sign-off block from Appendix C
will be filled only when every row below is `done` or an ADR accepts the risk.

<!-- BEGIN GENERATED: hardening matrix (scripts/hardening_status.py) -->

**Repository:** `active-infinity` **version:** `2.0.7` **baseline commit:** `9b44242496568e2338c5e98b90e558d4b0999f4e` **baseline tag:** `hardening-baseline` **measured:** 2026-10-27

Invariants: 6 covered, 1 partial, 0 gap, 5 not applicable. Checklist items: 23 done, 53 partial, 31 gap, 53 not applicable. Criticals with an implemented negative control: 4/4. Distinct automated checks resolved: 90.

| Invariant | Meaning | Status | Checks | Negative control |
|---|---|---|---|---|
| **I-1** | Structural secret taint | `covered` | 10 | - |
| **I-2** | Anti-oracle equality | `covered` | 2 | - |
| **I-3** | Secret non-leakage | `covered` | 18 | implemented |
| **I-4** | Capability unforgeability | `n/a` | 0 | - |
| **I-5** | Attenuation only narrows | `n/a` | 0 | - |
| **I-6** | Revocation at dispatch | `n/a` | 0 | - |
| **I-7** | Drop notification | `n/a` | 0 | - |
| **I-8** | Hard budgets | `covered` | 10 | implemented |
| **I-9** | Deterministic canonicalization | `covered` | 11 | implemented |
| **I-10** | Fail-closed validation | `covered` | 15 | implemented |
| **I-11** | No ambient authority | `n/a` | 0 | - |
| **I-12** | Domain operations under capability and budget | `partial` | 2 | - |

| Item | Checklist item | Status | Evidence |
|---|---|---|---|
| **H0.1** | Inventory all existing tests as an invariant-to-test matrix | `done` | `script:scripts/hardening_status.py` |
| **H0.2** | Inventory fuzz targets, corpus sizes and coverage snapshots | `done` | `doc:docs/hardening/CORPUS.md`, `fuzz:fuzz_decode_infinity` |
| **H0.3** | Inventory ADRs, SECURITY, REVIEWS, security and performance specs | `done` | `doc:docs/hardening/STATUS.md` |
| **H0.4** | Confirm license, MSRV, advisories, signing and publish status | `done` | `gate:audit`, `gate:deny` |
| **H0.5** | Tag a hardening baseline | `done` | `gate:baseline-tag` |
| **H0.6** | Create docs/hardening/STATUS.md | `done` | `script:scripts/hardening_status.py` |
| **H1.1** | fuzz_decode_infinity: full validate and view path | `partial` | `fuzz:fuzz_decode_infinity` |
| **H1.2** | fuzz_stream_reassembly: hostile frame sequences | `done` | `fuzz:fuzz_stream_reassembly` |
| **H1.3** | fuzz_canonical_roundtrip: mutate/encode/decode hash stability | `done` | `fuzz:fuzz_canonical_roundtrip` |
| **H1.4** | fuzz_layout_sections: overlap, offsets, sizes, duplicate tags | `done` | `fuzz:fuzz_layout_sections` |
| **H1.5** | fuzz_graph_cycles: every cycle shape surfaces as a cycle error | `done` | `fuzz:fuzz_graph_cycles` |
| **H1.6** | fuzz_secret_positions: no leak from any export path | `done` | `fuzz:fuzz_secret_positions` |
| **H1.7** | fuzz_unit_discriminants: unknown and boundary units | `done` | `fuzz:fuzz_unit_discriminants` |
| **H1.8** | fuzz_projection_agreement: JSON vs Protobuf redaction and hash | `done` | `fuzz:fuzz_projection_agreement` |
| **H1.9** | fuzz_arp1_frame | `n/a` | - |
| **H1.10** | fuzz_capability_lifecycle | `n/a` | - |
| **H1.11** | fuzz_promise_graph | `n/a` | - |
| **H1.12** | fuzz_budget_matrix | `n/a` | - |
| **H1.13** | fuzz_tool_mcp | `n/a` | - |
| **H1.14** | fuzz_tool_http | `n/a` | - |
| **H1.15** | fuzz_tool_process | `n/a` | - |
| **H1.16** | fuzz_channel_cap_transfer | `n/a` | - |
| **H1.17** | fuzz_transport_framing | `n/a` | - |
| **H1.18** | Seed corpus = vectors, examples, almost-valid images; document classes | `done` | `doc:docs/hardening/CORPUS.md` |
| **H1.19** | Every fixed bug adds a minimized seed | `done` | `doc:docs/hardening/CORPUS.md` |
| **H1.20** | CI fuzz budget on PRs, longer on main/nightly, fail on regression | `partial` | `fuzz:fuzz_decode_infinity` |
| **H1.21** | Optional public sanitized corpus | `gap` | - |
| **H1.22** | 32-bit target build and test lane (research: CVE-2026-116734, CVE-2021-32629) | `gap` | - |
| **H1.23** | Differential canonicalization oracle from an independent encoder | `gap` | - |
| **H1.24** | fuzz_tool_policy | `n/a` | - |
| **H2.0** | Scripted negative controls prove each security-critical check fails on a broken build | `done` | `gate:negative-controls` |
| **H2.1** | Integer overflow and underflow in length and offset arithmetic | `partial` | `test:tests/redteam_tests.rs::threat_count_bombs_in_every_section`, `test:tests/redteam_tests.rs::threat_offset_and_overlap_attacks` |
| **H2.2** | Overlapping and out-of-bounds sections | `partial` | `test:tests/redteam_tests.rs::threat_offset_and_overlap_attacks` |
| **H2.3** | Deep nesting aimed at stack overflow | `partial` | `test:tests/redteam_tests.rs::threat_deep_and_wide_modules_hit_limits_not_the_stack` |
| **H2.4** | Billion-laughs expansion via references or repeated subgraphs | `gap` | - |
| **H2.5** | Huge sparse claims with tiny actual buffers | `partial` | `test:tests/redteam_tests.rs::threat_size_limits_are_enforced_without_allocation`, `test:tests/redteam_tests.rs::threat_count_bombs_in_every_section` |
| **H2.6** | Invalid UTF-8, overlong encodings, surrogate nonsense | `partial` | `test:tests/redteam_tests.rs::threat_string_heap_faults` |
| **H2.7** | Streaming slowloris and oversize total declarations | `partial` | `test:tests/redteam_tests.rs::review_stream_bounds_reject_unbounded_batches`, `test:tests/redteam_tests.rs::review_stream_begin_uses_the_caller_limits`, `test:tests/redteam_tests.rs::review_delta_fragments_honor_the_stream_limits` |
| **H2.8** | Forge capability IDs | `n/a` | - |
| **H2.9** | Attenuate then widen | `n/a` | - |
| **H2.10** | Use after revoke or drop; borrowed channel lifetime | `n/a` | - |
| **H2.11** | Confused deputy provider | `n/a` | - |
| **H2.12** | Tool adapter confused deputy | `n/a` | - |
| **H2.13** | Revocation racing with dispatch | `n/a` | - |
| **H2.14** | Secrets in every legal position; scan all export paths | `partial` | `test:tests/redteam_tests.rs::threat_secret_never_reaches_any_export_surface`, `test:tests/protobuf_tests.rs::taint_follows_references_in_interpolations` |
| **H2.15** | Force secrets into error messages | `partial` | `test:tests/redteam_tests.rs::threat_secret_never_reaches_any_export_surface` |
| **H2.16** | Equality and ordering oracle attempts | `partial` | `test:tests/redteam_tests.rs::threat_anti_oracle_equality` |
| **H2.17** | Smuggle secrets via extensions, annotations, provenance, projections | `partial` | `test:tests/redteam_tests.rs::review_projection_redacts_secret_copies_in_keys_and_metadata`, `test:tests/protobuf_tests.rs::projection_refuses_an_extension_that_copies_a_secret` |
| **H2.18** | Logging and metrics carry no secrets or raw capability bits | `n/a` | - |
| **H2.19** | Queue storms under a low call budget | `n/a` | - |
| **H2.20** | Nested value byte bombs under a low byte budget | `partial` | `test:tests/redteam_tests.rs::threat_deep_and_wide_modules_hit_limits_not_the_stack` |
| **H2.21** | Many lanes, channels and promises to finite limits | `n/a` | - |
| **H2.22** | Enormous tool payloads and tools that never return | `n/a` | - |
| **H2.23** | Zero or near-zero ceilings refused where policy needs finite limits | `n/a` | - |
| **H2.24** | Single-bit mutation fails validation or changes the hash | `partial` | `test:tests/property_tests.rs::byte_flips_are_always_rejected` |
| **H2.25** | Large-corpus hash collision search | `gap` | - |
| **H2.26** | Pipelined vs sequential preserves the authorization side-effect set | `n/a` | - |
| **H2.27** | Projection hash and redaction agreement under adversarial valid modules | `partial` | `test:tests/protobuf_tests.rs::projection_is_canonical_for_logically_equal_modules`, `test:tests/protobuf_tests.rs::projection_never_contains_secret_material` |
| **H2.28** | Overlapping write capabilities detected or prevented | `n/a` | - |
| **H2.29** | Audit-only capability cannot write | `n/a` | - |
| **H2.30** | Stale capability after ownership change refused | `n/a` | - |
| **H2.31** | Another worker's secret-bearing subgraph denied or fully redacted | `n/a` | - |
| **H2.32** | Public errors do not enable secret or capability oracles | `partial` | `test:tests/unit_tests.rs::error_codes_are_stable_and_documented`, `test:tests/redteam_tests.rs::threat_anti_oracle_equality` |
| **H2.33** | No debug unlock or test ambient authority in release builds | `gap` | - |
| **H2.34** | Fuzz corpus treated as permanently hostile input | `gap` | - |
| **H2.35** | Docs and examples do not teach insecure patterns without warnings | `partial` | `doc:README.md`, `doc:SECURITY.md` |
| **H2.36** | Allocation ceiling for untrusted counts, not only an error code | `partial` | `test:tests/redteam_tests.rs::threat_size_limits_are_enforced_without_allocation`, `test:tests/redteam_tests.rs::threat_count_bombs_in_every_section` |
| **H2.37** | Span arithmetic checked on 32-bit and 64-bit widths | `gap` | - |
| **H2.38** | String and blob lengths that end exactly at EOF | `gap` | - |
| **H2.39** | Extension skip and duplicate-tag arithmetic | `partial` | `test:tests/unit_tests.rs::duplicate_extension_tags_are_refused`, `test:tests/unit_tests.rs::extension_blocks_round_trip_and_are_order_independent` |
| **H2.40** | Abort-free lane under panic=abort | `gap` | - |
| **H2.41** | Validation time is linear in image size | `gap` | - |
| **H2.42** | Cross-kernel and cross-connection capability transplant | `n/a` | - |
| **H2.43** | Event and log redaction oracle | `n/a` | - |
| **H2.44** | Tool timeout and payload ceiling | `n/a` | - |
| **H2.45** | Shared-memory frame TOCTOU | `n/a` | - |
| **H2.46** | URL and path allow-list canonicalization bypass | `n/a` | - |
| **H2.47** | Promise settlement count under concurrent cancel and resolve | `n/a` | - |
| **H3.1** | Freeze a review scope document | `gap` | - |
| **H3.2** | Independent review with recorded findings | `partial` | `doc:REVIEWS.md` |
| **H3.3** | Triage findings; critical and high fixed before maturity | `partial` | `doc:REVIEWS.md` |
| **H3.4** | Re-test after fixes with evidence | `partial` | `doc:REVIEWS.md` |
| **H3.5** | Schedule delta reviews after model or wire changes | `gap` | - |
| **H3.6** | Annual revisit in maintenance | `gap` | - |
| **H4.1** | Checked-in benchmark matrix | `partial` | `script:benches/codec.rs` |
| **H4.2** | Throughput and p50/p99 for encode, decode, validate, hash, projection | `gap` | - |
| **H4.3** | RPC call latency, pipelining, concurrency | `n/a` | - |
| **H4.4** | Sustained load tests with RSS, allocations, FDs, threads | `gap` | - |
| **H4.5** | CI regression gates on the benchmark matrix | `gap` | - |
| **H4.6** | Publish docs/performance.md with methodology and numbers | `partial` | `doc:docs/spec/performance.md` |
| **H4.7** | Explicit DoS scenarios prove budgets cap CPU and memory | `partial` | `test:tests/redteam_tests.rs::threat_size_limits_are_enforced_without_allocation`, `test:tests/redteam_tests.rs::threat_deep_and_wide_modules_hit_limits_not_the_stack` |
| **H4.8** | RSS stability over repeated validation cycles | `gap` | - |
| **H4.9** | FD and thread stability under connection churn | `n/a` | - |
| **H5.1** | Runnable examples for round-trip, queries, streaming | `partial` | `doc:README.md` |
| **H5.2** | Migration from JSON/YAML guide | `gap` | - |
| **H5.3** | Why not only Cap'n Proto, FlatBuffers or gRPC comparison | `gap` | - |
| **H5.4** | Stable machine-readable error code catalog | `partial` | `test:tests/conformance_tests.rs::every_declared_failure_code_has_a_vector`, `test:tests/unit_tests.rs::error_codes_are_stable_and_documented` |
| **H5.5** | Explicit what-is-safe-to-log rules | `partial` | `doc:docs/spec/security.md` |
| **H5.6** | Misuse documentation | `partial` | `doc:SECURITY.md` |
| **H5.7** | Optional active-habitat demo | `n/a` | - |
| **H6.1** | SBOM on every release | `partial` | `doc:docs/release-signing.md` |
| **H6.2** | cargo deny and advisory audit strict in CI | `done` | `gate:audit`, `gate:deny` |
| **H6.3** | Reproducible builds where feasible, limits documented | `gap` | - |
| **H6.4** | Signed tags with allowed_signers enforced | `partial` | `script:release-signing.allowed_signers` |
| **H6.5** | Dual publish checklist mechanical and reviewed | `partial` | `doc:docs/release-signing.md` |
| **H6.6** | Yank and advisory process exercised in a dry run | `gap` | - |
| **H6.7** | Property tests for attenuation monotonicity | `n/a` | - |
| **H6.8** | Bounded or exhaustive capability lifecycle model | `n/a` | - |
| **H6.9** | Public statement of tested vs fuzzed vs reviewed vs proven | `partial` | `doc:SECURITY.md` |
| **H6.10** | Exhaustive small-state capability lifecycle model | `n/a` | - |
| **H7.1** | Structured events for call, settle, revoke, budget, refusal | `n/a` | - |
| **H7.2** | Default logs carry no secrets or raw capability bits | `n/a` | - |
| **H7.3** | Metrics without sensitive payloads | `n/a` | - |
| **H7.4** | Tests that force sensitive data into events fail CI | `n/a` | - |
| **H8.1** | Written wire and format compatibility policy | `partial` | `doc:docs/spec/layout.md` |
| **H8.2** | Old Infinity images still validate | `partial` | `test:tests/conformance_tests.rs::valid_vectors_validate_and_reencode_identically` |
| **H8.3** | Unknown flags and extensions behavior specified and tested | `partial` | `test:tests/unit_tests.rs::duplicate_extension_tags_are_refused`, `test:tests/unit_tests.rs::extension_blocks_round_trip_and_are_order_independent` |
| **H8.4** | Versioned public conformance suite | `partial` | `test:tests/conformance_tests.rs::the_index_and_the_vector_files_agree` |
| **H8.5** | Deprecation windows for shipped behavior | `gap` | - |
| **H9.1** | Nightly continuous fuzz with growing corpus | `partial` | `gate:fuzz` |
| **H9.2** | Periodic independent review cadence on the calendar | `partial` | `doc:REVIEWS.md` |
| **H9.3** | Public status section: performance, security posture, residual risks | `gap` | - |
| **H9.4** | Hardening checklist reviewed every release; new classes added | `gap` | - |
| **H9.5** | Maturity claim only after H0-H8 complete and H9 sustained | `gap` | - |
| **R-0** | Research sprint before each phase | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **R-1** | Research sibling components after every critical fix | `partial` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **R-2** | Full multi-domain pass once per release cycle | `partial` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **R-3** | Log every finding in RESEARCH-LOG.md | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **R-4** | Every finding becomes a test, item, ADR or n/a note | `partial` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D1.1** | At least 15 historical parser bugs with identifiers | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D1.2** | Map each historical bug to layout, validate, stream or wire decode | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D1.3** | Add a test or fuzz oracle per mapped class | `partial` | `fuzz:fuzz_decode_infinity` |
| **D1.4** | Differential parsing and whether a second checker is warranted | `gap` | - |
| **D2.1** | At least 10 capability or RPC authz failure patterns | `n/a` | - |
| **D2.2** | Map authz patterns to kernel, cap, channel, tool, transport | `n/a` | - |
| **D2.3** | Monotonicity, revoke-at-dispatch and confused-deputy tests | `n/a` | - |
| **D2.4** | Rights amplification and caretaker patterns | `n/a` | - |
| **D3.1** | Enumerate every export path | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D3.2** | Attempt redaction bypass techniques in tests | `partial` | `test:tests/redteam_tests.rs::review_projection_redacts_secret_copies_in_keys_and_metadata`, `test:tests/protobuf_tests.rs::projection_refuses_an_extension_that_copies_a_non_utf8_secret` |
| **D3.3** | Anti-oracle equality in debug and optimized builds | `partial` | `test:tests/unit_tests.rs::secret_equality_is_always_false` |
| **D3.4** | Stable error codes do not branch on secret-dependent data | `gap` | - |
| **D4.1** | Compare fuzz targets to structure-aware state of the art | `partial` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D4.2** | Semantic oracles, not only crash oracles | `partial` | `fuzz:fuzz_decode_infinity` |
| **D4.3** | Directed seeds for cold paths | `gap` | - |
| **D4.4** | Corpus growth and minimize-and-commit policy | `partial` | `doc:docs/hardening/CORPUS.md` |
| **D5.1** | Map classic DoS classes to budget dimensions | `partial` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D5.2** | Prove hostile input hits budget before host OOM | `partial` | `test:tests/redteam_tests.rs::threat_size_limits_are_enforced_without_allocation` |
| **D5.3** | Compression bombs at transport edges | `n/a` | - |
| **D6.1** | Escape catalog for HTTP, process and MCP tools | `n/a` | - |
| **D6.2** | Automate escape attempts as red-team tests | `n/a` | - |
| **D6.3** | Runtime sandbox escape claims | `n/a` | - |
| **D7.1** | Audit dependencies for unnecessary privilege | `partial` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D7.2** | cargo deny and advisories gate merges | `done` | `gate:audit`, `gate:deny` |
| **D7.3** | Document residual non-reproducibility sources | `partial` | `doc:docs/release-signing.md` |
| **D8.1** | Capability patterns for writer, auditor, orchestrator | `n/a` | - |
| **D8.2** | Overlapping, stale and exfiltration grants | `n/a` | - |
| **D8.3** | Import applicable multi-agent security tests | `n/a` | - |
| **D9.1** | Secret- or capability-dependent timing in hot paths | `gap` | - |
| **D9.2** | Docs do not reveal privileged test-only behavior | `partial` | `doc:docs/spec/security.md` |
| **D9.3** | Standing question: what would an infinite-input agent try next | `gap` | - |

### Check index

<details><summary><strong>I-1</strong> (10 checks)</summary>

- `test:tests/unit_tests.rs::every_node_kind_round_trips`
- `test:tests/unit_tests.rs::secrets_never_leak_through_debug_or_exports`
- `test:tests/unit_tests.rs::debug_redacts_secret_copies_in_metadata`
- `script:scripts/negative_controls.py#I-3-debug`
- `test:tests/protobuf_tests.rs::taint_follows_references_in_interpolations`
- `test:tests/property_tests.rs::redaction_is_a_fixpoint_for_arbitrary_secrets_and_texts`
- `test:tests/redteam_tests.rs::threat_secret_never_reaches_any_export_surface`
- `test:tests/redteam_tests.rs::review_projection_redacts_secret_copies_in_keys_and_metadata`
- `test:tests/redteam_tests.rs::review_text_projections_redact_secret_copies`
- `fuzz:fuzz_decode_infinity` — fuzz/fuzz_targets/fuzz_decode_infinity.rs

</details>

<details><summary><strong>I-2</strong> (2 checks)</summary>

- `test:tests/unit_tests.rs::secret_equality_is_always_false`
- `test:tests/redteam_tests.rs::threat_anti_oracle_equality`

</details>

<details><summary><strong>I-3</strong> (18 checks)</summary>

- `test:tests/api_surface.rs::the_crate_exposes_no_plaintext_secret_accessor`
- `test:tests/api_surface.rs::the_redaction_marker_is_the_only_public_secret_constant`
- `test:tests/api_surface.rs::the_allowlist_entries_still_exist_and_are_argued`
- `test:tests/api_surface.rs::the_allowlisted_label_helper_never_returns_secret_material`
- `gate:api-surface` — cargo +nightly rustdoc --locked --lib --all-features -- -Zunstable-options --output-format json && python scripts/api_surface.py target/doc/active_infinity.json
- `test:tests/unit_tests.rs::secrets_never_leak_through_debug_or_exports`
- `test:tests/unit_tests.rs::debug_redacts_secret_copies_in_metadata`
- `script:scripts/negative_controls.py#I-3-debug`
- `test:tests/unit_tests.rs::provenance_keys_do_not_carry_secret_copies`
- `test:tests/unit_tests.rs::value_paths_do_not_carry_secret_copies`
- `test:tests/protobuf_tests.rs::projection_never_contains_secret_material`
- `test:tests/protobuf_tests.rs::short_secrets_are_redacted_in_metadata_text`
- `test:tests/protobuf_tests.rs::projection_refuses_an_extension_that_copies_a_secret`
- `test:tests/protobuf_tests.rs::projection_refuses_an_extension_that_copies_a_non_utf8_secret`
- `test:tests/redteam_tests.rs::threat_secret_never_reaches_any_export_surface`
- `test:tests/redteam_tests.rs::review_projection_redacts_secret_copies_in_keys_and_metadata`
- `test:tests/redteam_tests.rs::review_text_projections_redact_secret_copies`
- `fuzz:fuzz_decode_infinity` — fuzz/fuzz_targets/fuzz_decode_infinity.rs

Negative control (implemented): Make canonical::redact_text return its input unchanged (identity) and run the allowlist, projection and Debug tests → expected: the_allowlisted_label_helper_never_returns_secret_material and projection_never_contains_secret_material must fail with the leaked literal named in the assertion

</details>

<details><summary><strong>I-8</strong> (10 checks)</summary>

- `test:tests/redteam_tests.rs::threat_count_bombs_in_every_section`
- `test:tests/redteam_tests.rs::threat_deep_and_wide_modules_hit_limits_not_the_stack`
- `test:tests/redteam_tests.rs::threat_size_limits_are_enforced_without_allocation`
- `test:tests/redteam_tests.rs::review_stream_bounds_reject_unbounded_batches`
- `test:tests/redteam_tests.rs::review_limits_cover_total_bytes_and_string_heap`
- `test:tests/redteam_tests.rs::review_stream_begin_uses_the_caller_limits`
- `test:tests/redteam_tests.rs::review_delta_fragments_honor_the_stream_limits`
- `vector:tests/vectors/invalid/limit.ainf`
- `vector:tests/vectors/invalid/count_bomb.ainf`
- `vector:tests/vectors/invalid/too_deep.ainf`

Negative control (implemented): Raise Limits::default().max_nodes by 1 and run threat_deep_and_wide_modules_hit_limits_not_the_stack; then set max_total_bytes to usize::MAX and run review_limits_cover_total_bytes_and_string_heap → expected: each test must fail because the budget no longer fires before the allocation or traversal

</details>

<details><summary><strong>I-9</strong> (11 checks)</summary>

- `test:tests/unit_tests.rs::canonical_identity_is_independent_of_construction_order`
- `test:tests/unit_tests.rs::content_hash_changes_with_any_value_change`
- `test:tests/unit_tests.rs::canonical_proof_is_unconditional`
- `test:tests/unit_tests.rs::streaming_delta_produces_the_whole_module_encoding`
- `test:tests/unit_tests.rs::extension_blocks_round_trip_and_are_order_independent`
- `test:tests/integration_tests.rs::content_hash_is_stable_across_independent_encodes`
- `test:tests/property_tests.rs::round_trip_and_canonical_stability`
- `test:tests/property_tests.rs::hash_changes_when_a_value_changes`
- `test:tests/conformance_tests.rs::valid_vectors_validate_and_reencode_identically`
- `test:tests/redteam_tests.rs::threat_non_canonical_images_are_detected`
- `fuzz:fuzz_decode_infinity` — fuzz/fuzz_targets/fuzz_decode_infinity.rs

Negative control (implemented): Replace the canonical node ordering with insertion order in encode and run the canonical identity tests and the non_canonical vector → expected: canonical_identity_is_independent_of_construction_order and valid_vectors_validate_and_reencode_identically must fail, and tests/vectors/valid/non_canonical.ainf must be reported as non-canonical

</details>

<details><summary><strong>I-10</strong> (15 checks)</summary>

- `test:tests/conformance_tests.rs::invalid_vectors_are_rejected_with_their_declared_code`
- `test:tests/conformance_tests.rs::stream_vectors_are_rejected_with_their_declared_code`
- `test:tests/conformance_tests.rs::every_declared_failure_code_has_a_vector`
- `test:tests/unit_tests.rs::validator_rejects_every_declared_failure_class`
- `test:tests/unit_tests.rs::validator_rejects_unknown_unit_discriminant`
- `test:tests/unit_tests.rs::validator_rejects_cycles_and_unreachable_nodes`
- `test:tests/unit_tests.rs::error_codes_are_stable_and_documented`
- `test:tests/integration_tests.rs::malformed_input_never_panics_and_always_fails_closed`
- `test:tests/property_tests.rs::arbitrary_bytes_are_rejected_without_panicking`
- `test:tests/property_tests.rs::byte_flips_are_always_rejected`
- `test:tests/redteam_tests.rs::threat_count_bombs_in_every_section`
- `test:tests/redteam_tests.rs::threat_offset_and_overlap_attacks`
- `test:tests/redteam_tests.rs::threat_string_heap_faults`
- `test:tests/redteam_tests.rs::threat_empty_and_random_inputs_never_panic`
- `fuzz:fuzz_decode_infinity` — fuzz/fuzz_targets/fuzz_decode_infinity.rs

Negative control (implemented): Delete one bounds check in validate (for example the section-span check) and run the conformance suite → expected: the matching invalid vector must be accepted or panic, so invalid_vectors_are_rejected_with_their_declared_code fails and names the vector and code

</details>

<details><summary><strong>I-12</strong> (2 checks)</summary>

- `test:tests/integration_tests.rs::evaluation_still_works_after_the_binary_round_trip`
- `test:tests/integration_tests.rs::agents_can_ask_why_and_impact`

</details>

### Gates referenced by the matrix

| Gate | Command |
|---|---|
| `api-surface` | `cargo +nightly rustdoc --locked --lib --all-features -- -Zunstable-options --output-format json && python scripts/api_surface.py target/doc/active_infinity.json` |
| `audit` | `cargo audit` |
| `baseline-tag` | `git rev-parse --verify hardening-baseline^{commit}` |
| `clippy` | `cargo clippy --locked --all-targets --all-features -- -D warnings` |
| `clippy-nodefault` | `cargo clippy --locked --all-targets --no-default-features -- -D warnings` |
| `deny` | `cargo deny check` |
| `doc` | `RUSTDOCFLAGS=-D warnings cargo doc --locked --no-deps --all-features` |
| `fmt` | `cargo fmt --all -- --check` |
| `fuzz` | `cargo +nightly fuzz run fuzz_decode_infinity -- -runs=20000` |
| `msrv` | `cargo +1.85.0 check --locked --all-targets --all-features` |
| `negative-controls` | `python scripts/negative_controls.py --check` |
| `package` | `cargo package --locked` |
| `test` | `cargo test --locked --all-features` |
| `test-nodefault` | `cargo test --locked --no-default-features` |

<!-- END GENERATED: hardening matrix -->
