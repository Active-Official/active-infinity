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
| Measured | 2026-10-27 |

## H0 findings

### H0.1 Test inventory

120 test functions across the integration binaries plus the library unit tests
and a doctest:

| Suite | Tests | What it proves |
|---|---|---|
| `tests/unit_tests.rs` | 28 | round-trip, every node kind, canonical identity, stream reassembly, redaction (including Debug metadata), validator classes, extension rules, error-code catalog |
| `tests/integration_tests.rs` | 8 | real modules through `active-core`, hash stability, evaluation/why/impact, fail-closed malformed input |
| `tests/property_tests.rs` | 8 | arbitrary bytes, byte flips, canonical fixpoint, redaction fixpoint, generator sanity |
| `tests/conformance_tests.rs` | 6 | 49 committed vectors, declared codes, index agreement, spec agreement |
| `tests/redteam_tests.rs` | 26 | count bombs, overlap, forged graphs, string faults, deep/wide limits, secret export, anti-oracle, stream splicing, projection expansion, plus review regressions |
| `tests/redteam_battery.rs` | 1 (16 cases) | table-driven H2 cases, each naming its checklist id and invariant |
| `tests/protobuf_tests.rs` | 13 | independent reader, determinism, secret refusal, extension refusal, scalar extremes, taint through interpolation |
| `tests/api_surface.rs` | 4 | no public plaintext secret accessor; allowlist is argued and behaviorally tested |
| `tests/doc_gate.rs` | 13 | spec sections, constants, error-code catalog, README guarantees, ADR index, hardening docs, review record, performance matrix, release process, SECURITY evidence levels, status sign-off |
| `tests/perf_budget.rs` | 4 | linear validation, bounded hostile rejection, RSS stability (Linux) |

The machine-readable invariant-to-test mapping is
`docs/hardening/invariant-map.toml`. Every row resolves to a `#[test]`, a fuzz
target, a vector, a gate or a script that the validator parses out of the tree.

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
- `interop.rs`: a cyclic hand-built module must not hang a query (I-10), and a
  shared DAG must not expand past `PROJECTION_NODE_BUDGET` (I-8).

### H0.2 Fuzz, corpus and coverage

- Eight structure-aware targets cover validate/decode/encode/view, stream
  reassembly, canonical round-trips, section layout, graph cycles, secret
  positions, unit discriminants and projection agreement. Each asserts a semantic
  invariant, not only “did not crash”.
- Conformance corpus: 49 `.ainf` images, 46,673 bytes. Fuzz corpora are
  **committed** under `fuzz/corpus/<target>/` (all targets, 94 seeds total) and
  documented in `docs/hardening/CORPUS.md`.
- Coverage (all features, Windows x86_64): 73.44% regions, 71.66% lines,
  75.00% functions, tracked by `docs/hardening/coverage-baseline.json` and the
  nightly `coverage_gate.py` job.
- CI runs a 2,000-run campaign per target on every push and PR; the nightly
  workflow runs 200,000 runs per target with a matrix.

### H0.3 Documentation inventory

- 10 ADRs (0001–0010) plus index: purpose, active-core relationship, versioning,
  zero-copy, canonical form, secrets, streaming, dependency policy, Protobuf
  projection, no public secret accessor.
- Specs: `layout.md`, `streaming.md`, `security.md`, `projection.md`,
  `performance.md`.
- Hardening set: `STATUS.md`, `REVIEW-SCOPE.md`, `REVIEWS.md`, `RELEASE.md`,
  `COMPATIBILITY.md`, `MIGRATION.md`, `COMPARISON.md`, `LOGGING.md`, `CORPUS.md`,
  `RESEARCH-LOG.md`, `invariant-map.toml`.
- `SECURITY.md`, `CHANGELOG.md`, `docs/release-signing.md`.

### H0.4 Supply chain and release

- Dual license MIT OR Apache-2.0, both license files present.
- MSRV 1.85 verified by the CI `msrv` job.
- `cargo audit`: pass; one allowed unmaintained warning (`unsafe-libyaml`,
  RUSTSEC-2024-0449, via `active-core` → `serde_yaml`, not in the parsing path;
  ADR-0008).
- `cargo deny check`: advisories, bans, licenses, sources all ok.
- CycloneDX SBOM generated from `cargo metadata --locked` by `scripts/sbom.py`
  and attached to CI runs.
- Tags are SSH-signed with the key in `release-signing.allowed_signers`;
  `v2.0.7` verifies with `scripts/verify_tag.sh`.
- crates.io 2.0.7 is published and not yanked.
- Tags are identical on `Active-Official` and `RatioArtificiosa` (same tag
  object, same commit).

### H0.5 Baseline tag

`hardening-baseline` is an annotated, SSH-signed tag at the baseline commit.

### H0.6 This file

The matrix below is validated in CI by `scripts/hardening_status.py --check`.
A missing test, a stale row, or a critical invariant without a negative-control
plan fails the check.

## Red-team battery (H2)

`tests/redteam_battery.rs` is a table of cases. Each case names its checklist
id, the invariant it defends, the threat in one sentence, and a function that
drives the shipped entry points. The suite prints every case and fails on the
first case whose expectation is not met.

| Case | Invariant | Attack |
|---|---|---|
| H2.1 | I-8/I-10 | count bomb in every section |
| H2.2 | I-10 | overlapping and out-of-bounds sections |
| H2.3 | I-8 | deep nesting against the stack |
| H2.4 | I-8 | shared-DAG expansion (billion laughs) |
| H2.5 | I-8 | huge sparse claims with tiny buffers |
| H2.6 | I-10 | invalid UTF-8, overlong encodings, surrogates |
| H2.7 | I-8 | slowloris and oversize stream declarations |
| H2.14 | I-3 | secret in every legal position, all export paths |
| H2.15 | I-3 | secret forced into an error message |
| H2.16 | I-2 | equality and ordering oracle |
| H2.17 | I-3 | smuggling through extensions and metadata |
| H2.24 | I-9 | single-bit mutation of non-hash payload |
| H2.27 | I-9 | projection hash and redaction agreement |
| H2.33 | I-11 | debug-only unlock or ambient authority |
| H2.34 | I-10 | committed corpus replayed as hostile input |
| H2.36 | I-8 | allocation ceiling for untrusted counts |

## Negative controls

`scripts/negative_controls.py` creates a throwaway copy of the working tree,
proves the mapped check passes unmutated, applies one precise source mutation,
and requires the check to fail with that test in the failure list. A compile
error or a different test failing is rejected as a false positive. The copy is
removed afterwards; the working tree is never modified.

| Control | Invariant | Mutation | Check that must fail |
|---|---|---|---|
| `I-3-redaction` | I-3 | canonical redactor returns its input | `the_allowlisted_label_helper_never_returns_secret_material` |
| `I-3-debug` | I-3 | canonical redactor returns its input | `debug_redacts_secret_copies_in_metadata` |
| `I-8-depth` | I-8 | depth ceiling never fires | `threat_deep_and_wide_modules_hit_limits_not_the_stack` |
| `I-8-projection` | I-8 | projection budget removed | `projection_budget_refuses_an_exponential_dag` |
| `I-9-canonical` | I-9 | canonical proof stops comparing the re-encode | `canonical_proof_is_unconditional` |
| `I-10-trailing` | I-10 | both trailing-byte guards removed | `invalid_vectors_are_rejected_with_their_declared_code` |

Run: `python scripts/negative_controls.py --check`. CI job `negative-controls`.

## Gate results

| Gate | Result | Evidence |
|---|---|---|
| `cargo fmt --all -- --check` | pass | local run 2026-10-27 |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | pass | local run 2026-10-27 |
| `cargo clippy --locked --all-targets --no-default-features -- -D warnings` | pass | local run 2026-10-27 |
| `cargo test --locked --all-features` | pass (120 tests) | local run + CI |
| `cargo test --locked --no-default-features` | pass | local run + CI |
| `cargo doc` with `RUSTDOCFLAGS=-D warnings` | pass | local run 2026-10-27 |
| `cargo package --locked` | pass | local run 2026-10-27 |
| `cargo audit` / `cargo deny check` | pass (1 allowed warning) | local run + CI `supply-chain` |
| API-surface gate | pass | CI job `api-surface` |
| Fuzz campaigns (8 targets) | pass | CI 2k/target; nightly 200k/target |
| Negative controls (6) | pass | local run + CI `negative-controls` |
| 32-bit i686 lane | pass | `scripts/check_32bit.sh`, Docker |
| Benchmark matrix | checked in | `benches/codec.rs`, `docs/spec/performance.md` |
| Perf budgets | pass | `cargo test --test perf_budget` |

## Phase H3–H9 evidence

| Phase | State | Evidence |
|---|---|---|
| H3 review | complete | `REVIEW-SCOPE.md` (scope, method, severity, triggers, cadence), `REVIEWS.md` (rounds, triage, fixes with regression tests), `doc_gate` enforces both |
| H4 performance | complete | matrix in `docs/spec/performance.md`, `benches/codec.rs`, `tests/perf_budget.rs`, CI compiles the bench, 32-bit lane |
| H5 ecosystem | complete | runnable `round_trip`, `streaming`, `agent_queries`; `MIGRATION.md`, `COMPARISON.md`, stable error catalog, `LOGGING.md`, misuse notes |
| H6 supply chain | complete | SBOM script + CI job, `cargo audit`/`deny` CI, signed-tag verifier, dual-publish + yank tabletop in `RELEASE.md`, evidence levels in `SECURITY.md` |
| H7 observability | n/a | the codec emits no events, metrics or logs; RPC owns telemetry |
| H8 compatibility | complete | `COMPATIBILITY.md`, 49 frozen vectors, unknown-flag and extension rules, deprecation window |
| H9 continuous | complete | nightly fuzz matrix, coverage floor, review cadence, this public status page |

## Residual risks

- **Secret length is visible.** `SecretBytes::len` is public and is used by
  budgets. Content is not compared and never exported; length is not hidden.
- **Name-scoped API gate.** The semantic gate refuses public functions whose
  names or resolved return types look secret-bearing; a future public function
  with an innocent name that returns secret bytes through a new type would not
  be caught by name alone. ADR-0010 records the limit.
- **Corpus is a seed set, not a proof.** The committed corpora and nightly
  campaigns explore the grammar; they cannot prove absence of a bug.
- **No independent encoder.** The canonical fixpoint is checked against the same
  implementation, not a second one written from the spec (H1.23 documented n/a).
  The Protobuf reader is independent of the writer and covers the projection
  path.
- **`unsafe-libyaml` advisory.** Accepted, unreachable from the parsing path.
- **Dependency resolution at publish time.** The library allows semver-compatible
  patch updates of `blake3` and `thiserror`; the CI lockfile is the tested graph.
- **Coverage of `view.rs`.** The public zero-copy surface is under-tested at the
  unit level (12% region coverage at baseline); the integration and fuzz paths
  exercise it, but a dedicated view test matrix is future work.
- **Timing.** Validation is data-independent in control flow but not
  constant-time; a local attacker who can measure cache behaviour is outside the
  threat model.

## Maturity sign-off

```text
Hardening baseline commit/tag: 9b44242496568e2338c5e98b90e558d4b0999f4e / hardening-baseline
H0 inventory complete: yes
H1 fuzz continuous: yes
H2 red-team green: yes
H3 independent review: yes (REVIEWS.md; Muse-routed Copilot CLI)
H4 performance gated: yes (docs/spec/performance.md, tests/perf_budget.rs)
H5 ecosystem docs: yes (examples/, MIGRATION.md, COMPARISON.md, LOGGING.md)
H6 supply chain: yes (SBOM, audit, deny, signed tags, dual publish)
H7 observability safe: n/a (no runtime telemetry in the codec)
H8 compatibility: yes (COMPATIBILITY.md, frozen AINF 1.0 vectors)
H9 continuous assurance active: yes (nightly fuzz + coverage + review cadence)
Residual risks documented: yes
Sign-off: 2026-10-27, Grok (AI coding and security agent)
```

<!-- BEGIN GENERATED: hardening matrix (scripts/hardening_status.py) -->

**Repository:** `active-infinity` **version:** `2.0.7` **baseline commit:** `9b44242496568e2338c5e98b90e558d4b0999f4e` **baseline tag:** `hardening-baseline` **measured:** 2026-10-27

Invariants: 6 covered, 1 partial, 0 gap, 5 not applicable. Checklist items: 103 done, 0 partial, 0 gap, 57 not applicable. Criticals with an implemented negative control: 4/4. Distinct automated checks resolved: 123.

| Invariant | Meaning | Status | Checks | Negative control |
|---|---|---|---|---|
| **I-1** | Structural secret taint | `covered` | 10 | - |
| **I-2** | Anti-oracle equality | `covered` | 2 | - |
| **I-3** | Secret non-leakage | `covered` | 18 | implemented |
| **I-4** | Capability unforgeability | `n/a` | 0 | - |
| **I-5** | Attenuation only narrows | `n/a` | 0 | - |
| **I-6** | Revocation at dispatch | `n/a` | 0 | - |
| **I-7** | Drop notification | `n/a` | 0 | - |
| **I-8** | Hard budgets | `covered` | 12 | implemented |
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
| **H1.1** | fuzz_decode_infinity: full validate and view path | `done` | `fuzz:fuzz_decode_infinity`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
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
| **H1.20** | CI fuzz budget on PRs, longer on main/nightly, fail on regression | `done` | `script:scripts/coverage_gate.py`, `script:.github/workflows/nightly.yml` |
| **H1.21** | Optional public sanitized corpus | `done` | `doc:docs/hardening/CORPUS.md`, `doc:fuzz/corpus/fuzz_decode_infinity` |
| **H1.22** | 32-bit target build and test lane (research: CVE-2026-116734, CVE-2021-32629) | `done` | `script:scripts/check_32bit.sh` |
| **H1.23** | Differential canonicalization oracle from an independent encoder | `n/a` | - |
| **H1.24** | fuzz_tool_policy | `n/a` | - |
| **H2.0** | Scripted negative controls prove each security-critical check fails on a broken build | `done` | `gate:negative-controls` |
| **H2.1** | Integer overflow and underflow in length and offset arithmetic | `done` | `test:tests/redteam_tests.rs::threat_count_bombs_in_every_section`, `test:tests/redteam_tests.rs::threat_offset_and_overlap_attacks`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.2** | Overlapping and out-of-bounds sections | `done` | `test:tests/redteam_tests.rs::threat_offset_and_overlap_attacks`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.3** | Deep nesting aimed at stack overflow | `done` | `test:tests/redteam_tests.rs::threat_deep_and_wide_modules_hit_limits_not_the_stack`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.4** | Billion-laughs expansion via references or repeated subgraphs | `done` | `test:tests/redteam_battery.rs::redteam_battery_is_green`, `test:tests/redteam_tests.rs::projection_budget_is_shared_across_every_binding`, `test:tests/perf_budget.rs::projection_budget_fails_fast_on_a_shared_dag` |
| **H2.5** | Huge sparse claims with tiny actual buffers | `done` | `test:tests/redteam_tests.rs::threat_size_limits_are_enforced_without_allocation`, `test:tests/redteam_tests.rs::threat_count_bombs_in_every_section`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.6** | Invalid UTF-8, overlong encodings, surrogate nonsense | `done` | `test:tests/redteam_tests.rs::threat_string_heap_faults`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.7** | Streaming slowloris and oversize total declarations | `done` | `test:tests/redteam_tests.rs::review_stream_bounds_reject_unbounded_batches`, `test:tests/redteam_tests.rs::review_stream_begin_uses_the_caller_limits`, `test:tests/redteam_tests.rs::review_delta_fragments_honor_the_stream_limits`, `test:tests/redteam_battery.rs::redteam_battery_is_green`, `test:tests/perf_budget.rs::stream_reassembly_rejects_truncation_in_bounded_time` |
| **H2.8** | Forge capability IDs | `n/a` | - |
| **H2.9** | Attenuate then widen | `n/a` | - |
| **H2.10** | Use after revoke or drop; borrowed channel lifetime | `n/a` | - |
| **H2.11** | Confused deputy provider | `n/a` | - |
| **H2.12** | Tool adapter confused deputy | `n/a` | - |
| **H2.13** | Revocation racing with dispatch | `n/a` | - |
| **H2.14** | Secrets in every legal position; scan all export paths | `done` | `test:tests/redteam_tests.rs::threat_secret_never_reaches_any_export_surface`, `test:tests/protobuf_tests.rs::taint_follows_references_in_interpolations`, `test:tests/redteam_battery.rs::redteam_battery_is_green`, `test:tests/redteam_tests.rs::every_subvalue_debug_path_redacts_text` |
| **H2.15** | Force secrets into error messages | `done` | `test:tests/redteam_tests.rs::threat_secret_never_reaches_any_export_surface`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.16** | Equality and ordering oracle attempts | `done` | `test:tests/redteam_tests.rs::threat_anti_oracle_equality`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.17** | Smuggle secrets via extensions, annotations, provenance, projections | `done` | `test:tests/redteam_tests.rs::review_projection_redacts_secret_copies_in_keys_and_metadata`, `test:tests/protobuf_tests.rs::projection_refuses_an_extension_that_copies_a_secret`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.18** | Logging and metrics carry no secrets or raw capability bits | `n/a` | - |
| **H2.19** | Queue storms under a low call budget | `n/a` | - |
| **H2.20** | Nested value byte bombs under a low byte budget | `done` | `test:tests/redteam_tests.rs::review_limits_cover_total_bytes_and_string_heap`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.21** | Many lanes, channels and promises to finite limits | `n/a` | - |
| **H2.22** | Enormous tool payloads and tools that never return | `n/a` | - |
| **H2.23** | Zero or near-zero ceilings refused where policy needs finite limits | `n/a` | - |
| **H2.24** | Single-bit mutation fails validation or changes the hash | `done` | `test:tests/property_tests.rs::byte_flips_are_always_rejected`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.25** | Large-corpus hash collision search | `n/a` | - |
| **H2.26** | Pipelined vs sequential preserves the authorization side-effect set | `n/a` | - |
| **H2.27** | Projection hash and redaction agreement under adversarial valid modules | `done` | `test:tests/protobuf_tests.rs::projection_is_canonical_for_logically_equal_modules`, `test:tests/protobuf_tests.rs::projection_never_contains_secret_material`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.28** | Overlapping write capabilities detected or prevented | `n/a` | - |
| **H2.29** | Audit-only capability cannot write | `n/a` | - |
| **H2.30** | Stale capability after ownership change refused | `n/a` | - |
| **H2.31** | Another worker's secret-bearing subgraph denied or fully redacted | `n/a` | - |
| **H2.32** | Public errors do not enable secret or capability oracles | `done` | `test:tests/unit_tests.rs::error_codes_are_stable_and_documented`, `test:tests/redteam_tests.rs::threat_anti_oracle_equality`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.33** | No debug unlock or test ambient authority in release builds | `done` | `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.34** | Fuzz corpus treated as permanently hostile input | `done` | `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.35** | Docs and examples do not teach insecure patterns without warnings | `done` | `test:tests/doc_gate.rs::hardening_documents_exist_and_state_their_rules`, `doc:SECURITY.md` |
| **H2.36** | Allocation ceiling for untrusted counts, not only an error code | `done` | `test:tests/redteam_tests.rs::threat_size_limits_are_enforced_without_allocation`, `test:tests/redteam_tests.rs::threat_count_bombs_in_every_section`, `test:tests/redteam_battery.rs::redteam_battery_is_green`, `test:tests/redteam_tests.rs::header_try_write_refuses_a_short_buffer_without_panicking` |
| **H2.37** | Span arithmetic checked on 32-bit and 64-bit widths | `done` | `script:scripts/check_32bit.sh`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.38** | String and blob lengths that end exactly at EOF | `done` | `fuzz:fuzz_layout_sections`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.39** | Extension skip and duplicate-tag arithmetic | `done` | `test:tests/unit_tests.rs::duplicate_extension_tags_are_refused`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **H2.40** | Abort-free lane under panic=abort | `done` | `fuzz:fuzz_decode_infinity`, `fuzz:fuzz_secret_positions` |
| **H2.41** | Validation time is linear in image size | `done` | `test:tests/perf_budget.rs::validation_scales_linearly` |
| **H2.42** | Cross-kernel and cross-connection capability transplant | `n/a` | - |
| **H2.43** | Event and log redaction oracle | `n/a` | - |
| **H2.44** | Tool timeout and payload ceiling | `n/a` | - |
| **H2.45** | Shared-memory frame TOCTOU | `n/a` | - |
| **H2.46** | URL and path allow-list canonicalization bypass | `n/a` | - |
| **H2.47** | Promise settlement count under concurrent cancel and resolve | `n/a` | - |
| **H3.1** | Freeze a review scope document | `done` | `doc:docs/hardening/REVIEW-SCOPE.md`, `test:tests/doc_gate.rs::review_program_is_documented_and_has_a_record` |
| **H3.2** | Independent review with recorded findings | `done` | `test:tests/doc_gate.rs::review_program_is_documented_and_has_a_record`, `doc:REVIEWS.md` |
| **H3.3** | Triage findings; critical and high fixed before maturity | `done` | `test:tests/doc_gate.rs::review_program_is_documented_and_has_a_record`, `doc:REVIEWS.md` |
| **H3.4** | Re-test after fixes with evidence | `done` | `test:tests/doc_gate.rs::review_program_is_documented_and_has_a_record`, `doc:REVIEWS.md` |
| **H3.5** | Schedule delta reviews after model or wire changes | `done` | `test:tests/doc_gate.rs::review_program_is_documented_and_has_a_record`, `doc:docs/hardening/REVIEW-SCOPE.md` |
| **H3.6** | Annual revisit in maintenance | `done` | `test:tests/doc_gate.rs::review_program_is_documented_and_has_a_record`, `doc:docs/hardening/REVIEW-SCOPE.md` |
| **H4.1** | Checked-in benchmark matrix | `done` | `script:benches/codec.rs`, `test:tests/doc_gate.rs::performance_baselines_are_checked_in` |
| **H4.2** | Throughput and p50/p99 for encode, decode, validate, hash, projection | `done` | `doc:docs/spec/performance.md`, `test:tests/doc_gate.rs::performance_baselines_are_checked_in` |
| **H4.3** | RPC call latency, pipelining, concurrency | `n/a` | - |
| **H4.4** | Sustained load tests with RSS, allocations, FDs, threads | `done` | `test:tests/perf_budget.rs::repeated_validation_does_not_grow_rss`, `gate:perf` |
| **H4.5** | CI regression gates on the benchmark matrix | `done` | `gate:perf`, `gate:bench`, `test:tests/perf_budget.rs::validation_scales_linearly` |
| **H4.6** | Publish docs/performance.md with methodology and numbers | `done` | `doc:docs/spec/performance.md`, `test:tests/doc_gate.rs::performance_baselines_are_checked_in` |
| **H4.7** | Explicit DoS scenarios prove budgets cap CPU and memory | `done` | `test:tests/perf_budget.rs::hostile_rejection_is_bounded`, `test:tests/redteam_tests.rs::threat_size_limits_are_enforced_without_allocation`, `test:tests/perf_budget.rs::projection_budget_fails_fast_on_a_shared_dag`, `test:tests/perf_budget.rs::stream_reassembly_rejects_truncation_in_bounded_time` |
| **H4.8** | RSS stability over repeated validation cycles | `done` | `script:scripts/check_32bit.sh`, `test:tests/perf_budget.rs::repeated_validation_does_not_grow_rss` |
| **H4.9** | FD and thread stability under connection churn | `n/a` | - |
| **H5.1** | Runnable examples for round-trip, queries, streaming | `done` | `doc:examples/round_trip.rs`, `doc:examples/streaming.rs`, `doc:examples/agent_queries.rs` |
| **H5.2** | Migration from JSON/YAML guide | `done` | `doc:docs/hardening/MIGRATION.md`, `test:tests/doc_gate.rs::migration_comparison_and_compatibility_are_documented` |
| **H5.3** | Why not only Cap'n Proto, FlatBuffers or gRPC comparison | `done` | `doc:docs/hardening/COMPARISON.md`, `test:tests/doc_gate.rs::migration_comparison_and_compatibility_are_documented` |
| **H5.4** | Stable machine-readable error code catalog | `done` | `test:tests/conformance_tests.rs::every_declared_failure_code_has_a_vector`, `test:tests/unit_tests.rs::error_codes_are_stable_and_documented`, `test:tests/doc_gate.rs::every_error_code_is_documented` |
| **H5.5** | Explicit what-is-safe-to-log rules | `done` | `doc:docs/hardening/LOGGING.md`, `test:tests/doc_gate.rs::hardening_documents_exist_and_state_their_rules` |
| **H5.6** | Misuse documentation | `done` | `doc:docs/hardening/COMPARISON.md`, `test:tests/doc_gate.rs::migration_comparison_and_compatibility_are_documented` |
| **H5.7** | Optional active-habitat demo | `n/a` | - |
| **H6.1** | SBOM on every release | `done` | `script:scripts/sbom.py`, `gate:sbom` |
| **H6.2** | cargo deny and advisory audit strict in CI | `done` | `gate:audit`, `gate:deny` |
| **H6.3** | Reproducible builds where feasible, limits documented | `done` | `doc:docs/hardening/RELEASE.md`, `test:tests/doc_gate.rs::release_and_supply_chain_process_is_operational` |
| **H6.4** | Signed tags with allowed_signers enforced | `done` | `script:scripts/verify_tag.sh`, `test:tests/doc_gate.rs::release_and_supply_chain_process_is_operational` |
| **H6.5** | Dual publish checklist mechanical and reviewed | `done` | `doc:docs/hardening/RELEASE.md`, `test:tests/doc_gate.rs::release_and_supply_chain_process_is_operational` |
| **H6.6** | Yank and advisory process exercised in a dry run | `done` | `doc:docs/hardening/RELEASE.md`, `test:tests/doc_gate.rs::release_and_supply_chain_process_is_operational` |
| **H6.7** | Property tests for attenuation monotonicity | `n/a` | - |
| **H6.8** | Bounded or exhaustive capability lifecycle model | `n/a` | - |
| **H6.9** | Public statement of tested vs fuzzed vs reviewed vs proven | `done` | `doc:SECURITY.md`, `test:tests/doc_gate.rs::security_policy_states_the_evidence_levels` |
| **H6.10** | Exhaustive small-state capability lifecycle model | `n/a` | - |
| **H7.1** | Structured events for call, settle, revoke, budget, refusal | `n/a` | - |
| **H7.2** | Default logs carry no secrets or raw capability bits | `n/a` | - |
| **H7.3** | Metrics without sensitive payloads | `n/a` | - |
| **H7.4** | Tests that force sensitive data into events fail CI | `n/a` | - |
| **H8.1** | Written wire and format compatibility policy | `done` | `doc:docs/hardening/COMPATIBILITY.md`, `test:tests/doc_gate.rs::migration_comparison_and_compatibility_are_documented` |
| **H8.2** | Old Infinity images still validate | `done` | `test:tests/conformance_tests.rs::valid_vectors_validate_and_reencode_identically`, `doc:docs/hardening/COMPATIBILITY.md` |
| **H8.3** | Unknown flags and extensions behavior specified and tested | `done` | `test:tests/unit_tests.rs::duplicate_extension_tags_are_refused`, `test:tests/unit_tests.rs::extension_blocks_round_trip_and_are_order_independent`, `test:tests/doc_gate.rs::migration_comparison_and_compatibility_are_documented` |
| **H8.4** | Versioned public conformance suite | `done` | `test:tests/conformance_tests.rs::the_index_and_the_vector_files_agree`, `doc:docs/hardening/COMPATIBILITY.md` |
| **H8.5** | Deprecation windows for shipped behavior | `done` | `doc:docs/hardening/COMPATIBILITY.md`, `test:tests/doc_gate.rs::migration_comparison_and_compatibility_are_documented` |
| **H9.1** | Nightly continuous fuzz with growing corpus | `done` | `gate:fuzz`, `doc:.github/workflows/nightly.yml` |
| **H9.2** | Periodic independent review cadence on the calendar | `done` | `doc:docs/hardening/REVIEW-SCOPE.md`, `test:tests/doc_gate.rs::review_program_is_documented_and_has_a_record` |
| **H9.3** | Public status section: performance, security posture, residual risks | `done` | `doc:docs/hardening/STATUS.md`, `test:tests/doc_gate.rs::status_publishes_residual_risks_and_the_sign_off_block` |
| **H9.4** | Hardening checklist reviewed every release; new classes added | `done` | `doc:docs/hardening/STATUS.md`, `test:tests/doc_gate.rs::status_publishes_residual_risks_and_the_sign_off_block` |
| **H9.5** | Maturity claim only after H0-H8 complete and H9 sustained | `done` | `doc:docs/hardening/STATUS.md`, `test:tests/doc_gate.rs::status_publishes_residual_risks_and_the_sign_off_block` |
| **R-0** | Research sprint before each phase | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **R-1** | Research sibling components after every critical fix | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **R-2** | Full multi-domain pass once per release cycle | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **R-3** | Log every finding in RESEARCH-LOG.md | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **R-4** | Every finding becomes a test, item, ADR or n/a note | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D1.1** | At least 15 historical parser bugs with identifiers | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D1.2** | Map each historical bug to layout, validate, stream or wire decode | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D1.3** | Add a test or fuzz oracle per mapped class | `done` | `fuzz:fuzz_decode_infinity`, `fuzz:fuzz_layout_sections`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **D1.4** | Differential parsing and whether a second checker is warranted | `n/a` | - |
| **D2.1** | At least 10 capability or RPC authz failure patterns | `n/a` | - |
| **D2.2** | Map authz patterns to kernel, cap, channel, tool, transport | `n/a` | - |
| **D2.3** | Monotonicity, revoke-at-dispatch and confused-deputy tests | `n/a` | - |
| **D2.4** | Rights amplification and caretaker patterns | `n/a` | - |
| **D3.1** | Enumerate every export path | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D3.2** | Attempt redaction bypass techniques in tests | `done` | `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **D3.3** | Anti-oracle equality in debug and optimized builds | `done` | `test:tests/property_tests.rs::redaction_is_a_fixpoint_for_arbitrary_secrets_and_texts` |
| **D3.4** | Stable error codes do not branch on secret-dependent data | `done` | `test:tests/redteam_tests.rs::threat_anti_oracle_equality`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **D4.1** | Compare fuzz targets to structure-aware state of the art | `done` | `doc:docs/hardening/CORPUS.md` |
| **D4.2** | Semantic oracles, not only crash oracles | `done` | `fuzz:fuzz_secret_positions`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **D4.3** | Directed seeds for cold paths | `done` | `doc:docs/hardening/CORPUS.md` |
| **D4.4** | Corpus growth and minimize-and-commit policy | `done` | `doc:docs/hardening/CORPUS.md` |
| **D5.1** | Map classic DoS classes to budget dimensions | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D5.2** | Prove hostile input hits budget before host OOM | `done` | `test:tests/redteam_tests.rs::threat_size_limits_are_enforced_without_allocation`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |
| **D5.3** | Compression bombs at transport edges | `n/a` | - |
| **D6.1** | Escape catalog for HTTP, process and MCP tools | `n/a` | - |
| **D6.2** | Automate escape attempts as red-team tests | `n/a` | - |
| **D6.3** | Runtime sandbox escape claims | `n/a` | - |
| **D7.1** | Audit dependencies for unnecessary privilege | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D7.2** | cargo deny and advisories gate merges | `done` | `gate:audit`, `gate:deny` |
| **D7.3** | Document residual non-reproducibility sources | `done` | `doc:docs/hardening/RELEASE.md` |
| **D8.1** | Capability patterns for writer, auditor, orchestrator | `n/a` | - |
| **D8.2** | Overlapping, stale and exfiltration grants | `n/a` | - |
| **D8.3** | Import applicable multi-agent security tests | `n/a` | - |
| **D9.1** | Secret- or capability-dependent timing in hot paths | `n/a` | - |
| **D9.2** | Docs do not reveal privileged test-only behavior | `done` | `test:tests/doc_gate.rs::hardening_documents_exist_and_state_their_rules` |
| **D9.3** | Standing question: what would an infinite-input agent try next | `done` | `doc:docs/hardening/RESEARCH-LOG.md`, `test:tests/redteam_battery.rs::redteam_battery_is_green` |

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

<details><summary><strong>I-8</strong> (12 checks)</summary>

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
- `test:tests/redteam_tests.rs::projection_budget_refuses_an_exponential_dag`
- `script:scripts/negative_controls.py#I-8-projection`

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
| `bench` | `cargo bench --locked --bench codec --no-run` |
| `clippy` | `cargo clippy --locked --all-targets --all-features -- -D warnings` |
| `clippy-nodefault` | `cargo clippy --locked --all-targets --no-default-features -- -D warnings` |
| `deny` | `cargo deny check` |
| `doc` | `RUSTDOCFLAGS=-D warnings cargo doc --locked --no-deps --all-features` |
| `fmt` | `cargo fmt --all -- --check` |
| `fuzz` | `cargo +nightly fuzz run fuzz_decode_infinity -- -runs=20000` |
| `msrv` | `cargo +1.85.0 check --locked --all-targets --all-features` |
| `negative-controls` | `python scripts/negative_controls.py --check` |
| `package` | `cargo package --locked` |
| `perf` | `cargo test --locked --test perf_budget` |
| `sbom` | `python scripts/sbom.py --output dist/active-infinity.cdx.json && python scripts/sbom.py --check dist/active-infinity.cdx.json` |
| `test` | `cargo test --locked --all-features` |
| `test-nodefault` | `cargo test --locked --no-default-features` |

<!-- END GENERATED: hardening matrix -->

- **Hash-collision search (H2.25) is out of budget.** A birthday search against a
  256-bit Blake3 content hash needs ~2^128 work; the committed tests prove hash
  stability and single-bit sensitivity, not collision resistance. This is an
  accepted computational limit, not an untested guard.
- **Bindings, provenance and hashes are bounded by total bytes.** Their counts
  are not separate `Limits` fields: the per-entry size is fixed (8, 1 and 32
  bytes), so `max_total_bytes` plus the section-offset check bounds them before
  allocation. The count error is reported as `infinity/count` when the count
  exceeds the buffer and `infinity/limit` when a configurable ceiling fires.
