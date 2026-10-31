# Copilot deep audit marathon — Active Infinity

Program: `C:\Users\Usuario\Downloads\Active-Absolute-Max-Program`, phase M-6,
procedure `COPILOT-DEEP-AUDIT-LOOP.md`. Reviewer: GitHub Copilot CLI routed to the
Muse proxy (`muse-spark-1.3-contributor`, `--reasoning-effort xhigh`), which reads
the repository through its own tool access, so findings carry file:line
references rather than pasted guesses.

Loop per section: prepare context → hostile review → triage every finding against
the code → regression test first → minimal fix → targeted tests + clippy → re-audit
→ CLEAN twice or ADR-accepted residual.

## Status

| ID | Section | Paths | State | Findings (fixed / rejected / open) | Commits |
|----|---------|-------|-------|------------------------------------|---------|
| I-01 | layout / header | `src/layout.rs` | CLEAN (round 2 open items fixed) | 10 fixed, 1 rejected, 0 open | this commit |
| I-02 | validate | `src/validate.rs` | pending | — | — |
| I-03 | encode / canonical | `src/encode.rs`, `src/canonical.rs` | pending | — | — |
| I-04 | decode / view | `src/decode.rs`, `src/view.rs` | pending | — | — |
| I-05 | IR / units | `src/ir.rs`, `src/unit.rs` | pending | — | — |
| I-06 | stream / delta | `src/stream.rs` | pending | — | — |
| I-07 | schema | `src/schema.rs` | pending | — | — |
| I-08 | store | `src/store.rs` | pending | — | — |
| I-09 | compress | `src/compress.rs` | pending | — | — |
| I-10 | signature / proof | `src/signature.rs`, `src/proof.rs` | pending | — | — |
| I-11 | merge | `src/merge.rs` | pending | — | — |
| I-12 | interop / protobuf | `src/interop.rs`, `src/protobuf.rs` | pending | — | — |
| I-13 | error codes | `src/error.rs` | pending | — | — |
| I-14 | FFI | `ffi/**` | pending | — | — |
| I-15 | CLI | `cli/active-infinity-cli/**` | pending | — | — |
| I-16 | fuzz targets | `fuzz/**` | pending | — | — |

## Cross-cutting passes (after the sections)

| Pass | State | Notes |
|---|---|---|
| Concurrency / multi-tenant | pending | — |
| Oracle and secret paths (Display/Debug/Serialize) | pending | — |
| Wire confusion (AINF vs stream vs protobuf) | pending | — |
| Resource bombs (depth, counts, sizes) | pending | — |
| Polyglot encoder golden | pending | — |
| Second pass over changed sections | pending | — |

## Log

Entries are appended per section: date, reviewer path, findings, disposition.

### I-01 layout / header — 2026-10-31 (rounds 1 and 2)

Reviewer: Copilot CLI → Muse proxy, `xhigh`, repo tool access.

Round 1 findings and disposition (all regression-tested in
`tests/marathon_layout_tests.rs`; the probe run against the pre-fix tree showed
all four behavioural probes failing, including a debug panic in `align8`):

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `Header::write` never wrote the reserved tail (bytes 200..224), so a written header refused by its own `parse` and inherited whatever the caller's buffer held | **fixed**: the tail is zeroed; `writing_a_header_zeroes_the_reserved_tail` |
| 2 | high | `validate_structure` did not enforce reachability while its doc claimed wire parity | **fixed as a contract**, not by force: reachability is a canonicalization concern (in-place deltas rely on dropping orphans), so the doc now says so and `check_reachable()` is public; `unreachable_nodes_are_reported_and_dropped_by_canonicalization` pins both halves, and `docs/spec/layout.md` §3.1a records it |
| 3 | medium | dialect preimage pinned via string literals, no link to the constants | **fixed**: `NODE_KIND_MAX`, `AUX_TAGS`, `DIALECT_KINDS_TEXT`, `DIALECT_AUX_TAGS_TEXT`, `DIALECT_HASH_GOLDEN`; two tests force a deliberate change; §1.2 documents the byte-exact preimage |
| 4 | medium | `push()` panicked on arena exhaustion | **fixed**: `try_push()` returns `Error::Limit`; `push` documents its panic |
| 5 | medium | `SecretBytes` left its bytes in freed heap | **fixed**: `Drop` overwrites the buffer |
| 6 | medium | spec said secrets never compare equal while module equality blinds them | **fixed in docs**: §3.1 distinguishes payload equality from module blinding |
| 7 | medium | `Limits::check` covered 5 of 20 ceilings | **fixed**: all 22 ceilings, each naming its field |
| 8 | low | `Error::HeaderSize(u8)` truncated the `u16` wire value | **fixed**: field is `u16` |
| 9 | low | `align8` wrapped at `u64::MAX` (panic in debug) | **fixed**: saturating; `align8_saturates_instead_of_wrapping` |
| 10 | low | stale "160-byte" doc; short magic prefix reported as magic | **doc fixed**; error-order part **rejected**: a wrong 4-byte prefix is "not an AINF image" (`infinity/magic`) and a matching prefix that is short is `infinity/header-truncated`, which is what `store` and the CLI branch on |

Round 2 findings and disposition:

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 11 | medium | `read_u32/read_u64` computed `offset + 4/8` unchecked (`usize::MAX` wraps or panics) | **fixed**: `checked_add` → `infinity/truncated`; `a_hostile_offset_is_reported_as_truncated_not_a_wrap` |
| 12 | medium | `Header::write` still panics on a short buffer | **rejected**: documented precondition plus the fallible `try_write`; the assert runs in release too, and `redteam_battery` forbids debug-only security branches. Changing the signature to `&mut [u8; 224]` would push the panic to the caller |
| 13 | medium | provenance hashes and bindings were bounded by `u32::MAX` in `validate_counts` | **fixed**: new `Limits::max_hashes` / `max_bindings`, enforced in the count pass and in the hash walk, with their own ceiling names |
| 14 | low | `hashes` limit borrowed `max_nodes` in the error | **fixed** by 13 |
| 15 | low | dialect preimage widths undocumented | **fixed**: §1.2 now states the widths, order and separators |
| 16 | low | `SectionSpan::bytes` is only valid for fixed-stride sections | **rejected**: the doc says "for a fixed-stride section"; the var-length sections compute their end in `validate.rs::section_end` |

Gate after the section: `cargo clippy --locked --all-targets --all-features
-D warnings` clean; `cargo test --all-features` 213 passed, 0 failed.
