# Hardening research log — active-infinity

Addendum A of `ACTIVE-HARDENING-GUIDE-AND-CHECKLIST.md` requires a dated research
sprint at the start of every phase and a log entry per finding. An entry is only
complete when it produces a test, a fuzz oracle, a checklist item, or an ADR
recording accepted risk (`R-4`).

Format: date — topic / source / attack class / mapped invariant / new item IDs /
status.

## 2026-10-27 — H0 research sprint: parser and resource-exhaustion classes (D1, D5)

Sources: NVD 2.0 records fetched on 2026-10-27 for `capnproto`, `flatbuffers`,
`protobuf`, `msgpack`, `grpc`, `wasmtime`; RustSec advisories.

### D1.1 historical bug inventory and mapping

| # | Identifier | Class | Source | Mapped item | Status |
|---|---|---|---|---|---|
| 1 | CVE-2019-25004 | Arbitrary bytes reinterpreted as `bool` in the Rust flatbuffers crate (<0.6.1); soundness defeat, CVSS 9.8 | RustSec-2019-0028 | H2.1, H2.24, I-10 | open: add a "kind vs payload" oracle to `fuzz_unit_discriminants` |
| 2 | CVE-2020-35864 | `read_scalar`/`read_scalar_at` transmute without `unsafe` (flatbuffers Rust ≤1.12) | RustSec-2020-0009 | H2.1, I-10 | covered by `#![forbid(unsafe_code)]`; add a cfg audit (H2.33) |
| 3 | CVE-2026-88344 | Schema-lexer out-of-bounds read when an exact-length buffer ends with a digit (flatcc) | NVD / flatcc#384 | H2.6, I-10 | open: add a "buffer ends on the last byte of a token" seed family |
| 4 | CVE-2026-88345 | Schema-lexer out-of-bounds read on an unterminated quote (flatcc) | NVD / flatcc#385 | H2.6, I-10 | open: same family with an unterminated string |
| 5 | CVE-2026-116734 | Verifier `check_header` integer overflow whose guard is dead code on 32-bit builds (flatcc ≤0.6.4) | NVD / VulnCheck | H2.1, H1.22 | open: add a 32-bit check lane; audit every `as usize`/`as u32` cast |
| 6 | CVE-2022-44011 | Malformed Cap'n Proto object causes a heap buffer overflow in ClickHouse (CWE-787) | NVD | H2.1, H2.2 | partial: `threat_offset_and_overlap_attacks` |
| 7 | CVE-2015-5237 | Heap-based buffer overflow in protobuf ≤3.1.0 (CWE-787) | NVD | H2.1, H2.2 | partial: conformance vectors |
| 8 | CVE-2018-3738 | ReDoS parsing crafted invalid `.proto` files (CWE-185/770) | NVD | H2.5 | n/a: AINF has no regex or text grammar |
| 9 | CVE-2019-15544 | rust-protobuf `Vec::reserve` from an untrusted count exhausts memory (CWE-770) | RustSec-2019-0003 | H2.5, I-8 | partial: `threat_count_bombs_in_every_section`; add an allocation-ceiling assertion |
| 10 | CVE-2021-3121 | GoGo protobuf missing index validation in skip logic, "skippy peanut butter" (CWE-129) | NVD | H2.1, H8.3 | open: fuzz unknown/extension skip arithmetic |
| 11 | CVE-2021-22569 | protobuf-java `UnknownFieldSet` interleaving keeps the parser busy for minutes (CWE-696) | NVD | H2.5, H2.7 | open: measure worst-case time for interleaved repeated fields |
| 12 | CVE-2022-23564 | TensorFlow protobuf decode reaches a `CHECK` abort on user-controlled input (CWE-617) | NVD | H2.1, I-10 | covered in spirit: property tests never panic; add an abort-free harness assertion |
| 13 | CVE-2022-23570 | TensorFlow protobuf decode null-dereferences when a field is absent (CWE-476) | NVD | H2.1, I-10 | covered: `malformed_input_never_panics_and_always_fails_closed` |
| 14 | CVE-2021-21368 | msgpack5 map key `__proto__` changes the decoded object's prototype (CWE-1321) | NVD | H2.17 | n/a for Rust values; table-key handling is tested against duplicate/redacted keys |
| 15 | CVE-2021-46878 | Fluent Bit msgpack type confusion → use-after-free (CWE-843) | NVD | H2.1, H2.24 | partial: kind/discriminant vectors |
| 16 | CVE-2021-46879 | Fluent Bit msgpack heap overflow from a wrong length variable (CWE-787) | NVD | H2.1, H2.2 | partial: offset/overlap tests |
| 17 | CVE-2023-52079 | msgpackr recursive extension keeps the decoder in a loop (CWE-674) | NVD | H1.5, H2.4 | open: `fuzz_graph_cycles` must prove every cycle is reported as `infinity/cycle` |
| 18 | CVE-2026-25899 | A 10-character cookie triggers an 85 GB allocation through unvalidated msgpack lengths (CWE-789/770) | NVD | H2.5, I-8 | partial: declared counts are checked against bytes before allocation |
| 19 | CVE-2026-2454 | Corrupted msgpack frames with wrong array lengths cause OOM (CWE-1287) | NVD | H2.5 | partial: count bombs |
| 20 | CVE-2026-28277 | msgpack checkpoint deserialization reconstructs arbitrary objects (CWE-502) | NVD | H2.17 | n/a: AINF has no polymorphic object construction |
| 21 | CVE-2017-7860 | gRPC `parse_unix` heap buffer overflow (CWE-787) | NVD | H2.1, H2.6 | n/a for Infinity; RPC transport path |
| 22 | CVE-2017-7861 | gRPC `gpr_free` out-of-bounds write (CWE-787) | NVD | H2.1 | n/a for Infinity |
| 23 | CVE-2017-8359 | gRPC use-after-free in `grpc_call_destroy` (CWE-787/UAF) | NVD | H2.10 | n/a for Infinity; RPC handle lifetime |
| 24 | CVE-2017-9431 | gRPC `iomgr/error.c` out-of-bounds write (CWE-787) | NVD | H2.1 | n/a for Infinity |
| 25 | CVE-2017-6599 | gRPC request handling leaks memory, crashing the daemon (CWE-772) | NVD | H2.7, H4.7 | open: sustained-load memory test for the validator |
| 26 | CVE-2023-44487 | HTTP/2 Rapid Reset stream churn (CWE-400) | vendor advisories | H2.19 (RPC) | n/a for Infinity |
| 27 | CVE-2021-32629 | Cranelift sign-extends instead of zero-extends a reloaded i32 (CWE-681) | NVD | H2.1, H1.22 | open: 32-bit lane and cast audit |
| 28 | CVE-2021-39216 | Wasmtime `externref` use-after-free across a GC (CWE-416) | NVD | H2.10 (RPC) | n/a for Infinity |
| 29 | CVE-2021-39218 | Wasmtime invalid free and OOB access through stale GC stack maps (CWE-125/590/787) | NVD | H2.10 (RPC) | n/a for Infinity |
| 30 | CVE-2021-39219 | Wasmtime cross-`Engine` `Linker` type confusion (CWE-843) | NVD | H2.8 (RPC) | n/a for Infinity |
| 31 | CVE-2022-23636 | Wasmtime invalid drop of an uninitialized pointer (CWE-824) | NVD | H2.10 (RPC) | n/a for Infinity |
| 32 | CVE-2022-24791 | Wasmtime UAF when safepoints are inside cold blocks (CWE-416) | NVD | H2.10 (RPC) | n/a for Infinity |
| 33 | CVE-2022-31146 | Wasmtime missing GC metadata after a register-allocator migration (CWE-416) | NVD | H2.10 (RPC) | n/a for Infinity |

### Extracted classes and the concrete oracle each one demands

1. **Untrusted count drives allocation** (CVE-2019-15544, CVE-2026-25899,
   CVE-2026-2454). Oracle: for every section, a count of `u32::MAX` must fail
   with `infinity/limit`, `infinity/count` or `infinity/offset` before any
   allocation proportional to the count. Existing test asserts the error; the
   missing oracle asserts the *allocation* did not happen. New item H2.36.
2. **Arithmetic width and dead guards** (CVE-2026-116734, CVE-2021-32629).
   Oracle: compile and test on a 32-bit target (`i686-unknown-linux-gnu` in
   Docker) and property-test every span computation against `checked_*`. New
   item H1.22 and H2.37.
3. **Lexer boundary reads** (CVE-2026-88344/88345). Oracle: seeds whose final
   byte is the first byte of a multi-byte token. Our format is binary with
   explicit lengths, so the analogue is a string/blob whose declared length ends
   exactly at the buffer end. New item H2.38.
4. **Skip and extension arithmetic** (CVE-2021-3121). Oracle: unknown extension
   tag with a payload length that points to the last byte; duplicate tags; a
   zero-length payload at the end. New item H2.39.
5. **Abort/panic on hostile input** (CVE-2022-23564/23570). Oracle: run the
   corpus and property generator under `panic=abort` in a child process; any
   abort fails the lane. New item H2.40.
6. **Stuck loops and super-linear work** (CVE-2023-52079, CVE-2021-22569).
   Oracle: every accepted image must validate in time linear in its size; add a
   time-ratio assertion for 1k/10k/100k-node images. New item H2.41.
7. **Memory leaks on repeated validation** (CVE-2017-6599). Oracle: RSS after
   100k validate/decode cycles must not grow beyond a fixed slack. New item
   H4.8.

### Research-derived checklist items (added to `invariant-map.toml`)

- **H1.22** 32-bit target build and test lane (Docker `i686`).
- **H1.23** Differential canonicalization oracle: an independent encoder written
  from the spec must reproduce the same bytes for the same logical module.
- **H2.36** Allocation ceiling, not only error code, for untrusted counts.
- **H2.37** Span arithmetic property test against `checked_*` on both widths.
- **H2.38** Length-exactly-at-EOF string/blob seeds.
- **H2.39** Extension skip and duplicate-tag arithmetic.
- **H2.40** Abort-free lane under `panic=abort`.
- **H2.41** Linear-time validation assertion across input sizes.
- **H4.8** RSS stability over repeated validation cycles.

Status: open. Each item is a gap or partial row in `docs/hardening/STATUS.md`
until its oracle lands.

## 2026-10-27 — D3 export-path enumeration (Infinity)

Every path that can emit module data:

| Path | Redaction | Evidence |
|---|---|---|
| `Debug for InfinityModule` | kind names and structure only, secrets as marker | `secrets_never_leak_through_debug_or_exports` |
| `Display`/`Debug for Inode` | `Secret(..)` opaque | same |
| `to_redacted_json` | marker replacement, label occurrences | `projection_never_contains_secret_material` |
| `to_protobuf` | marker replacement, extension refusal | `projection_refuses_an_extension_that_copies_a_secret` |
| `Error` display | no payload bytes | `malformed_input_never_panics_and_always_fails_closed` |
| `provenance_lines`, `value_paths` | labels only, occurrences replaced | `provenance_keys_do_not_carry_secret_copies`, `value_paths_do_not_carry_secret_copies` |
| Public API surface | no accessor returns secret bytes | `api_surface` gate + tripwire |

Gap: there is no test that enumerates the set of public functions returning
`String`/`Vec<u8>` at *runtime* and asserts none is fed a secret. The semantic
gate covers names and resolved return types; H2.15 extends it with a behavioral
probe per export path.

## 2026-10-27 — D4 fuzzing methodology review

Current: one libFuzzer target, byte-level mutations, semantic assertions inside
the target, corpus generated in CI. Missing: committed corpus, structure-aware
mutator, coverage snapshots per target, crash-minimization workflow, and
directed seeds for streaming and projection agreement. H1.18–H1.20 and the
target split in H1.1–H1.8 close these. Corpus policy is recorded in
`docs/hardening/CORPUS.md`.

## 2026-10-27 — D9 side-channel notes

The validator rejects with stable codes and does not compare secret bytes at
all: `SecretBytes` has no equality. The only secret-dependent work is redaction,
which scans literal occurrences in metadata. Timing therefore depends on the
*length* of the metadata and the secret, both of which are already visible to
the data owner; the secret *content* is not compared. Residual risk: length is
not hidden (documented). No error code branches on secret content. A timing
probe for redaction is still worth adding under H2.32.

## 2026-10-27 — D7 supply-chain review

`cargo audit` and `cargo deny` are green; one advisory (`unsafe-libyaml`
unmaintained, via `active-core` → `serde_yaml`) is accepted in `deny.toml` with
ADR-0008. Dependency surface: `blake3`, `thiserror`, optional `active-core`,
optional `serde_json`; dev: `proptest`, `criterion`. No proc-macro dependency in
the crate's own graph except transitive derive macros from `thiserror`. No
`build.rs` in this crate. Residual: the lockfile pins the tested graph, but the
published crate resolves `blake3 = "1.5"` and `thiserror = "1.0"` by semver, so a
consumer may resolve a newer patch release; this is normal for libraries and is
recorded as a residual risk in STATUS.md.

## 2026-10-27 — D3.2 Debug metadata redaction bypass (found by fuzz_secret_positions)

Source: H1.6 fuzz target; minimized input is the empty byte string.
Attack class: a secret literal copied into a binding name, table key, annotation
text, provenance producer/model/tool/key/text, or any other metadata string
survived the derived Debug formatter. The canonical encoder redacts those
copies, but an in-memory Debug, panic message or log line did not.
Mapped invariant: I-3.
Fix: hand-written Debug for InfinityModule clones the module and redacts every
string field through the canonical redactor; extension payloads print as
(tag, length) because a payload has no safe renderer.
New test: tests/unit_tests.rs::debug_redacts_secret_copies_in_metadata.
New control: I-3-debug (redact_text identity must fail the test).
Status: fixed.

## 2026-10-27 — fuzz harness lessons (not library defects)

- Canonical encoding renumbers the arena in pre-order, so a mutation that
  assumes a node index is meaningless. The cycle target now follows the root
  and the Ref chain, and builds a ring with a directly reachable leaf so that
  reachability passes and acyclicity is the check under test.
- A short lowercase canary can collide with formatter field names
  (sta inside 	imestamp_ms). Canaries now have a canary- prefix and hex
  digits.
- A call is queued before the provider runs: an adapter policy refusal is
  observed when the promise settles, not at Agent::call.
Status: all three were harness fixes; no library change.

