# Security model (Active Infinity)

This document is the threat model for the codec, the validator, the views and the
stream layer. It complements `docs/spec/layout.md` (normative wire contract) and
`active-core`'s `spec/threat-model.md` (language-level threats).

## 0. Invariants (never weaken)

These are the non-negotiable properties the hardening program defends. A change
that would violate one stops and needs an ADR.

| ID | Invariant |
|---|---|
| I-1 | Structural secret taint: a secret is a kind, not a removable flag. |
| I-2 | Anti-oracle equality: a secret never equals anything, including itself. |
| I-3 | Secret non-leakage: secrets never appear in Debug, Display, JSON, Protobuf, diagnostics, logs, errors, annotations, provenance or wire tags. |
| I-4 | Capability unforgeability: capability ids are unguessable and possession is authority. |
| I-5 | Attenuation only narrows: no operation may widen methods, budgets, paths or tool policy. |
| I-6 | Revocation at dispatch: a capability revoked after queue but before the provider runs is refused. |
| I-7 | Drop notification: the last handle drop notifies the provider. |
| I-8 | Hard budgets: nodes, depth, bytes, calls, arrays, values and tool payloads fail closed. |
| I-9 | Deterministic canonicalization: the same logical module maps to the same bytes and hash. |
| I-10 | Fail-closed validation: malformed, truncated, overlapping, cyclic or over-budget input is rejected with a stable code. |
| I-11 | No ambient authority: no hidden global permission in the kernel, tools or transports. |
| I-12 | Domain operations run only under a valid capability and within budget. |

## 1. Assets

1. **Secret material** in a module: values, secret locators, blob payloads
   marked tainted, and the fact of whether two secrets are equal.
2. **The agent's process**: memory, CPU time, stack and disk.
3. **Module integrity**: a module must not be accepted with altered content.
4. **Graph integrity**: a module's dependency answers must reflect its nodes.

## 2. Adversaries

- **Malicious producer**: sends bytes designed to crash, hang, over-allocate or
  mislead a consumer.
- **Confused deputy**: a legitimate consumer of module A is tricked into
  processing module B or a mutated A.
- **Curious observer**: reads logs, diagnostics, JSON projections, graph output.
- **Insider code path**: an accidental `Debug`/`Serialize`/format string that
  leaks a value.

## 3. Threats and controls

| Threat | Control | Where |
|---|---|---|
| Truncated / oversized input | exact total size, per-section range checks, `Limits` | `validate::validate_layout` |
| Count bomb (claim 4M nodes in 160 bytes) | counts checked against remaining bytes and `Limits` before allocation | `validate_counts`, `section_end` |
| Integer overflow in ranges | `checked_*`, `u64` arithmetic, saturating slice bounds | `validate`, `encode` |
| Infinite loop / stack overflow | all traversals iterative; depth and node budgets | `check_acyclic`, `check_depth`, `DependencyGraph` walks |
| Dangling reference | every id bounds-checked; unused fields must be zero | `check_nodes` |
| Hidden data in slack | zero padding enforced; unused record fields must be zero; unreachable nodes rejected | `validate_layout`, `check_nodes`, `check_reachability` |
| Forged graph | edge table must equal the derived edges exactly | `check_edges` |
| Content substitution | Blake3 content hash over the whole canonical payload | `hash_image` |
| A writer lies in the `canonical` flag | the flag is a claim: `validate` checks structure and hash, `validate_canonical` / `DecodeOpts::paranoid()` proves canonicality; dedup and signatures must use the proof (layout §6.1) | `validate::validate_canonical` |
| Cross-version confusion | dialect hash refused before parsing; version fields | `Header::parse` |
| Secret leakage through `Debug` | hand-written redacting `Debug`; `SecretBytes` has no value-bearing formatting | `ir.rs` |
| Secret leakage through equality | `SecretBytes::eq` always false; module equality blinds payloads | `ir.rs` |
| Secret leakage through exports | marker replacement; strings equal to a secret redacted; locator promotion at canonicalization | `interop::projection`, `canonical::promote_secret_locators` |
| Secret leakage through errors | messages carry codes and positions only, never payload bytes | `error.rs` |
| Misuse of a partial buffer | views constructible only from `Validated`; borrow prevents mutation | `view.rs` |
| Frame splicing / reordering | sequence numbers, per-frame checksum, strict section order | `stream.rs` |
| Stream hash substitution | `End` hash compared with the reassembled image | `stream.rs` |
| Tainted payload smuggling | tainted blob entries must have zero-length payloads | `check_nodes` |
| Unbounded stream growth | declared size bounded by `Limits::max_total_bytes` | `stream.rs` |

## 4. Non-goals

- **Confidentiality at rest.** A module file contains its payload, including
  secret bytes. Encrypt the store or keep it in a protected location; the format
  guarantees no *code path* emits secret material.
- **Authentication.** The hash proves integrity, not authorship. Signing is a
  transport or distribution concern (`active-rpc` and the release process).
- **Denial of service by sheer size within the limits.** An operator sets
  `Limits` to what its process can afford; defaults are a starting point.
- **Side channels.** Constant-time comparison of secrets is meaningless when
  equality is always false; timing of the *validator* is proportional to input
  size by design.

## 5. Verification

- `tests/redteam_tests.rs` exercises each row above that has a testable control.
- `tests/conformance_tests.rs` pins the failure classes to checked-in vectors.
- The fuzz target (`fuzz/fuzz_targets/decode.rs`) drives `validate` and `decode`
  with arbitrary bytes; a crash or a hang is a release blocker.
- Property tests assert round-trip, canonical stability, hash sensitivity and
  mutation rejection on generated modules.

## 6. Reporting

Security reports go to the address in `SECURITY.md`. Please include the vector,
the code returned, and the expected behaviour. Do not include secret material in
a report.
