# Security policy

## Supported versions

| Version | Security fixes |
|---|---|
| 1.1.x | yes |
| < 1.1 | no |

## Reporting a vulnerability

Report privately to the maintainers of the `Active-Official` organization (or via
a GitHub private security advisory on `Active-Official/active-infinity`). Do not
open a public issue, and never include secret material in a report.

Please include:

- the byte sequence or module that triggers the issue (as a hex dump or a file);
- the code returned (e.g. `infinity/offset`) and the expected behaviour;
- whether the issue is a crash, a hang, an over-allocation, a canonical-form
  break, a secret leak, or an integrity bypass.

## Response

- Acknowledgement within 3 business days.
- A fix or a mitigation plan within 30 days for a confirmed issue.
- A CVE and a patched release for anything that affects a released version.
- Credit in the advisory unless you ask otherwise.

## Scope

In scope: the codec, validator, view and stream layers of this crate; the
`active-core` bridge; the conformance vectors; the fuzz target.

Out of scope: confidentiality of a module at rest (a module contains its payload,
including secret bytes — encrypt or protect the store), the security of an
`active-core` release, and denial of service by input larger than the configured
`Limits`.

## Hardening expectations

- A buffer is never trusted before `validate`.
- `#![forbid(unsafe_code)]`.
- No secret material in `Debug`, `Display`, `Serialize`, diagnostics, projections
  or error messages.
- Every traversal is bounded; every count is checked against the bytes.
- The fuzz target and the red-team suite are part of every release gate.

## What is tested, fuzzed, reviewed, and proven

| Level | What it covers | Where the evidence lives |
|---|---|---|
| **Tested** | 49 conformance vectors, 100+ unit/integration/property tests, the table-driven red-team battery, negative controls and performance budgets | `tests/`, `docs/hardening/STATUS.md` |
| **Fuzzed** | eight structure-aware targets: decode/validate/view, stream reassembly, canonical round-trip, section layout, cycles, secret positions, unit discriminants, projection agreement | `fuzz/`, committed corpora, nightly 200k-run campaign |
| **Reviewed** | independent review rounds with triaged findings and regression tests for every fix | `REVIEWS.md`, `docs/hardening/REVIEW-SCOPE.md` |
| **Proven** | linear bounded validation, canonical fixpoint and redaction fixpoint are stated as invariants and property-tested; they are **not** machine-checked proofs | `docs/spec/security.md` |

Nothing in this crate is formally verified. The claims are bounded by the
checked-in tests and the documented residual risks; a property that is not in
that table is not claimed.
