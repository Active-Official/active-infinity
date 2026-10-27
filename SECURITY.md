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
