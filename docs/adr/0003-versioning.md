# ADR-0003 — Versioning, MSRV and the crates.io name reservation

**Status:** accepted (2026-10-27)

## Context

- `active-infinity` 1.0.0 already exists on crates.io as a reservation crate
  published by the Active organization. Cargo cannot publish a second 1.0.0.
- The scaffold and the proposals specify `0.1.0`, which is now impossible to
  publish over the reservation.
- The format itself is at major 1: the layout document is normative and the ids
  in it are permanent.
- MSRV is 1.85, matching the rest of the Active workspace.

## Decision

1. The crate version starts at **1.1.0**. The wire format version is a separate
   `u16` pair in the header (`1.0`) and is not tied to the crate version.
2. Semver for the crate:
   - **patch**: fixes, documentation, performance, no API or format change;
   - **minor**: additive API; format minor may rise for skippable additions;
   - **major**: any change to the documented byte layout or to a public API in a
     way that breaks a conforming consumer.
3. MSRV is 1.85.0, declared in `rust-version` and checked in CI.
4. Publishing is from a clean checkout with `cargo publish --dry-run` first, then
   the real publish, then the same tag pushed to both organizations' remotes.
5. A published version is never yanked without an ADR; withdrawal breaks content
   addressing for every replica that already stored modules.

## Consequences

- The crate version (1.1.0) and the format version (1.0) can diverge; tools
  report both.
- The name reservation is superseded by this release rather than replaced, which
  keeps crates.io history linear.
