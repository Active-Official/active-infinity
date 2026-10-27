# ADR-0002 — Relationship to `active-core` and wire-format independence

**Status:** accepted (2026-10-27)

## Context

`active-core` exposes `Module` with `arena: Vec<Node>`, a `petgraph` dependency
graph, `indexmap` tables and a unit enum. The obvious shortcut is to mirror that
enum in the wire format, one node kind per Rust variant, and be done.

That shortcut couples the bytes to a dependency's semver. Adding a node kind,
renaming a unit or reordering a struct in `active-core` would silently change
what a stored or transmitted module means. It also makes `active-infinity`
unusable on modules produced by an older peer.

## Decision

1. The wire format is defined by `docs/spec/layout.md` alone. Node kinds, unit
   discriminants, aux tags, operator codes and error codes are permanent ids in
   that document.
2. `active-infinity` owns its IR (`InfinityModule`) and its own unit enum
   (`UnitTag`). The mapping to `active-core` is an explicit, auditable bridge in
   `src/interop.rs`.
3. The bridge depends on the published `active-core = "1.4.0"`. The local
   workspace copy is newer than the published crate; the published crate is the
   contract consumers get, so the code is compiled and tested against it.
4. Conversion is total in one direction (every `active-core` 1.4.0 node kind is
   representable) and explicit in the other: Infinity features with no
   `active-core` 1.4.0 counterpart (blob identity, the `Blob` schema type) are
   refused with a stable error rather than degraded into something that looks
   equal and is not.
5. The private dependency is optional (`active-core` feature, default on). With
   `--no-default-features` the crate is a self-contained codec.

## Consequences

- A new `active-core` release does not change the wire format; it only extends
  the bridge, which is covered by round-trip tests.
- Two Infinity peers at different `active-core` versions interoperate as long
  as their *dialect hash* matches.
- Upgrading the bridge is deliberate: bump the dependency, run the integration
  suite, and record any behavioural difference.
