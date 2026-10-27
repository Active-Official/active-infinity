# ADR-0001 — Purpose of Active Infinity

**Status:** accepted (2026-10-27)

## Context

Active has a text surface with a rich semantic model: an arena IR with an
explicit dependency graph, units, structural secrets, budgets, annotations and
schema. Nothing in that model survives a trip through JSON, YAML, TOML or a
generic binary encoder: numbers lose their unit, secrets become strings, the
graph becomes tree-shaped data, and identity becomes "whatever key order the
writer chose".

Agents make the gap worse. An agent that receives a module wants to ask *what
depends on this value*, *why does it have this value*, *what is secret here*,
and *do I already have a copy* — and none of those questions is answerable from
a JSON document without re-parsing and heuristics.

## Decision

Active Infinity is the canonical binary form of an Active module:

- an arena of tagged nodes with a derived, validated dependency graph;
- permanent unit discriminants, including Active's AI-age units;
- structural secrets that cannot be stripped or compared;
- annotations and provenance as first-class data;
- a deterministic canonical form with a Blake3 content address;
- a bounded, fail-closed validator and safe zero-copy views;
- streaming frames that reproduce the canonical bytes exactly.

It is a separate crate from the Active monorepo: it depends on the language's
IR, not the other way round.

## Consequences

- Text Active stays the authoring surface; Infinity is the storage, network and
  agent-exchange surface.
- Every semantic feature of the language must be representable, or explicitly
  refused (blob identity in `active-core` 1.4.0 is refused, ADR-0002).
- Content addressing enables delta negotiation ("I already have hash H") and
  signed module distribution without a second format.
