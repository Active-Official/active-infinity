# ADR 0012 — Schema-class companion modules

Status: accepted for AIM-PROP-2026-10 C-3.1.

## Context

AINF is deliberately open and self-describing. Applications still need a way to
say "this module must have these fields with these types" without replacing the
open node model or moving identity into a schema registry.

## Decision

A schema is a **separate AINF module** whose root is an `Inode::SchemaTable`
containing `Inode::SchemaField` entries. The `schema` module exposes:

- `Schema::from_fields(&[(&str, TypeSpec)], closed)` — construct a top-level
  schema;
- `Schema::to_bytes` / `Schema::from_bytes` — canonical AINF round-trip;
- `Schema::validate_instance(&InfinityModule)` and `Schema::validate_bytes` —
  fail-closed instance validation.

A closed schema rejects unknown root fields. An open schema permits them. All
declared fields are required unless their `SchemaFieldSpec` carries a default
(a later additive extension). Type checks use the existing `TypeSpec` family:
null, bool, int, float, string, duration/quantity, bytes/blob, table, enum,
secret and any.

**Hash boundary:** the content hash is always over the canonical instance
bytes. The schema module has its own independent hash. A schema is evidence, not
identity; changing a schema never changes an instance's hash and never rewrites
the instance.

Nested schema recursion, numeric/length/pattern constraints and enum defaults
are additive extensions using the already-reserved schema field aux tags. They
do not require a wire version change.

## Consequences

- Instances remain readable without a schema.
- A verifier can pin both the instance hash and the schema hash.
- Schema errors are `infinity/schema`, a stable code.
- The public API is additive; existing `DecodeOpts` and validation are
  unchanged.
