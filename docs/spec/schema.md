# Schema-class companion modules

Status: additive, AIM-PROP-2026-10 C-3.1/C-3.2.

AINF remains open and self-describing. A **schema** is a separate canonical
module whose root is `SchemaTable` and whose fields are `SchemaField` nodes.
The schema never replaces the instance and never changes the instance hash.

## API

- `Schema::from_fields(&[(&str, TypeSpec)], closed)`
- `Schema::to_bytes` / `Schema::from_bytes`
- `Schema::validate_instance(&InfinityModule)` / `validate_bytes`
- `Schema::field_names`, `is_closed`, `module`, `root`

## Semantics

- Every declared field is required unless its `SchemaFieldSpec` has a default.
- A closed schema rejects unknown root fields; an open schema permits them.
- Types use the existing `TypeSpec`: null, bool, int, float, string,
  duration/quantity, bytes/blob, table, enum, secret, any.
- A failure is `infinity/schema` and is fail-closed.
- The instance hash covers the canonical instance bytes. The schema has its own
  hash. A verifier may pin both; a schema change never rewrites the instance.

## Limits

Nested schema recursion, numeric/length/pattern constraints and defaults are
reserved additive extensions using the schema aux tags. Until they are
implemented, a nested `TypeSpec::Table` checks only that the value is a table.
