# Projections: JSON and Protobuf

Active Infinity is the canonical form, and Active peers should exchange it. Two
projections exist for the world outside Active: a redacted JSON document for
humans, logs and legacy consumers, and a Protobuf wire encoding for typed
clients in other languages. Both are **lossy by design** and neither can carry
secret material.

Normative rules for the AINF image itself are in [layout.md](layout.md); this
document covers the projections only.

---

## 1. Shared redacted tree

Both projections render one intermediate tree, built by
`interop::project_root`:

| Projected value | JSON | Protobuf field |
|---|---|---|
| null | `null` | `Value.null_value` |
| boolean | `true` / `false` | `Value.boolean` |
| integer | number | `Value.integer` (`sint64`, zig-zag) |
| float | number | `Value.float` (IEEE-754, little-endian) |
| text | string | `Value.text` |
| duration | `{"ms": n}` | `Value.duration_ms` |
| quantity | `{"value": v, "unit": "u"}` | `Value.quantity` |
| array | array | `Value.list` |
| table | object | `Value.record` (ordered `Field` messages) |
| blob | `{"$active.blob": {...}}` | `Value.blob` (identity only) |
| environment lookup | `{"$env": "NAME"}` | `Value.env` |
| operator, schema, patch | `{"$expr": "<kind>"}` | `Value.expr` |
| secret | `"***SECRET***"` | `Value.text` = `***SECRET***` |

Because the renderers consume the same tree, they cannot disagree about what is
allowed to leave the process. A new node kind must be handled once, in the
builder, and both projections gain it.

## 2. Redaction

Redaction is structural, not textual:

- a secret node projects as the marker; its bytes never reach a renderer;
- a text value that **contains** a secret literal becomes the marker as a whole,
  so a partial copy cannot leak;
- a table key or a provenance key that contains a secret has each occurrence
  replaced, so a key cannot smuggle a copy;
- a blob projects its identity only (hash, size, media type, taint); its payload
  is never rendered, and a tainted blob's media type is replaced by the marker;
- an interpolated string whose expression part is secret projects as the marker
  even though the literal parts are public.

The test suite asserts that the secret literal does not appear anywhere in the
projected bytes.

## 3. JSON

`interop::to_redacted_json` and `to_redacted_json_pretty` return the root value.
Properties consumers depend on:

- deterministic output: canonical field order from the module, no maps with
  unstable iteration;
- `$`-prefixed keys are reserved for projection markers (`$env`, `$expr`,
  `$active.blob`), so data can never impersonate a marker;
- numbers are emitted as JSON numbers; integers that exceed the IEEE-754 exact
  range are still emitted as integers (a consumer that needs exactness reads the
  binary form).

## 4. Protobuf

`to_protobuf` (`active_infinity::to_protobuf`) returns a `Module` message. The
full schema is in the [module documentation](../src/protobuf.rs) and repeated
here for reviewers:

```proto
syntax = "proto3";
package active.infinity.v1;

message Module {
  bytes content_hash = 1;    // Blake3-256 of the canonical AINF image
  uint64 total_size = 2;     // canonical AINF image size in bytes
  Value root = 3;            // omitted when the module has no root
  repeated Binding bindings = 4;
  Provenance provenance = 5; // omitted when absent
  repeated Annotation annotations = 6;
  repeated Extension extensions = 7;
}

message Binding { string name = 1; Value value = 2; }

message Annotation {
  uint32 subject = 1;
  oneof kind {
    string intent = 2;
    Constraint constraint = 3;
    bool ai_immutable = 4;
  }
}
message Constraint { string source = 1; uint32 expr = 2; }

message Provenance {
  string producer = 1;
  uint64 timestamp_ms = 2;
  string model = 3;
  string tool = 4;
  bytes parent = 5;
  repeated Entry entries = 6;
  message Entry {
    string key = 1;
    oneof value {
      string text = 2;
      sint64 integer = 3;
      bool flag = 4;
      bytes hash = 5;
    }
  }
}

message Extension { uint64 tag = 1; bytes payload = 2; }

message Value {
  oneof kind {
    Null null_value = 1;
    bool boolean = 2;
    sint64 integer = 3;
    double float = 4;
    string text = 5;
    Ms duration_ms = 6;
    Quantity quantity = 7;
    List list = 8;
    Record record = 9;
    Blob blob = 10;
    Env env = 11;
    Expr expr = 12;
  }
}
message Null {}
message Ms { uint64 ms = 1; }
message Quantity { Value value = 1; string unit = 2; }
message List { repeated Value items = 1; }
message Record { repeated Field fields = 1; }
message Field { string name = 1; Value value = 2; }
message Blob { bytes blake3 = 1; uint64 size = 2; string media_type = 3; bool tainted = 4; }
message Env { string name = 1; }
message Expr { string kind = 1; }
```

### 4.1 Encoding rules

- Fields are emitted in ascending field-number order.
- Scalar fields are emitted even when they equal the proto3 default, so the
  encoding is injective for the projected tree and a diff is meaningful.
- Absent optional messages (`root`, `provenance`) and empty repeated fields are
  omitted.
- Varints are minimal, `sint64` is zig-zag, `double` is little-endian IEEE-754,
  and length prefixes are exact.
- Projecting the same module twice produces identical bytes.

### 4.2 Compatibility

Field numbers are permanent: they are never reused or renumbered. New fields are
additive and take the next free number, so a reader built against this version
skips what it does not know. Removing a field retires its number. The value
oneof follows the same rule; kinds are never renumbered.

### 4.3 What the projection is not

The Protobuf form is a **view**, not a second canonical form. Content addressing,
signatures and streaming all use the AINF image. A consumer that needs to verify
what it received fetches the AINF bytes, checks them with `validate` or
`validate_canonical`, and compares the hash with `Module.content_hash`.

## 5. Depth and refusals

A projection follows the graph recursively. It refuses, rather than approximates:

- a module deeper than 1024 edges from a projected node
  (`infinity/encode`, reason `projection nesting exceeds the limit`);
- a module with a cycle, a dangling reference, a duplicate binding or a
  duplicate field name, because `to_protobuf` requires a canonical image.

A refused projection returns an error; it never emits a truncated tree.
