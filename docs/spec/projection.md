# Projections: JSON and Protobuf

Active Infinity is the canonical form, and Active peers should exchange it. Two
projections exist for the world outside Active: a redacted JSON document for
humans, logs and legacy consumers, and a Protobuf wire encoding for typed
clients in other languages. Both are **lossy by design** and neither can carry
secret material.

Normative rules for the AINF image itself are in [layout.md](layout.md); this
document covers the projections only.

---

## 0. Authority

- The **AINF image is the system of record**. Its content hash is Blake3 over
  the canonical bytes; nothing in this document changes that address.
- A projection is a derived, lossy view and is **unauthenticated**. Editing the
  JSON or the Protobuf changes only the view: it never becomes the identity of
  the module and never overrides the hash.
- To verify a module, validate the AINF bytes (`validate_canonical`) and compare
  the content hash. A projection cannot be re-addressed as an image, and
  `validate` rejects projection bytes.
- Secrets never enter either projection: the redaction pass in §2 replaces them
  before any renderer runs.
- A consumer that treats a projection as authoritative has stepped outside this
  specification. Interop bridges may carry projections, but the AINF bytes and
  their hash remain the reference.

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
- **data text** in a projection that contains a secret literal becomes the marker
  as a whole, so a partial copy cannot leak. This covers string values,
  provenance producer/model/tool and text entries, intent annotations and
  constraint sources;
- **the canonical image** redacts metadata prose (annotations, provenance) with
  the *storage* rule: each occurrence is replaced, which keeps the surrounding
  prose usable for local consumers. `interop::intents` applies the same rule, so
  its answer for an in-memory module matches what a decoded module yields;
- **labels** (table field names, binding names, identifier names, unit names,
  environment names, media types and provenance keys) have each occurrence
  replaced in a projection, because a label is an identifier rather than a
  document and whole-value replacement would erase it entirely for every
  consumer;
- the rule has **no length threshold**: a one- or two-byte secret is redacted
  exactly like a long one. Redaction in canonicalization follows the same
  no-threshold rule, so a copy cannot survive in the image and then be hidden
  only by the projections;
- a replacement can create a new secret by joining the text around it, so the
  canonicalizer repeats the pass until the text is clean. When the marker itself
  contains a secret, no marker can hide it: the encoder refuses a *stored*
  metadata string that contains it (`infinity/encode`), and the paths that
  cannot refuse substitute the empty string (`redact_text` and the JSON
  projection);
- **fragments of an interpolated locator** (`secret("hunter-${name}")`) move to
  the secret heap but are not stored-metadata redaction targets: rewriting a
  one-byte fragment would destroy the prose. A metadata string that contains one
  is therefore refused (`infinity/encode`, reason "a secret fragment occurs in
  ..."), which keeps the canonical image a fixed point. The fragments are still
  hidden by every export;
- **binary surfaces are not text.** A provenance `parent` or hash entry whose
  bytes equal a 32-byte secret, and an opaque extension payload that contains a
  secret literal, cannot use the marker: there is no textual form to replace.
  The encoder refuses such a module (`infinity/encode`); a projection of a
  hand-built module that was never encoded substitutes the marker for a matching
  hash and refuses a matching extension payload. The copy therefore never
  reaches a stored image or a projection.
- **the `active-core` bridge refuses a secret-bearing module**
  (`infinity/encode`). `active-core` 1.4.0 models a secret as a plain string, so
  lowering one would export the plaintext to every consumer of the bridge.
- reference wrappers are transparent: an interpolated `${ref_to_secret}` redacts
  the whole string instead of rendering `${}`;
- a blob projects its identity only (hash, size, media type, taint); its payload
  is never rendered, and a tainted blob's media type is replaced by the marker;
- an extension payload is opaque, so the Protobuf projection **refuses** a
  module whose payload contains a secret literal rather than shipping the copy
  (`infinity/encode`, reason `extension payload carries secret material`).

Structural names are the exception, in both directions:

- the canonical image **does not rewrite** table field names, binding names,
  unit names, environment names, identifier names or blob media types. They are
  part of the module's identity: rewriting them would change what the module
  means, and two names that collapse onto the marker would create a duplicate
  field the encoder must refuse.
- the projections **do redact** those names, because an export must not carry a
  copy. A projection is therefore lossy for a module that embeds a secret inside
  such a name; a consumer that needs the exact names reads the AINF image
  instead.
- two names that redact to one key are **refused** (`infinity/encode`) rather
  than merged: a JSON object with duplicate keys loses one silently, and a
  lossy export is worse than a loud refusal. The same rule applies to bindings.
- the provenance exports follow the same rule: `provenance_json_for` returns
  `None` on a redacted-key collision, and `provenance_lines` keeps the first
  entry (in stored key order), so the two exports cannot disagree about which
  value the module holds.
- a data key that starts with `$` is escaped with a leading `$` (`$env` becomes
  `$$env`) so module data cannot impersonate a projection marker such as
  `{"$env": ...}` or `{"$active.blob": ...}`.

Metadata prose (annotations, provenance and schema-field deprecation notes) is
redacted in the image itself, before the string heap is collected, with each
occurrence replaced, so a copy cannot be stored there either. String *values*
are user data: they are stored as written and redacted only when they leave
through a projection.

The test suite asserts that the secret literal does not appear anywhere in the
projected bytes.

Two limits are documented rather than hidden:

- A non-finite float is `null` in JSON (JSON has no NaN or infinity) and a real
  IEEE double in Protobuf. A consumer that needs to tell `null` from NaN reads
  the AINF image or the Protobuf form.
- The copy gate compares a hash against a secret **by value**. A 1-31 byte
  secret embedded inside a 32-byte hash is only caught when it happens to equal
  the whole value; finding it would require a substring search of every hash
  against every secret at encode time. Use a 32-byte secret, or a keyed hash,
  when a hash could carry a copy.

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
- The projection is built from the **canonical module** — the decode of its own
  encoded image — so bindings, annotations and extensions come out in canonical
  order and two logically equal modules (same AINF bytes, same hash) project to
  identical bytes.

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

### 4.4 Envelope difference from JSON

The two projections render the same tree but not the same envelope. JSON is the
module's **root value**: the shape a legacy consumer expects, with no module
metadata. Protobuf is the **module**: root, bindings, annotations, provenance,
extensions, content hash and size. A consumer that needs the metadata reads the
Protobuf form; a consumer that needs only the document reads JSON. Neither
projection is a complete copy of the AINF bytes, and neither is meant to be.

## 5. Depth and refusals

A projection follows the graph recursively. It refuses, rather than approximates:

- a module deeper than 1024 edges from a projected node
  (`infinity/encode`, reason `projection nesting exceeds the limit`);
- a module with a cycle, a dangling reference, a duplicate binding or a
  duplicate field name, because `to_protobuf` requires a canonical image.

A refused projection returns an error; it never emits a truncated tree.

Two resource ceilings turn a hostile module into a refusal instead of a stall:

- the shared node budget (`PROJECTION_NODE_BUDGET`, 100 000 visits) covers the
  value tree *and* every secret-taint walk, so a hostile interpolation shape
  cannot spend an unbounded number of lookups; it reports `infinity/limit`;
- the Protobuf output is capped at `MAX_PROTOBUF_BYTES` (1 GiB) and the
  extension secret scan at `MAX_SECRET_SCAN_BYTES` (64 MiB of comparisons), both
  `infinity/limit`;
- the non-projection exports — `provenance_lines`, `provenance_json_for`,
  `value_paths` and `intents` — share one `EXPORT_REDACTION_BUDGET` (64 MiB of
  scan bytes). They return text rather than a `Result`, so the placeholder is
  computed once per export and every remaining value saturates to it. A key has
  no substitute that keeps its meaning, so the provenance exports stop emitting
  entries when the budget is spent; a spent budget never invents a key and never
  reports the provenance block absent. A caller that needs a refusal uses the
  JSON or Protobuf projection.
- `value_paths` bounds its own material: at most `MAX_EXPORT_PATH_BYTES`
  (16 MiB) of dotted-path text and `MAX_EXPORT_PATH_DEPTH` (64) segments, then
  a node keeps a short `@node[id]` label. A path copies its parent's prefix, so
  a deep comb is otherwise quadratic.
- annotation ordering keys are bounded in total (`MAX_ANNOTATION_KEY_BYTES`,
  64 MiB of rendered subtree); past it the encoder refuses with
  `infinity/limit`. See `layout.md` §3.
