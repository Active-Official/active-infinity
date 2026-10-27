# Active Infinity wire layout (`AINF`, format 1.0)

**Status:** normative. This document is the contract: an implementation that
disagrees with it is wrong, and the repository's `tests/doc_gate.rs` fails the
build when the prose and the code drift apart.

Active Infinity is the canonical binary form of an Active module. A module is an
arena of tagged nodes plus a root, name bindings, annotations, provenance and an
optional extension directory. Dependency edges are **derived** from node
children, never stored independently, so a module cannot carry a graph that
disagrees with its nodes.

- The magic is `AINF`.
- The format version is 1, with the minor number currently 0.
- The fixed header size is 224 bytes.
- The content hash is Blake3-256 over the whole canonical image with the hash
  field zeroed.
- Integers are little-endian. Floats are IEEE-754 binary64 bit patterns.
- Every section starts at an 8-byte aligned offset; the gap between sections is
  zero padding. The canonical image has no other slack.

---

## 1. Fixed header (224 bytes)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 4 | magic `41 49 4E 46` (`AINF`) |
| 4 | 2 | format major version (`1`) |
| 6 | 2 | format minor version (`0`) |
| 8 | 2 | header flags |
| 10 | 2 | header size (`224`) |
| 12 | 4 | reserved (zero) |
| 16 | 32 | content hash (Blake3-256) |
| 48 | 8 | dialect hash |
| 56 | 8 | total image size in bytes |
| 64 | 136 | 17 section descriptors, in the order of §2 |
| 200 | 24 | reserved (zero) |

Each section descriptor is `{ offset: u32, count: u32 }`. `count` is an element
count for fixed-stride sections and a byte length for `provenance`. For
`strings`, `blobs`, `secrets` and `extensions` the element count is stored and
the byte length is derived from the section body (§4).

### 1.1 Header flags

| Bit | Name | Meaning |
|----:|------|---------|
| 0 | `canonical` | the writer declares canonical form; a reader that relies on canonical identity must prove it by re-encoding (§6.1) |
| 1 | `annotations` | an annotation table is present |
| 2 | `provenance` | a provenance block is present |
| 3 | `extensions` | an extension directory is present |
| 4 | `streamed` | the module was reassembled from a stream |
| 5 | `secrets` | a secret table is present |
| 6..15 | reserved | must be zero |

The `canonical`, `annotations`, `provenance`, `extensions` and `secrets` flags
must agree with their sections: a section present without its flag, or a flag
without its section, is `infinity/annotation`, `infinity/provenance`,
`infinity/extension` or `infinity/secret-entry`.

### 1.2 Dialect hash

`dialect_hash = first 8 bytes of Blake3("active-infinity/dialect" || major ||
minor || unit-table-limit || node-kind-range || aux-tag-set)`.

A reader refuses a different dialect with `infinity/dialect` before parsing any
record. The dialect changes only when the meaning of an existing id changes,
which the versioning rules forbid (§10).

### 1.3 Content hash

The writer lays out the whole image with the 32-byte hash field zeroed, computes
Blake3-256 over every byte, and writes the digest into bytes 16..48. Readers
recompute and compare (`infinity/hash-mismatch`). Consequences:

- a single changed byte changes the hash;
- the hash is stable across runs, processes, machines and endianness;
- the hash is the module's content address and the unit of delta negotiation.

---

## 2. Section order

Sections appear in exactly this order, densely, each at `align8(previous end)`:

1. `nodes`
2. `children`
3. `fields`
4. `parts`
5. `edges`
6. `strings`
7. `blobs`
8. `annotations`
9. `provenance`
10. `extensions`
11. `units`
12. `types`
13. `aux`
14. `numbers`
15. `secrets`
16. `hashes`
17. `bindings`

The first section starts at 224. `total_size` is `align8` of the last section's
end, and the buffer length must equal `total_size` exactly
(`infinity/trailing-bytes`, `infinity/truncated`).

---

## 3. Node records (32 bytes)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | kind |
| 1 | 1 | flags |
| 2 | 2 | reserved (zero) |
| 4 | 4 | `aux` |
| 8 | 8 | `a` |
| 16 | 8 | `b` |
| 24 | 8 | `c` |

Unused fields must be zero. A non-zero unused field, an unused flag bit, or a
flag on a kind that defines none is `infinity/node`: nothing can hide in slack.

### 3.1 Kinds

| Kind | Name | `aux` | `a` | `b` | `c` | flags |
|-----:|------|-------|-----|-----|-----|-------|
| 0 | `Null` | — | — | — | — | — |
| 1 | `Bool` | — | `0` or `1` | — | — | — |
| 2 | `Int` | — | i64 bits | — | — | — |
| 3 | `Float` | — | f64 bits | — | — | — |
| 4 | `Str` | string id | — | — | — | — |
| 5 | `DurationMs` | — | milliseconds | — | — | — |
| 6 | `Quantity` | value node | unit index | — | — | — |
| 7 | `Array` | — | first child | count | — | — |
| 8 | `Table` | — | first field | count | — | — |
| 9 | `Secret` | — | secret index | — | — | — |
| 10 | `SecretRef` | — | locator node | — | — | — |
| 11 | `Ref` | — | node | — | — | — |
| 12 | `Env` | name string id | default node or `0xFFFF_FFFF` | — | — | — |
| 13 | `Ident` | string id | — | — | — | — |
| 14 | `Interpolate` | — | first part | count | — | — |
| 15 | `Binary` | binop code | lhs node | rhs node | — | — |
| 16 | `Unary` | unop code | expr node | — | — | — |
| 17 | `Constrained` | constraint kind | target node | aux start | aux count | — |
| 18 | `Patch` | patch kind | — | aux start | aux count | — |
| 19 | `SchemaField` | type index | — | aux start | aux count | — |
| 20 | `SchemaTable` | — | first field | count | — | bit 0 = closed |
| 21 | `SchemaArray` | — | element node | — | — | — |
| 22 | `Semantic` | tag (`0` prompt, `1` policy, `2` template) | inner node | — | — | — |
| 23 | `Blob` | media-type string id | blob index | size | — | bit 0 = tainted, bit 1 = payload present |
| 24 | `ContentAddressed` | — | media-type node | data node | — | — |

Kinds above 24 are refused with `infinity/node`.

`Secret` is a **kind**, not a bit: taint cannot be stripped by re-encoding.
Two secret values never compare equal; the secret table is never enumerated by
any projection.

### 3.2 Operator codes

`BinOp`: `0 +`, `1 -`, `2 *`, `3 /`, `4 ==`, `5 !=`, `6 <`, `7 <=`, `8 >`,
`9 >=`, `10 and`, `11 or`.
`UnOp`: `0 neg`, `1 not`.

### 3.3 Constraints and patches

Constraint kinds: `0 MinMax`, `1 Enum`, `2 Pattern`, `3 Odd`, `4 Custom`.
Aux tags inside a `Constrained` node:

| Tag | Meaning | Value |
|----:|---------|-------|
| 0 | `min` | numbers index |
| 1 | `max` | numbers index |
| 2 | enum member | string id |
| 3 | pattern | string id |
| 4 | custom payload | string id |

The aux payload must match the declared kind (an enum constraint has at least
one member; `Odd` has none; `Pattern`/`Custom` have exactly one).

Patch kinds: `0 Set`, `1 Remove`, `2 Rename`. Aux tags:

| Tag | Meaning | Value |
|----:|---------|-------|
| 10 | path (or rename source) | string id |
| 11 | value | node id |
| 12 | rename destination | string id |

### 3.4 Schema fields and types

`SchemaField` aux tags: `20 min`, `21 max`, `22 min_len`, `23 max_len`,
`24 pattern`, `25 default` (all node ids) and `26 deprecated` (string id).

Type records (16 bytes: `code`, `flags`, `aux start`, `aux count`):

| Code | Type | Aux |
|-----:|------|-----|
| 0 | `Null` | — |
| 1 | `Bool` | — |
| 2 | `Int` | — |
| 3 | `Float` | — |
| 4 | `String` | — |
| 5 | `Duration` | — |
| 6 | `Bytes` | — |
| 7 | `Table` | tag 31 with `0`/`1` closed flag |
| 8 | `Enum` | tag 30 per member (string id) |
| 9 | `Secret` | — |
| 10 | `Any` | — |
| 11 | `Blob` | — |

Flags are zero except for `Table`, where bit 0 carries `closed`.

---

## 4. Heaps and side tables

### 4.1 Children, fields, parts

- `children`: `u32` node ids.
- `fields`: 16 bytes `{ name string id, pad 0, node id, pad 0 }`.
- `parts`: 8 bytes `{ tag, value }` with tag `0` = literal (string id) and
  tag `1` = expression (node id).

`fields` are shared by `Table` and `SchemaTable`.

### 4.2 Strings

`strings` holds `count + 1` `u32` offsets followed by the heap. Offsets are
relative to the heap start; entry `i` is `[offset[i], offset[i+1])`. The table's
last offset equals the heap length. All strings are UTF-8 (`infinity/utf8`) and
strictly increasing in byte order (`infinity/offset`), so the heap is a sorted
set and interning is unambiguous. A zero-length heap means no strings; there is
then no offset table.

### 4.3 Blobs

`blobs` holds `count` entries of 40 bytes `{ Blake3-256 hash, payload offset,
payload length }` followed by the payload heap. Entry `i`'s payload offset is the
cumulative sum of the preceding lengths (no gaps). Entries are strictly
increasing by `(hash, offset, length)`.

A `Blob` node with the payload flag set must have `length == size` and
`Blake3(payload) == hash` (`infinity/blob`). A blob with the tainted flag must
not carry a payload: tainted identity travels without bytes.

### 4.4 Annotations

`count` records of 16 bytes `{ node id, kind, a, b }`:

| Kind | Name | `a` | `b` |
|-----:|------|-----|-----|
| 0 | `Intent` | string id | `0` |
| 1 | `Constraint` | source string id | expression node |
| 2 | `AiImmutable` | `0`/`1` | `0` |

Records are strictly increasing by `(node, kind, a, b)`.

### 4.5 Provenance

The `provenance` descriptor's `count` is a **byte length**. The block is:

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 4 | block version (`1`) |
| 4 | 4 | entry count |
| 8 | 8 | timestamp (Unix epoch milliseconds, `0` = unrecorded) |
| 16 | 4 | producer string id or `0xFFFF_FFFF` |
| 20 | 4 | model string id or `0xFFFF_FFFF` |
| 24 | 4 | tool string id or `0xFFFF_FFFF` |
| 28 | 4 | flags (bit 0 = parent hash present) |
| 32 | 32 | parent content hash (zero when absent) |
| 64 | 32 | reserved (zero) |
| 96 | … | entries, 16 bytes each `{ kind, key string id, a, b }` |

Entry kinds: `0` text (`a` = string id), `1` int (`a` = numbers index),
`2` flag (`a` = `0`/`1`), `3` hash (`a` = hashes index). `b` must be `0`.
Kinds `4` and above are **reserved**: a reader refuses them with
`infinity/provenance` rather than decoding a value that would re-encode as a
different kind. Entries are strictly increasing by key (provenance is a map, so
duplicate keys are refused). The block length must equal `96 + 16 * count`.

### 4.6 Extensions

`count` directory entries of 16 bytes `{ tag u64, payload offset u32, payload
length u32 }`, followed by payloads. Tags are unique and strictly increasing;
payload offsets are absolute image offsets, non-overlapping and inside the
section (`infinity/extension`). The directory ends where the first payload
begins, payloads are packed in tag order with each starting at the next
multiple of 8 (`align8(previous end)`, with zero padding in between), and the
last payload ends the section body: padding to the next section is zero. There
is no slack a reader could not account for. Tag `1` is reserved for future use
by this specification; other tags are application-defined and opaque to this
layer, so an implementation that does not understand a tag can still copy it
through unchanged.

### 4.7 Units

`count` records of 8 bytes `{ discriminant u32, name string id u32 }`.

Discriminants `0..=66` are built-in (§5.2) and their `name` field is `0`.
Discriminant `0xFFFF` is a named unit and `name` must point at a non-empty
string. Any other discriminant is `infinity/unknown-unit`. Records are strictly
increasing by `(discriminant, name)`.

### 4.8 Aux

`count` records of 8 bytes `{ tag u32, value u32 }`. Node records and type
records index into this table; every tag is validated against its consumer.
Known tags: 0, 1, 2, 3, 4 (constraints), 10, 11, 12 (patches), 20–26 (schema
fields), 30, 31 (types).

### 4.9 Numbers

`count` `i64` values, strictly increasing. Constraint bounds and integer
provenance values reference entries by index.

### 4.10 Secrets

`count` records of 8 bytes `{ heap offset u32, length u32 }` followed by the
secret heap. Offsets are cumulative from `0` (no gaps). The heap holds the raw
secret bytes and is never enumerated by any export, projection or diagnostic.
Secret entries are *not* deduplicated: identical secrets occupy distinct table
entries so table layout cannot become an equality oracle.

### 4.11 Hashes

`count` 32-byte digests, strictly increasing. Provenance hash entries reference
entries by index.

### 4.12 Bindings

`count` records of 8 bytes. Record 0 is the module index:
`{ root node id or 0xFFFF_FFFF, reserved 0 }`. Records 1.. are
`{ name string id, node id }`, strictly increasing by name.

---

## 5. Identity tables

### 5.1 Node kinds

See §3.1. Kind ids are permanent.

### 5.2 Unit discriminants

| Id | Unit | Id | Unit | Id | Unit |
|---:|------|---:|------|---:|------|
| 0 | nanoseconds | 23 | requests-per-minute | 46 | petaflops |
| 1 | microseconds | 24 | requests-per-hour | 47 | pascal |
| 2 | milliseconds | 25 | percent | 48 | bar |
| 3 | seconds | 26 | hertz | 49 | psi |
| 4 | minutes | 27 | kilohertz | 50 | volts |
| 5 | hours | 28 | megahertz | 51 | amperes |
| 6 | days | 29 | gigahertz | 52 | watts |
| 7 | weeks | 30 | terahertz | 53 | joules |
| 8 | bytes | 31 | bits | 54 | kilowatt-hours |
| 9 | kibibytes | 32 | kilobits | 55 | newtons |
| 10 | mebibytes | 33 | megabits | 56 | degrees |
| 11 | gibibytes | 34 | gigabits | 57 | radians |
| 12 | tebibytes | 35 | bits-per-second | 58 | rpm |
| 13 | pebibytes | 36 | kilobits-per-second | 59 | meters |
| 14 | exbibytes | 37 | megabits-per-second | 60 | kilometers |
| 15 | kilobytes | 38 | gigabits-per-second | 61 | kilograms |
| 16 | megabytes | 39 | megabytes-per-second | 62 | grams |
| 17 | gigabytes | 40 | tokens | 63 | kelvin |
| 18 | terabytes | 41 | kilo-tokens | 64 | celsius |
| 19 | per-second | 42 | mega-tokens | 65 | fahrenheit |
| 20 | per-minute | 43 | tokens-per-second | 66 | decibel |
| 21 | per-hour | 44 | flops | `0xFFFF` | named unit |
| 22 | requests-per-second | 45 | teraflops | | |

Ids 0–18 are quantities of a dimension; 19–46 are rates, ratios and AI-age
units; 47–66 are domain SI units. Absolute temperatures (63–65) and decibels
(66) keep their non-arithmetic property from the text language.

---

## 6. Canonical form

A canonical image is produced by this exact procedure, and re-canonicalizing a
canonical image reproduces it byte for byte:

1. **Normalize nodes.** Table fields and schema-table fields are sorted by key.
   `-0.0` becomes `+0.0`; every NaN becomes the quiet NaN
   `0x7ff8_0000_0000_0000`.
2. **Promote secret locators.** A string literal that is referenced only by
   secret nodes and is not a root is re-encoded as a `Secret` node, so the
   literal moves out of the public string heap.
3. **Number nodes.** Pre-order depth-first from the roots — the module root,
   then bindings in name order, then annotation subjects and their constraint
   expressions. Children are visited in node order (§3.1), which is itself
   canonical after step 1. Nodes unreachable from the roots are **dropped**; a
   canonical image never carries hidden data.
4. **Sort tables.** Strings (byte order), units (`(discriminant, name)`), types
   (`(code, flags, aux start, aux count)`), blobs (`(hash, size)`), hashes,
   numbers, annotations, provenance entries, extensions (tag) and edges are
   sorted and deduplicated. Secrets are ordered by node order and not
   deduplicated.
5. **Derive edges.** For every node, each child contributes `(child, node)`.
   The resulting table is sorted and deduplicated. It must equal the stored
   edge table exactly (`infinity/edge`).
6. **Lay out.** Sections in §2 order, zero padding, then hash.

Consequences, all tested:

- logically equal modules have identical bytes and identical hashes;
- construction order, arena order and field insertion order are irrelevant;
- a decoded canonical module re-encodes to the same bytes;
- every node in a valid image is reachable from a root (`infinity/node`,
  reason `unreachable node`).

### 6.1 Proving canonical form

The `canonical` flag is a **claim by the writer**, not a fact a parser can take
on trust. Structural validation never decodes and re-encodes, because that would
double the work an attacker can force with a single request; canonicality is
therefore an explicit, separate proof:

- `validate` / `validate_with` check structure, ranges, ordering, reachability,
  acyclicity, depth and the content hash. They accept a structurally valid image
  whose bytes are not the canonical encoding of their own content.
- `validate_canonical` (or `DecodeOpts { verify_canonical: true, .. }`) decodes,
  re-encodes and compares. A declared-canonical image that differs is
  `infinity/not-canonical`. `DecodeOpts::paranoid()` enables this together with
  the strict limits, and is the profile for untrusted network input.

An image produced by this crate's encoder is always canonical, so a receiver
that re-encodes before storing or forwarding never propagates a lie. A receiver
that uses the flag for deduplication, caching or signatures must prove it first;
the content hash alone is computed over the bytes actually received and is
therefore safe without the proof.

---

## 7. Validation classes

Validation is total and fail-closed. It runs in this order and stops at the
first failure:

1. magic, versions, header size, header flags, reserved words
   (`infinity/magic`, `infinity/version-major`, `infinity/version-minor`,
   `infinity/header-size`, `infinity/flags`, `infinity/reserved`);
2. dialect (`infinity/dialect`);
3. counts against `Limits` (`infinity/limit`) and against the buffer size
   (`infinity/count`);
4. total size and section ranges, alignment, order, padding
   (`infinity/truncated`, `infinity/trailing-bytes`, `infinity/offset`,
   `infinity/padding`);
5. flag/section agreement;
6. strings (`infinity/utf8`, `infinity/offset`), units
   (`infinity/unknown-unit`, `infinity/unit-ref`), types (`infinity/type`),
   numbers and hashes (ordering), secrets (`infinity/secret-entry`), blobs
   (`infinity/blob`);
7. node records (`infinity/node`, `infinity/string-ref`, `infinity/node-ref`,
   `infinity/duplicate-field`), fields (padding), parts (tags), edges
   (`infinity/edge`), annotations (`infinity/annotation`), provenance
   (`infinity/provenance`), extensions (`infinity/extension`);
8. reachability and binding order (`infinity/node`, `infinity/duplicate-binding`);
9. acyclicity (`infinity/cycle`);
10. depth (`infinity/depth`);
11. content hash (`infinity/hash-mismatch`);
12. optional canonical re-encode (`infinity/not-canonical`).

Traversal is iterative: a 4-million-node chain must not overflow the stack.
Allocation is bounded by the validated counts, never by header claims.

---

## 8. Streaming

See `docs/spec/streaming.md`. Frames carry the canonical sections, so a
reassembled generation is byte-identical to the whole-module encoding and has
the same content hash. Deltas are semantic and re-canonicalize.

---

## 9. Error codes

Codes are permanent and machine-readable; agents branch on them, never on
messages. Every code below is part of the contract.

| Code | Condition |
|------|-----------|
| `infinity/magic` | input does not start with `AINF` |
| `infinity/version-major` | unsupported major version |
| `infinity/version-minor` | unsupported minor version |
| `infinity/header-truncated` | shorter than the fixed header |
| `infinity/header-size` | header size field is not 224 |
| `infinity/flags` | unknown header flag bits |
| `infinity/reserved` | non-zero reserved field |
| `infinity/offset` | section offset/range invalid, misaligned, out of order, or a string heap offset fault |
| `infinity/truncated` | buffer shorter than the declared sections |
| `infinity/trailing-bytes` | bytes after the declared image |
| `infinity/count` | a count field cannot be satisfied by the buffer |
| `infinity/padding` | non-zero padding between sections |
| `infinity/hash-mismatch` | content hash does not match |
| `infinity/dialect` | dialect hash not implemented |
| `infinity/not-canonical` | declared canonical but re-encoding differs |
| `infinity/string-ref` | dangling string id |
| `infinity/node-ref` | dangling node id |
| `infinity/node` | node record violates its kind contract |
| `infinity/utf8` | invalid UTF-8 in the string heap |
| `infinity/unknown-unit` | unit discriminant not implemented |
| `infinity/unit-ref` | dangling unit reference |
| `infinity/type` | malformed type record |
| `infinity/edge` | invalid, unsorted or forged edge table |
| `infinity/annotation` | malformed annotation record |
| `infinity/provenance` | malformed provenance block |
| `infinity/extension` | malformed or overlapping extension block |
| `infinity/blob` | malformed blob entry or payload mismatch |
| `infinity/secret-entry` | malformed secret entry or flags disagree |
| `infinity/duplicate-field` | repeated table field name |
| `infinity/duplicate-binding` | repeated or unsorted binding name |
| `infinity/cycle` | dependency cycle |
| `infinity/depth` | nesting deeper than the configured limit |
| `infinity/limit` | a configured `Limits` ceiling was exceeded |
| `infinity/invalid-argument` | caller-supplied argument outside its range |
| `infinity/encode` | module cannot be encoded (dangling reference, tainted blob with payload, ...) |
| `infinity/encode-dangling` | encoding referenced a missing node |
| `infinity/too-large` | image exceeds the 4 GiB address space |
| `infinity/stream-magic` | frame does not start with `AINS` |
| `infinity/stream-version` | unsupported frame version |
| `infinity/stream-frame-len` | frame length exceeds its ceiling or the buffer |
| `infinity/stream-frame-kind` | unknown frame kind |
| `infinity/stream-sequence` | frame out of order |
| `infinity/stream-state` | frame illegal in the current stream state |
| `infinity/stream-hash` | reassembled hash disagrees with the end frame |
| `infinity/stream-delta` | delta cannot be applied |
| `infinity/stream-unterminated` | stream ended without an end frame |

Messages never echo payload bytes, so a malformed buffer cannot turn an error
report into a leak channel.

---

## 10. Versioning

- The **major** version changes when any documented byte layout changes. Readers
  refuse an unknown major.
- The **minor** version changes for additive, skippable features. This reader
  refuses a newer minor instead of guessing.
- Existing kind ids, unit discriminants, aux tags, operator codes and error
  codes are never reused or renumbered.
- New units are added as named units until the built-in table is revised in a
  major version.
- The dialect hash pins the exact semantic tables, so a peer refuses a module
  from an incompatible build before parsing a single record.

---

## 11. Limits

`Limits` bounds nodes, edges, children, fields, parts, strings, string bytes,
blobs, blob bytes, annotations, units, types, aux, numbers, secrets, secret
bytes, extensions, provenance entries, total bytes and depth. The total-byte and
string-heap ceilings are checked before anything is decoded, and the depth
ceiling applies to **every** root (module root, bindings, annotation subjects) —
a second shallow root cannot hide a deep chain. Defaults accept
real modules (millions of nodes) and refuse bombs; `Limits::strict()` is the
profile for adversarial surfaces. There is no unlimited mode: `0` in a ceiling
is rejected with `infinity/invalid-argument`.

---

## 12. What a valid image guarantees

For a buffer that passes `validate`:

1. every byte is accounted for, and slack is zero;
2. no reference is dangling and no count can over-allocate;
3. the dependency graph is acyclic, every node is reachable, and the stored edge
   table is exactly the derived one;
4. the content hash matches the payload;
5. no secret is reachable through `Debug`, `Display`, `Serialize`, a diagnostic
   or a projection;
6. a zero-copy view can hand out borrowed strings, blobs and records without
   copying, without alignment requirements and without `unsafe`.
