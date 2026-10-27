# Active Infinity (Active ∞)

**The canonical binary form of Active modules.** Graph-native, unit-aware,
secret-safe, content-addressed, zero-copy to read and streaming to ship — built
for configuration, for data exchange, and for agents that exchange modules with
each other.

```text
AINF ──► validate (bounded, fail-closed) ──► view (zero copy) ──► evaluate
  ▲                                            │
  └──────────── canonical encode ◄─────────────┘   same bytes, same Blake3 hash
```

## Why it exists

JSON is a text format with no integers-versus-floats rule, no units, no graph, no
identity and no way to tell a secret from a string. YAML adds ambiguity. Cap'n
Proto and FlatBuffers give you bytes but not semantics: no units, no taint, no
canonical content address, no graph queries.

Active Infinity is the serialization of the *Active* language model, which already
has those things:

- **Canonical**: one logical module has exactly one byte image and one Blake3
  content address. Two modules that describe the same values hash identically.
- **Graph-native**: dependency edges are derived from nodes and validated, so
  `why`, `impact` and subgraph queries run on the binary form.
- **Unit-aware**: quantities carry a permanent unit discriminant, including
  Active's AI-age units (tokens, tokens/second, FLOPS).
- **Secret-safe**: a secret is a *kind*, not a flag. It never equals anything,
  never appears in `Debug`/`Display`/JSON/diagnostics, and literal locators are
  moved out of the public string heap at canonicalization.
- **Zero-copy**: a validated buffer hands out borrowed strings and blobs with no
  copy, no alignment requirement and no `unsafe`.
- **Streaming**: frames carry the canonical sections plus semantic deltas, so a
  reassembled stream is byte-identical to the whole-module encoding.
- **Fail-closed**: a bounded, iterative validator rejects truncation, count
  bombs, bad offsets, invalid UTF-8, unknown units, cycles, unreachable nodes and
  hash mismatches with permanent machine-readable codes.

## Quick start

```rust
use active_infinity::{encode, decode, validate, content_hash, InfinityModule, Inode};

let mut module = InfinityModule::new();
let greeting = module.push(Inode::Str("hello".into()));
let answer = module.push(Inode::Int(42));
let root = module.push(Inode::Table {
    fields: vec![("greeting".into(), greeting), ("answer".into(), answer)],
});
module.set_root(Some(root));

let bytes = encode(&module)?;          // canonical image
let meta = validate(&bytes)?;          // bounded, fail-closed
let decoded = decode(&bytes)?;         // equal values
let hash = content_hash(&bytes)?;      // content address
assert_eq!(encode(&decoded)?, bytes);  // re-encoding is byte-identical
# Ok::<(), active_infinity::Error>(())
```

From the Active text language (feature `active-core`, on by default):

```rust
use active_infinity::interop::{from_active_source, to_redacted_json};

let source = "port = 8080\npassword = secret(\"hunter2\")\n";
let module = from_active_source(source, "app.active")?;
let bytes = active_infinity::encode(&module)?;
let json = to_redacted_json(&module)?;
assert!(!json.contains("hunter2"));
# Ok::<(), active_infinity::Error>(())
```

Run the shipped examples:

```bash
cargo run --example roundtrip        # encode/decode/hash/stream demo
cargo run --example agent_queries    # why / impact / taint over a binary module
cargo run --example generate_vectors # regenerate the conformance vectors
```

## Format at a glance

| Property | Value |
|---|---|
| Magic | `AINF` |
| Format | 1.0 (major 1, minor 0) |
| Header | 224 bytes, 17 section descriptors |
| Node record | 32 bytes, 25 kinds |
| Hash | Blake3-256 over the canonical payload with the hash field zeroed |
| Canonical | sorted tables, pre-order numbering, zero slack |
| Endianness | little, alignment 8 |

The normative specification is [`docs/spec/layout.md`](docs/spec/layout.md);
streaming is [`docs/spec/streaming.md`](docs/spec/streaming.md); the threat model
is [`docs/spec/security.md`](docs/spec/security.md); projections for consumers
outside Active are [`docs/spec/projection.md`](docs/spec/projection.md).

## Projections

A consumer that does not speak AINF can still read a module, and it can never
read a secret through the projection.

```rust
use active_infinity::{to_protobuf, InfinityModule};

let module = InfinityModule::new();
let protobuf = to_protobuf(&module)?;                 // typed, for other languages
let json = active_infinity::interop::to_redacted_json(&module)?;
```

Both projections render the same redacted tree, so they cannot disagree about
what is safe to expose. The protobuf message carries the canonical content hash,
which a consumer can use to fetch and verify the authoritative bytes.

## Feature flags

| Feature | Default | Meaning |
|---|---|---|
| `active-core` | on | bridge to the Active text language IR (`from_active_core`, `to_active_core`, `evaluate`) |
| `json` | on | redacted JSON projection (`to_redacted_json`) |

`--no-default-features` builds a dependency-free wire codec (Blake3 and
`thiserror` only).

## Testing

```bash
cargo test                     # unit, integration, property, conformance, red team
cargo test --no-default-features
cargo bench                    # codec baselines
cargo +nightly fuzz run decode -- -runs=200000
```

The conformance set under `tests/vectors/` is checked in: valid images with
their expected hashes and invalid images with the exact error code each must
produce. Regenerate with `cargo run --example generate_vectors`; the diff is the
review.

## Design invariants (never weakened)

1. Structural secret taint, anti-oracle equality, redaction on every export path.
2. Hard budgets: nodes, depth, array length, keys, value size, wall clock.
3. Deterministic evaluation and content hashing.
4. Dimensional unit safety, including non-arithmetic temperatures and decibels.
5. Cycle rejection before any value exists.
6. Capability security and no ambient authority (see `active-rpc`).
7. A validated buffer is the only way to obtain a view.

## Repository

- `src/layout.rs` — header, sections, limits, dialect
- `src/ir.rs` — canonical module model
- `src/canonical.rs` — normalization and ordering
- `src/encode.rs` / `src/decode.rs` / `src/validate.rs` — codec and validator
- `src/view.rs` — zero-copy views
- `src/stream.rs` — frames, reassembly, deltas
- `src/interop.rs` — `active-core` bridge, redacted JSON, graph queries
- `docs/spec/` — normative specifications
- `docs/adr/` — architecture decisions

## License

MIT OR Apache-2.0.
