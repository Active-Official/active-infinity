# ADR-0009 - Protobuf interop projection

**Status:** accepted (2026-10-27)

## Context

Active Infinity is the canonical form, and Active peers exchange it directly.
Every other system in a deployment — queues, dashboards, tracing pipelines,
analytics jobs, service meshes — speaks something else. The master checklist
requires at least one binary projection besides the redacted JSON document
(M-4.3), and the master proposal names Protobuf explicitly.

The candidates were:

- **Protobuf**: ubiquitous generated clients, stable field-number evolution,
  streaming-friendly length-delimited framing, zero new dependencies for a
  hand-written encoder.
- **FlatBuffers**: zero-copy reads, but a schema compiler on the consumer side
  and a larger dependency for a projection that is inherently a few hundred
  kilobytes at most.
- **Cap'n Proto**: excellent wire design, smallest ecosystem of the three among
  the consumers this project targets.

## Decision

1. **Protobuf wire format, encoded by hand.** `to_protobuf` writes the wire
   format directly: varints, zig-zag `sint64`, little-endian `double`, exact
   length prefixes. No new runtime dependency, no code generation step, no
   `build.rs` in the published crate.
2. **The schema is published in the crate documentation and in
   `docs/spec/projection.md`.** Consumers generate their own bindings from it;
   the encoder is checked against an independent reader in
   `tests/protobuf_tests.rs`.
3. **The projection is a view, not a second canonical form.** Content addressing,
   signatures and streaming stay on the AINF image. The `Module` message carries
   that image's Blake3 hash so a consumer can fetch and verify the authority.
4. **One redacted tree feeds both projections.** The JSON and Protobuf
   projections render `interop::Projected`, so redaction cannot drift between
   them and a new node kind is handled once.
5. **Field numbers are permanent.** Additive changes take the next free number;
   removals retire the number. Kind ids inside the `Value` oneof follow the same
   rule.
6. **Deterministic encoding.** Fields ascend by number, scalars are emitted even
   at their proto3 default, and absent optionals are omitted, so the same module
   always produces the same bytes.

## Consequences

- Any language with a Protobuf runtime can read Active data without an AINF
  implementation, and without a chance of reading a secret.
- The projection is lossy in the same places JSON is: blob payloads, operator
  text and secret material are represented by identity or by marker. A consumer
  that needs those fetches the AINF image with the advertised hash.
- Scalar defaults being emitted makes the encoding slightly larger than a
  minimal protobuf encoder would produce; determinism and injectivity are worth
  more than a few bytes on a projection.
- A future need for true zero-copy reads in another ecosystem can be met by a
  superseding ADR for FlatBuffers, which would not disturb this one.
