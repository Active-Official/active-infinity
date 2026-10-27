# PROPOSAL — Active Infinity (Active ∞)

**Crate / repo:** `active-infinity`  
**Print name:** Active Infinity or Active ∞  
**Status:** Normative specification for implementation  
**Cross-references:** `CHECKLIST.md` (this folder), `../MASTER-PROPOSAL.md`, `../MASTER-CHECKLIST.md`

---

## 1. Purpose and scope

Active Infinity is the binary data language of the Active ecosystem. It is the canonical, zero-copy, content-addressable, graph-native representation of Active modules. It is designed to be strictly superior to JSON for configuration and data exchange, especially for AI agents, while remaining fully compatible with the existing text Active language and its safety invariants.

**Checklist mapping:** C-0.* (scaffolding), C-1.* (layout).

---

## 2. Relationship to text Active and active-core

- Text Active is the authoring form.
- Parsing + IR construction (arena + petgraph) already exists in `active-core`.
- Active Infinity is the **canonical binary serialization** of that IR (plus evaluation results, provenance, streaming state).
- Decoding Infinity must be able to feed the existing evaluator (or a zero-copy view that the evaluator can consume).
- All invariants from `spec/secrets.md`, `spec/budgets.md`, `spec/specification.md`, `spec/graph.md` remain absolute.

**Checklist mapping:** C-1.1, C-1.2, M-1.1.

---

## 3. Binary format (ABF) — detailed layout

### 3.1 Header (fixed prefix)

```
Offset  Size   Field
0       4      Magic "AINF" (0x41 0x49 0x4E 0x46)
4       1      Format major version
5       1      Format minor version
6       1      Flags bitfield
7       1      Reserved / header length encoding
8       8      Content hash (Blake3-64 or first 8 bytes of Blake3-256)
16      8      Dialect / schema hash
24      8      Node count (u64)
32      8      Edge count (u64)
40      8      String heap byte length
48      8      Blob heap byte length
56      8      Offset to node arena
64      8      Offset to edge table
72      8      Offset to string heap
80      8      Offset to blob heap
88      8      Offset to annotation table (optional)
96      8      Offset to provenance block (optional)
104     8      Offset to extension directory
112     …      Optional capability-table offset (when used with RPC)
```

Flags (bitfield): streaming, has_annotations, has_provenance, compressed_payload, signed, has_capability_table, canonical, reserved.

**Checklist mapping:** C-2.1, C-2.2.

### 3.2 Node arena

Each node is a tagged record. Preferred design: length-prefixed or fixed-size where possible for zero-copy.

Node kinds (must mirror `active-core` IR):

- Literal (Null, Bool, Int, Float, String ref, DurationMs, …)
- Env { name_ref, default_node }
- Secret { locator_node }          ← structural taint
- Ref(NodeId)
- Ident (should be resolved before canonical Infinity)
- Interpolate { parts }
- Binary / Unary
- Array { element NodeIds }
- Table { field name refs + value NodeIds }
- Quantity { value_node, unit discriminant }
- Patch, ContentAddressed, Semantic, Schema-related, etc.

Unit discriminants: compact enum (None, Milliseconds, Bytes, Count, TokensPerSec, Ratio, Custom…).

**Checklist mapping:** C-2.3, C-2.4, C-3.1.

### 3.3 Edge table

Dense array of `(from: NodeId, to: NodeId)` or CSR for large graphs. Direction = dependency → dependent (identical to current petgraph usage).

**Checklist mapping:** C-2.5.

### 3.4 Heaps and side tables

- String heap: offset + length or length-prefixed, UTF-8, optional interning.
- Blob heap: content-addressed (Blake3), media type, size.
- Annotation table: maps NodeId → list of (@intent, @constraint, @ai_immutable, …).
- Provenance block: producer, timestamp, model/tool hashes, input content hashes.

**Checklist mapping:** C-2.6, C-2.7.

### 3.5 Zero-copy contract

- Using `rkyv` (recommended) or `zerocopy`/`bytemuck` + careful `#[repr(C)]`.
- Untrusted input **must** be validated before any view is handed out.
- Validated buffers may be mmap’ed or shared.

**Checklist mapping:** C-3.2, C-3.3, C-6.3.

---

## 4. Canonicalization and content hashing

- Deterministic field order, edge order, string interning order.
- Same logical module → identical bytes → identical content hash.
- Hash covers the entire canonical payload (header content-hash field is the hash of the rest).

**Checklist mapping:** C-4.1, C-4.2.

---

## 5. Streaming / Infinity mode

- Header flag `streaming`.
- Subsequent frames: node batches, edge batches, string/blob deltas, patches, tombstones.
- Supports unbounded or live-updating modules.
- Back-pressure is the responsibility of the transport (Active RPC or other).

**Checklist mapping:** C-5.1–C-5.4.

---

## 6. Secret and unit handling

- Secret is a **kind**, not a separate bit that can be stripped.
- Equality of two Secret values is always false (anti-oracle).
- All export / debug / diagnostic paths must redact.
- Units travel with numeric values; dimensional mismatches are rejected at decode or at evaluation boundary.

**Checklist mapping:** C-3.4, C-6.4; must stay consistent with active-core `spec/secrets.md` and unit system.

---

## 7. Validation

- Magic, version, offsets, lengths, UTF-8, NodeId bounds, edge endpoints, unit discriminants, cycle detection (or deferred to evaluator), budget pre-checks where applicable.
- Fail closed on malformed input.

**Checklist mapping:** C-3.5, C-6.2.

---

## 8. Encode / decode API surface (Rust)

Suggested high-level API (to be refined in implementation):

```rust
pub fn encode_module(module: &active_core::Module, opts: EncodeOpts) -> Result<Vec<u8>, Error>;
pub fn decode_module(bytes: &[u8], opts: DecodeOpts) -> Result<DecodedModule, Error>;
pub fn validate(bytes: &[u8]) -> Result<(), Error>;
pub fn content_hash(bytes: &[u8]) -> Result<Hash, Error>;
// Zero-copy view types under a validated buffer
```

**Checklist mapping:** C-3.6, C-4.3.

---

## 9. Agent-centric features

- Annotations and provenance are first-class.
- Content-addressed identity enables efficient agent-to-agent delta sync.
- Stable error codes for machine consumption.
- Binary form of graph queries (`why`, `impact`, secret-tainted-cone) can operate directly on validated Infinity buffers.

**Checklist mapping:** C-4.4, C-7.1.

---

## 10. Interop projections

- Redacted JSON (for humans and legacy tools).
- Optional FlatBuffers / Cap’n Proto / Protobuf projections for ecosystems that require them.
- Never the primary form; Infinity is canonical.

**Checklist mapping:** C-7.2, M-4.3.

---

## 11. Testing and hardening requirements

See CHECKLIST Phase 6 and Phase 8 (hardening). Minimum:

- Round-trip property tests (text → IR → Infinity → IR → values).
- Malformed input / decoder bomb resistance.
- Secret non-leakage tests.
- Canonicalization stability tests.
- Streaming correctness.
- Fuzz targets on the decoder.

**Checklist mapping:** C-6.*, C-8.*.

---

## 12. Performance goals

- Encode/decode competitive with or better than rkyv / Cap’n Proto / FlatBuffers on representative Active modules.
- Zero-copy path for same-process and shared-memory use.
- Streaming overhead acceptable for large or live modules.

**Checklist mapping:** C-8.3, benches/.

---

## 13. Documentation and ADRs

Every major layout or API decision must have an ADR under `docs/adr/`.  
Public README must clearly explain why Active ∞ is better than JSON for agents and configuration.

**Checklist mapping:** C-0.5, C-9.*.