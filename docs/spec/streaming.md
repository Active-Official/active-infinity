# Streaming and incremental updates (`AINS`)

**Status:** normative. See `layout.md` for the image format this carries.

A stream is a sequence of self-delimiting frames. A stream produced from a
module reassembles to **exactly** the bytes `encode(module)` produces and to the
same Blake3 content hash, and a stream may continue with semantic deltas that
land on the identical whole-module encoding of the updated module.

## 1. Frame header (32 bytes)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 4 | magic `41 49 4E 53` (`AINS`) |
| 4 | 1 | frame version (`1`) |
| 5 | 1 | frame kind |
| 6 | 2 | flags (zero) |
| 8 | 8 | sequence number (starts at 0, increments by 1) |
| 16 | 4 | payload length |
| 20 | 4 | reserved (zero) |
| 24 | 8 | first 8 bytes of Blake3(payload) |

A frame payload larger than 64 MiB is refused with `infinity/stream-frame-len`.
A wrong checksum is `infinity/hash-mismatch`; a wrong magic is
`infinity/stream-magic`; a skipped sequence number is
`infinity/stream-sequence`.

Frames may be split across reads and several may arrive in one read: a decoder
buffers partial frames and never requires frame boundaries at call boundaries.

## 2. Kinds

| Kind | Name | Payload |
|-----:|------|---------|
| 1 | `Begin` | `{ major u16, minor u16, flags u16, reserved u16, dialect u64, total_size u64 }` (24 bytes) |
| 2 | `Batch` | `{ section u8, count u32, chunk_len u32, bytes }` |
| 3 | `Delta` | `{ op_count u32, ops… }` |
| 4 | `End` | `{ content_hash [32], total_size u64 }` (40 bytes) |

### 2.1 Generation

1. `Begin` announces format, header flags, dialect and the total image size.
2. `Batch` frames follow in section order (the 17 sections of `layout.md` §2),
   each section once, possibly split into several chunks that share the same
   `count`. A section with no bytes still emits one empty batch.
3. `End` carries the content hash and size of the resulting image.

The reassembler rebuilds the header from `Begin`'s flags, the section counts from
the batches, and the section bodies from the concatenated chunk bytes, then
validates the image exactly as a standalone module (hash included). Because the
batches carry the canonical section bytes, the result is byte-identical to the
whole-module encoding — not merely equivalent.

### 2.2 Incremental generation

After an `End`, a stream may carry `Delta` frames followed by another `End`:

1. the current module is decoded;
2. the delta operations are applied;
3. the module is canonicalized and encoded;
4. the image size and hash must equal the new `End` frame.

Applying the same operations to the same base module is deterministic, so the
result equals `encode(updated)`. A failure is `infinity/stream-delta`, except for
a hash disagreement, which is `infinity/stream-hash`.

## 3. Delta operations

| Tag | Operation | Payload |
|----:|-----------|---------|
| 0 | `SetRoot` | `node u32` (`0xFFFF_FFFF` = no root) |
| 1 | `PutNode` | `target u32, fragment_len u32, fragment` |
| 2 | `PushNode` | `fragment_len u32, fragment` |
| 3 | `SetBinding` | `name_len u16, name, node u32` |
| 4 | `RemoveBinding` | `name_len u16, name` |
| 5 | `SetAnnotation` | `node u32, kind u8, payload` |
| 6 | `ClearAnnotations` | — |
| 7 | `SetProvenance` | `present u8`, then producer/model/tool optional strings, timestamp `u64`, parent flag + hash, entry count and entries |

A **fragment** is a complete canonical `AINF` image. Its node 0 (its root, or its
first node when rootless) is the payload:

- `PutNode` merges the fragment's nodes into the module and replaces the
  target's content with the fragment root's content;
- `PushNode` merges the fragment and appends it.

Merging renumbers node ids, so a delta never has to reason about the receiver's
arena layout beyond the target id it names.

Annotation kinds: `0` intent (string), `1` constraint (source string + expression
node), `2` ai-immutable (`0`/`1`).

## 4. Limits and failure

- A frame is bounded by `MAX_FRAME_PAYLOAD` (64 MiB) and a stream's declared
  size by `Limits::max_total_bytes`.
- Delta operation count is bounded by `Limits::max_aux`.
- A `Batch` outside a generation, a `Begin` after `End`, a `Delta` before `End`
  and a section out of order are `infinity/stream-state`.
- A stream that ends before `End`, or with a partially received frame, is
  `infinity/stream-unterminated` or `infinity/truncated`.

## 5. Why sections, not hand-written node deltas

Reassembling section bytes makes "the stream equals the file" a property of the
transport rather than of a second serializer. There is one encoder in the
crate, and a stream cannot drift from it: if the canonical form changes, both
change together and the bytes still match. Semantic deltas exist for the case
that matters — an agent has module *M* and receives a small update — and they
re-canonicalize, so they cannot introduce a second canonical form either.
