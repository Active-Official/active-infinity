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
The fault is permanent: no amount of input makes an oversized frame legal, so
the error is fatal and not `is_incomplete()`. A buffer that merely stops short
of a legal frame is `infinity/truncated` and waits for more bytes, including a
read shorter than the four-byte magic. A wrong *frame* checksum is
`infinity/stream-checksum` (a framing fault the sender can retry); a wrong
reassembled-module hash at `End` is `infinity/stream-hash`; a wrong magic is
`infinity/stream-magic`; a skipped
sequence number is `infinity/stream-sequence`. A non-zero `flags` or `reserved`
field is `infinity/stream-flags` or `infinity/reserved`; the latter is the
image-family code, listed in `layout.md` §9.

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
a hash disagreement (`infinity/stream-hash`) and a resource ceiling
(`infinity/limit`). An encoder or merge refusal on this path is a delta fault:
the module came from the peer, so it is not the caller's own image.

## 3. Delta operations

| Tag | Operation | Payload |
|----:|-----------|---------|
| 0 | `SetRoot` | `node u32` (`0xFFFF_FFFF` = no root) |
| 1 | `PutNode` | `target u32, fragment_len u32, fragment` |
| 2 | *retired* | refused with `infinity/stream-delta` |
| 3 | `SetBinding` | `name_len u16, name, node u32` |
| 4 | `RemoveBinding` | `name_len u16, name` |
| 5 | `SetAnnotation` | `node u32, kind u8, payload` |
| 6 | `ClearAnnotations` | — |
| 7 | `SetProvenance` | `present u8`, then producer/model/tool optional strings, timestamp `u64`, parent flag + hash, entry count and entries |

A **fragment** is a complete canonical `AINF` image. Its node 0 (its root, or its
first node when rootless) is the payload:

- `PutNode` merges the fragment's nodes into the module and replaces the
  target's content with the fragment root's content.

Tag `2` (`PushNode`) was specified but retired before release: appending a
fragment without a name produces nodes no root reaches, which canonicalization
then drops — a silent no-op. Use `PutNode` (replace) or `SetBinding` (name) and
a following `PutNode`.

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
- The bytes accumulated across a generation may never exceed the size declared by
  `Begin` (or `Limits::max_total_bytes`), and pending delta operations are capped
  by `Limits::max_aux`; both are `infinity/limit`. Without those bounds a producer
  could stream batches forever and exhaust memory before `End`.
- A stream that ends before `End`, or with a partially received frame, is
  `infinity/stream-unterminated` or `infinity/truncated`. A generation that was
  opened (a `Delta` frame was accepted) and never closed is
  `infinity/stream-unterminated`; a repeated `End` with no pending delta is
  `infinity/stream-state`, and a `Delta` with `op_count == 0` is
  `infinity/stream-delta`, because either one would re-encode and re-validate
  the whole module for no new content.
- The decoder's work is bounded across generations, not only within one: a
  generation is charged **before** the assembly, merge and encode, against a
  counter that may not exceed 64x `Limits::max_total_bytes` (`infinity/limit`,
  kind `stream generation work`). A tripped ceiling latches: every later frame
  is refused before any work, so replaying one refused frame cannot buy another
  encode. A wrong-hash `End` stays retryable, and the retry is charged.
- A delta must change the module. A `Delta` whose ops re-encode to the image
  already held (`SetRoot` to the current root, `RemoveBinding` of an absent
  name, `SetProvenance(None)` on a module without provenance) is refused with
  `infinity/stream-delta`: it would still cost a clone, a merge and a full
  encode for no new content.
- The closing `End` carries the image size, and the content hash covers that
  field. A size that disagrees with the re-encoded image is reported as
  `infinity/stream-hash`, never as a distinct size fault: separate codes would
  let a peer recover the receiver's exact image size one bit at a time.
- A wire boolean is exactly `0` or `1`; any other tag is
  `infinity/stream-delta`. Two encodings of one operation would make a
  re-encoding inspector and the receiver disagree.
- The public `apply_delta_in_place` is fail-closed: the ops run against a clone
  and the caller's module is replaced only when every op succeeded. A refused
  list leaves the module byte-identical.
- `push_bytes` is recoverable per frame, not per buffer: a refused frame is
  consumed and its semantic state is rolled back, so the caller can correct
  that frame; bytes already consumed before a fault are not replayed.
- A delta merge also runs under the decoder's own `max_nodes`, not the
  defaults, so a strict caller is never made to allocate a larger arena than it
  declared.

## 5. Why sections, not hand-written node deltas

Reassembling section bytes makes "the stream equals the file" a property of the
transport rather than of a second serializer. There is one encoder in the
crate, and a stream cannot drift from it: if the canonical form changes, both
change together and the bytes still match. Semantic deltas exist for the case
that matters — an agent has module *M* and receives a small update — and they
re-canonicalize, so they cannot introduce a second canonical form either.

## 6. Compression (transport profile, not a frame kind)

The zstd feature ships helpers that compress and decompress image or frame
payloads. Compression is storage and transport; it is **not** part of the AINS
frame grammar and it does not move identity:

- The content hash is always over the uncompressed canonical image. A compressed
  object is an encoding of transport bytes, not a second canonical form.
- Decompression takes an explicit output ceiling (for an image, at most
  Limits::max_total_bytes). The ceiling bounds the allocation, and a frame
  that expands past it is infinity/compression.
- An empty input is refused: an empty file is not a zstd frame, and returning an
  empty buffer for it would read as a successful decode.
- An input that holds only skippable frames is refused with infinity/compression.
  Skippable frames are legal zstd and carry nothing; decoding them to an empty
  buffer would be indistinguishable from an empty payload. A content frame after
  any number of skippable frames decodes normally.
- Concatenated content frames decode to their concatenated output, the standard
  zstd behavior. The output ceiling bounds the total, so a caller always owns
  the final size; an image consumer still fail-closes at validation because the
  concatenation is not one canonical image.
- Compression levels outside the build's zstd range (-131072..=22 for current
  zstd) are infinity/invalid-argument; they are never silently clamped.
- A trained dictionary is a **hint**. zstd decompresses a frame that does not
  use the supplied dictionary, so a successful dictionary decode says nothing
  about the producer or the dictionary. Authenticity comes only from a
  SignedImage envelope or the content hash.
- Dictionary training takes an allocation ceiling (max_size); zero is refused, and
  a size above Limits::max_total_bytes is infinity/invalid-argument. zstd's
  allocator aborts the process rather than returning an error for a large enough
  capacity, so the ceiling is enforced before the call.
