/*
 * Active Infinity C ABI (ABI version 1).
 *
 * One canonicalizer: every binding validates, hashes and re-encodes through the
 * Rust reference, so bytes cannot drift between languages.
 *
 * Calling convention
 * ------------------
 * - Return 0 on success, -1 on invalid input or a refused operation, -2 when
 *   the output buffer is too small, -3 on an internal panic. The shim catches
 *   panics on unwinding targets; on `panic=abort` targets, including
 *   `wasm32-unknown-unknown`, a panic traps the instance instead of returning
 *   -3, so a host must treat a trap as a failed call.
 * - After a call that reports a status, active_infinity_last_error() gives the
 *   stable `infinity/...` code for the calling thread (`infinity/ok` on
 *   success). `active_infinity_alloc` and `active_infinity_free` never change
 *   it: they are allocation primitives, and a binding may free an internal
 *   buffer between a failed call and its read of the code.
 *   Copy the string immediately: the pointer is owned by the library and is
 *   released by the next call on that thread. Never keep it.
 * - Output functions take `out` and `out_len`. On entry `*out_len` is the
 *   capacity of `out`; on success it is the bytes written; on -2 it is the
 *   required size. `out_len` must be aligned for `size_t`; a misaligned pointer
 *   is refused with `infinity/out-len-misaligned` rather than dereferenced.
 * - A null pointer with a non-zero length is invalid input, never undefined
 *   behaviour. A null output with a zero capacity is the documented size query.
 * - `active_infinity_content_hash` writes exactly 32 bytes; there is no length
 *   negotiation for that output.
 *
 * Allocation
 * ----------
 * `active_infinity_alloc` returns NULL for more than 1 GiB, or when the
 * allocator fails, rather than aborting; a NULL return means the allocation
 * failed, and (unlike the status-bearing calls) it does not set `last_error`.
 * Every live allocation is recorded, and
 * `active_infinity_free` consults that record: a foreign pointer, a forged tag
 * and a wrong length are each a no-op (the buffer is leaked at worst) instead
 * of heap corruption. Buffers are 8-byte aligned.
 *
 * A double free is a no-op only while the address has not been reused. If an
 * allocation between the two frees returned the same address, the stale free
 * releases that newer buffer. Always null the pointer after freeing it; using
 * a pointer after it was freed is undefined behaviour.
 *
 * `active_infinity_alloc` returns NULL on failure and does not set
 * `last_error`; treat NULL as an allocation failure. The getters return NULL
 * only if an internal panic occurred; bindings should treat NULL as
 * "unavailable".
 *
 * Untrusted input: the shim runs the default profile (1 GiB total bytes). A
 * wasm32 instance has a 4 GiB address space, so size the module's memory for
 * the decode plus one re-encode; a host that cannot afford that must cap the
 * input itself before calling in.
 *
 * The library is thread-safe; `last_error` is thread-local. No function
 * retains a caller pointer after it returns.
 */

#ifndef ACTIVE_INFINITY_H
#define ACTIVE_INFINITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ACTIVE_INFINITY_ABI_VERSION 1u

/* Largest single active_infinity_alloc request. */
#define ACTIVE_INFINITY_MAX_ALLOC_BYTES (1024u * 1024u * 1024u)

/* Largest module name accepted by active_infinity_from_active. */
#define ACTIVE_INFINITY_MAX_NAME_BYTES 4096u

/* Largest Active source accepted by active_infinity_from_active. */
#define ACTIVE_INFINITY_MAX_SOURCE_BYTES (16u * 1024u * 1024u)

typedef enum active_infinity_status {
  ACTIVE_INFINITY_OK = 0,
  ACTIVE_INFINITY_INVALID = -1,
  ACTIVE_INFINITY_BUFFER_TOO_SMALL = -2,
  ACTIVE_INFINITY_PANIC = -3
} active_infinity_status;

/* Caller-supplied budget (INF-FFI-02): one ceiling per field, in the same
 * order as the Rust `Limits` struct. All ceilings are uint32_t except
 * max_total_bytes and max_decoded_bytes (uint64_t). A ceiling of zero is
 * refused with `infinity/invalid-argument`. Pass NULL to the
 * `*_with_limits` functions for the library defaults; call
 * `active_infinity_limits_default` to fill a struct with the defaults and
 * then override the one ceiling to tighten. */
typedef struct active_infinity_limits {
  uint32_t max_nodes;
  uint32_t max_edges;
  uint32_t max_children;
  uint32_t max_fields;
  uint32_t max_parts;
  uint32_t max_strings;
  uint32_t max_string_bytes;
  uint32_t max_blobs;
  uint32_t max_blob_bytes;
  uint32_t max_annotations;
  uint32_t max_units;
  uint32_t max_types;
  uint32_t max_aux;
  uint32_t max_numbers;
  uint32_t max_secrets;
  uint32_t max_secret_bytes;
  uint32_t max_extensions;
  uint32_t max_prov_bytes;
  uint32_t max_prov_entries;
  uint32_t max_hashes;
  uint32_t max_bindings;
  uint64_t max_total_bytes;
  uint64_t max_decoded_bytes;
  uint32_t max_depth;
} active_infinity_limits;

/* ABI version of the loaded library. */
uint32_t active_infinity_abi_version(void);

/* Codec version, e.g. "2.3.0" (not the shim's version). Static storage. */
const char *active_infinity_version(void);

/* Shim version, e.g. "0.1.0". Static storage. */
const char *active_infinity_ffi_version(void);

/* Stable error code from the last call on this thread. Copy immediately. */
const char *active_infinity_last_error(void);

/* Allocate/free a linear-memory buffer (WASM hosts and callers that want the
 * library to own the allocation). Free with the same length; see above. */
uint8_t *active_infinity_alloc(size_t len);
void active_infinity_free(uint8_t *ptr, size_t len);

/* Validate an AINF image. Returns 0 only for a structurally valid image
 * that is exactly the canonical encoding of its own content (INF-02):
 * the stored hash is verified and the canonical form is re-proved, so a
 * structurally valid but non-canonical image is refused with
 * `infinity/not-canonical`. `active_infinity_reencode` is the repair path
 * for an image this function refuses. */
int32_t active_infinity_validate(const uint8_t *ptr, size_t len);

/* Validate and prove the canonical form (re-encodes to the same bytes).
 * `active_infinity_validate` already proves the canonical form; this
 * states the requirement explicitly. */
int32_t active_infinity_validate_canonical(const uint8_t *ptr, size_t len);

/* Fill a limits struct with the library defaults. Returns 0 on success,
 * -1 for a null pointer. Build a narrowed budget by calling this, then
 * overriding the one ceiling to tighten. */
int32_t active_infinity_limits_default(active_infinity_limits *limits);

/* Validate an image under caller-supplied limits (NULL = defaults). This
 * is the limits-parameterized form of
 * active_infinity_validate_canonical: the stored hash is verified and the
 * canonical form is re-proved under the caller's budget. This is what makes
 * the manifest's limit vectors reproducible through a binding: `limit` is
 * refused with `infinity/limit` under max_nodes 1 and `too_deep` with
 * `infinity/depth` under max_depth 8. */
int32_t active_infinity_validate_with_limits(
    const uint8_t *ptr, size_t len, const active_infinity_limits *limits);

/* Validate, decode and re-encode under caller-supplied limits (NULL =
 * defaults). The limits-parameterized form of active_infinity_reencode:
 * the input is decoded leniently under the caller's budget, re-encoded,
 * and the output is strict-validated under the same budget before it is
 * returned. */
int32_t active_infinity_decode_with_limits(const uint8_t *ptr, size_t len,
                                           const active_infinity_limits *limits,
                                           uint8_t *out, size_t *out_len);

/* Compute the 32-byte Blake3 content hash of a canonical image. The value
 * is the byte identity: it equals the header's stored hash and the
 * reference `content_hash(bytes)`. A non-canonical image is refused with
 * `infinity/not-canonical` instead of being hashed, because the hash is
 * the identity of the canonical form: repair first with
 * `active_infinity_reencode`, then hash the repaired bytes. */
int32_t active_infinity_content_hash(const uint8_t *ptr, size_t len,
                                     uint8_t out32[32]);

/* Validate, decode and re-encode into canonical AINF bytes. The input need
 * not already be canonical: it is decoded leniently (the stored hash is
 * still verified, only the canonical-form proof is skipped), re-encoded,
 * and the output is strict-validated before it is returned, so the output
 * is always canonical. A non-canonical input therefore succeeds and the
 * output differs from the input: this is the repair path. */
int32_t active_infinity_reencode(const uint8_t *ptr, size_t len, uint8_t *out,
                                 size_t *out_len);

/* Compile Active text (UTF-8) into canonical AINF. `name` is NUL-terminated
 * and at most ACTIVE_INFINITY_MAX_NAME_BYTES long. */
int32_t active_infinity_from_active(const uint8_t *source, size_t source_len,
                                    const char *name, uint8_t *out,
                                    size_t *out_len);

/* Redacted JSON projection: secret values become the redaction marker.
 * The input must be canonical (INF-02): a non-canonical image is refused
 * with `infinity/not-canonical`. Repair it first with
 * `active_infinity_reencode`. */
int32_t active_infinity_redacted_json(const uint8_t *ptr, size_t len,
                                      uint8_t *out, size_t *out_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ACTIVE_INFINITY_H */
