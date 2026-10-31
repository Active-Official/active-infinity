/*
 * Active Infinity C ABI (ABI version 1).
 *
 * One canonicalizer: every binding validates, hashes and re-encodes through the
 * Rust reference, so bytes cannot drift between languages.
 *
 * Calling convention
 * ------------------
 * - Return 0 on success, -1 on invalid input, -2 when the output buffer is too
 *   small, -3 on an internal panic (never aborts across the boundary).
 * - After a non-zero return, active_infinity_last_error() gives the stable
 *   `infinity/...` code for the calling thread. The pointer is valid until the
 *   next failing call on that thread.
 * - Output functions take `out` and `out_len`. On entry `*out_len` is the
 *   capacity of `out`; on success it is the bytes written; on -2 it is the
 *   required size.
 * - A null pointer with a non-zero length is invalid input, never undefined
 *   behaviour.
 *
 * The library is thread-safe; `last_error` is thread-local. No function
 * retains a pointer after it returns.
 */

#ifndef ACTIVE_INFINITY_H
#define ACTIVE_INFINITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ACTIVE_INFINITY_ABI_VERSION 1u

typedef enum active_infinity_status {
  ACTIVE_INFINITY_OK = 0,
  ACTIVE_INFINITY_INVALID = -1,
  ACTIVE_INFINITY_BUFFER_TOO_SMALL = -2,
  ACTIVE_INFINITY_PANIC = -3
} active_infinity_status;

/* ABI version of the loaded library. */
uint32_t active_infinity_abi_version(void);

/* Library version, e.g. "2.1.0". Static storage. */
const char *active_infinity_version(void);

/* Stable error code from the last failing call on this thread. */
const char *active_infinity_last_error(void);

/* Allocate/free a linear-memory buffer (WASM hosts and callers that want the
 * library to own the allocation). Free with the same length. */
uint8_t *active_infinity_alloc(size_t len);
void active_infinity_free(uint8_t *ptr, size_t len);

/* Validate an AINF image. Returns 0 for a structurally valid image. */
int32_t active_infinity_validate(const uint8_t *ptr, size_t len);

/* Compute the 32-byte Blake3 content hash of a valid image. */
int32_t active_infinity_content_hash(const uint8_t *ptr, size_t len,
                                     uint8_t out32[32]);

/* Validate, decode and re-encode into canonical AINF bytes. */
int32_t active_infinity_reencode(const uint8_t *ptr, size_t len, uint8_t *out,
                                 size_t *out_len);

/* Compile Active text (UTF-8) into canonical AINF. `name` is NUL-terminated. */
int32_t active_infinity_from_active(const uint8_t *source, size_t source_len,
                                    const char *name, uint8_t *out,
                                    size_t *out_len);

/* Redacted JSON projection: secret values become the redaction marker. */
int32_t active_infinity_redacted_json(const uint8_t *ptr, size_t len,
                                      uint8_t *out, size_t *out_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ACTIVE_INFINITY_H */
