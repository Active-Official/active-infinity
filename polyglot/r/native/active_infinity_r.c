/* R's `.C` passes a pointer for every argument, so this shim adapts the frozen
 * C ABI to that convention: `size_t` values arrive as `double *` (R numerics)
 * and `size_t *` out-parameters are mirrored into `double *` slots.
 *
 * No R headers are needed, which keeps the lane buildable with plain gcc:
 *
 *   gcc -shared -O2 -I ffi/active-infinity-ffi/include \
 *       polyglot/r/native/active_infinity_r.c \
 *       ffi/active-infinity-ffi/target/release/active_infinity_ffi.dll.lib \
 *       -o polyglot/r/active_infinity_r.dll
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "active_infinity.h"

void ai_r_abi_version(int32_t *out) {
  *out = (int32_t)active_infinity_abi_version();
}

void ai_r_validate(const uint8_t *ptr, const double *len, int32_t *status) {
  *status = active_infinity_validate(ptr, (size_t)*len);
}

void ai_r_validate_canonical(const uint8_t *ptr, const double *len,
                             int32_t *status) {
  *status = active_infinity_validate_canonical(ptr, (size_t)*len);
}

void ai_r_content_hash(const uint8_t *ptr, const double *len, uint8_t *out,
                       int32_t *status) {
  *status = active_infinity_content_hash(ptr, (size_t)*len, out);
}

void ai_r_reencode(const uint8_t *ptr, const double *len, uint8_t *out,
                   double *out_len, int32_t *status) {
  size_t capacity = (size_t)*out_len;
  *status = active_infinity_reencode(ptr, (size_t)*len, out, &capacity);
  *out_len = (double)capacity;
}

void ai_r_redacted_json(const uint8_t *ptr, const double *len, uint8_t *out,
                        double *out_len, int32_t *status) {
  size_t capacity = (size_t)*out_len;
  *status = active_infinity_redacted_json(ptr, (size_t)*len, out, &capacity);
  *out_len = (double)capacity;
}

void ai_r_from_active(const uint8_t *source, const double *source_len,
                      const char *name, uint8_t *out, double *out_len,
                      int32_t *status) {
  size_t capacity = (size_t)*out_len;
  *status = active_infinity_from_active(source, (size_t)*source_len, name, out,
                                        &capacity);
  *out_len = (double)capacity;
}

/* Copy the calling thread's error code; R has no pointer type to hand back. */
void ai_r_last_error_text(char *out, const double *capacity) {
  const char *code = active_infinity_last_error();
  size_t room = (size_t)*capacity;
  if (out == NULL || room == 0) {
    return;
  }
  if (code == NULL) {
    out[0] = '\0';
    return;
  }
  strncpy(out, code, room - 1);
  out[room - 1] = '\0';
}
