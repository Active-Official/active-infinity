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

/* Build the C limits struct from an R numeric[24] in struct order, or the
   library defaults when the array is NULL. Returns 0 on success. */
static int ai_r_limits_from_array(const double *values,
                                  active_infinity_limits *limits) {
  if (values == NULL) {
    return active_infinity_limits_default(limits) == 0 ? 0 : -1;
  }
  limits->max_nodes = (uint32_t)values[0];
  limits->max_edges = (uint32_t)values[1];
  limits->max_children = (uint32_t)values[2];
  limits->max_fields = (uint32_t)values[3];
  limits->max_parts = (uint32_t)values[4];
  limits->max_strings = (uint32_t)values[5];
  limits->max_string_bytes = (uint32_t)values[6];
  limits->max_blobs = (uint32_t)values[7];
  limits->max_blob_bytes = (uint32_t)values[8];
  limits->max_annotations = (uint32_t)values[9];
  limits->max_units = (uint32_t)values[10];
  limits->max_types = (uint32_t)values[11];
  limits->max_aux = (uint32_t)values[12];
  limits->max_numbers = (uint32_t)values[13];
  limits->max_secrets = (uint32_t)values[14];
  limits->max_secret_bytes = (uint32_t)values[15];
  limits->max_extensions = (uint32_t)values[16];
  limits->max_prov_bytes = (uint32_t)values[17];
  limits->max_prov_entries = (uint32_t)values[18];
  limits->max_hashes = (uint32_t)values[19];
  limits->max_bindings = (uint32_t)values[20];
  limits->max_total_bytes = (uint64_t)values[21];
  limits->max_decoded_bytes = (uint64_t)values[22];
  limits->max_depth = (uint32_t)values[23];
  return 0;
}

void ai_r_limits_default(double *values, int32_t *status) {
  active_infinity_limits limits;
  *status = active_infinity_limits_default(&limits) == 0 ? 0 : -1;
  if (*status != 0) {
    return;
  }
  values[0] = (double)limits.max_nodes;
  values[1] = (double)limits.max_edges;
  values[2] = (double)limits.max_children;
  values[3] = (double)limits.max_fields;
  values[4] = (double)limits.max_parts;
  values[5] = (double)limits.max_strings;
  values[6] = (double)limits.max_string_bytes;
  values[7] = (double)limits.max_blobs;
  values[8] = (double)limits.max_blob_bytes;
  values[9] = (double)limits.max_annotations;
  values[10] = (double)limits.max_units;
  values[11] = (double)limits.max_types;
  values[12] = (double)limits.max_aux;
  values[13] = (double)limits.max_numbers;
  values[14] = (double)limits.max_secrets;
  values[15] = (double)limits.max_secret_bytes;
  values[16] = (double)limits.max_extensions;
  values[17] = (double)limits.max_prov_bytes;
  values[18] = (double)limits.max_prov_entries;
  values[19] = (double)limits.max_hashes;
  values[20] = (double)limits.max_bindings;
  values[21] = (double)limits.max_total_bytes;
  values[22] = (double)limits.max_decoded_bytes;
  values[23] = (double)limits.max_depth;
}

void ai_r_validate_with_limits(const uint8_t *ptr, const double *len,
                               const double *limits_values, int32_t *status) {
  active_infinity_limits limits;
  if (ai_r_limits_from_array(limits_values, &limits) != 0) {
    *status = -1;
    return;
  }
  *status = active_infinity_validate_with_limits(ptr, (size_t)*len, &limits);
}

void ai_r_decode_with_limits(const uint8_t *ptr, const double *len,
                             const double *limits_values, uint8_t *out,
                             double *out_len, int32_t *status) {
  active_infinity_limits limits;
  if (ai_r_limits_from_array(limits_values, &limits) != 0) {
    *status = -1;
    return;
  }
  size_t capacity = (size_t)*out_len;
  *status = active_infinity_decode_with_limits(ptr, (size_t)*len, &limits, out,
                                               &capacity);
  *out_len = (double)capacity;
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
