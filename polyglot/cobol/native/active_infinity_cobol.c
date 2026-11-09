/* Lane scaffolding for GnuCOBOL: file reading, hex formatting and a manifest
 * scan. The binding itself calls the frozen C ABI directly; these helpers only
 * make byte-oriented work expressible in COBOL without a JSON or I/O library.
 *
 *   gcc -shared -O2 -I ffi/active-infinity-ffi/include \
 *       polyglot/cobol/native/active_infinity_cobol.c \
 *       ffi/active-infinity-ffi/target/release/active_infinity_ffi.dll.lib \
 *       -Wl,--out-implib,polyglot/cobol/libactive_infinity_cobol.dll.a \
 *       -o polyglot/cobol/active_infinity_cobol.dll
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "active_infinity.h"

size_t ai_cobol_read_file(const char *path, uint8_t *buffer, size_t capacity) {
  FILE *file = fopen(path, "rb");
  if (file == NULL) {
    return 0;
  }
  size_t read = fread(buffer, 1, capacity, file);
  fclose(file);
  return read;
}

void ai_cobol_hex32(const uint8_t *digest, char *out) {
  static const char digits[] = "0123456789abcdef";
  for (int index = 0; index < 32; index++) {
    out[2 * index] = digits[digest[index] >> 4];
    out[2 * index + 1] = digits[digest[index] & 0x0f];
  }
}

void ai_cobol_last_error(char *out, size_t capacity) {
  const char *code = active_infinity_last_error();
  if (out == NULL || capacity == 0) {
    return;
  }
  if (code == NULL) {
    out[0] = '\0';
    return;
  }
  strncpy(out, code, capacity - 1);
  out[capacity - 1] = '\0';
}

static const char *find_text(const char *start, const char *end,
                             const char *needle) {
  size_t length = strlen(needle);
  for (const char *at = start; at + length <= end; at++) {
    if (memcmp(at, needle, length) == 0) {
      return at;
    }
  }
  return NULL;
}

static int quoted_after(const char **cursor, const char *end, const char *key,
                        char *out, size_t capacity) {
  const char *at = find_text(*cursor, end, key);
  if (at == NULL) {
    return 0;
  }
  at += strlen(key);
  const char *quote = memchr(at, '"', (size_t)(end - at));
  if (quote == NULL || capacity == 0) {
    return 0;
  }
  size_t length = (size_t)(quote - at);
  if (length >= capacity) {
    length = capacity - 1;
  }
  memcpy(out, at, length);
  out[length] = '\0';
  *cursor = quote + 1;
  return 1;
}

/* Number of `"kind": "valid"` cases in the manifest text. */
size_t ai_cobol_case_count(const char *manifest, size_t length) {
  const char *end = manifest + length;
  const char *cursor = manifest;
  size_t count = 0;
  while (1) {
    const char *at = find_text(cursor, end, "\"kind\": \"valid\"");
    if (at == NULL) {
      break;
    }
    count++;
    cursor = at + 1;
  }
  return count;
}

/* Number of `"kind": "invalid"` cases in the manifest text. The closing
 * quote keeps `"kind": "invalid_stream"` out of the count. */
size_t ai_cobol_invalid_count(const char *manifest, size_t length) {
  const char *end = manifest + length;
  const char *cursor = manifest;
  size_t count = 0;
  while (1) {
    const char *at = find_text(cursor, end, "\"kind\": \"invalid\"");
    if (at == NULL) {
      break;
    }
    count++;
    cursor = at + 1;
  }
  return count;
}

/* Fetch the name, path and expected error code of the index-th invalid
 * case. */
int ai_cobol_invalid_case(const char *manifest, size_t length, size_t index,
                          char *path, size_t path_capacity, char *name,
                          size_t name_capacity, char *code,
                          size_t code_capacity) {
  const char *end = manifest + length;
  const char *cursor = manifest;
  for (size_t at = 0; at <= index; at++) {
    const char *found = find_text(cursor, end, "\"kind\": \"invalid\"");
    if (found == NULL) {
      return 0;
    }
    cursor = found + 1;
  }
  if (!quoted_after(&cursor, end, "\"name\": \"", name, name_capacity)) {
    return 0;
  }
  if (!quoted_after(&cursor, end, "\"path\": \"", path, path_capacity)) {
    return 0;
  }
  if (!quoted_after(&cursor, end, "\"expected_code\": \"", code,
                     code_capacity)) {
    return 0;
  }
  return 1;
}

/* Fetch the limits spec ("field:value") of the index-th invalid case,
 * or return 0 when the case has none. The options object sits between the
 * path and the expected_code, so the limits must come before this case's
 * expected_code. */
int ai_cobol_invalid_limits(const char *manifest, size_t length, size_t index,
                            char *limits, size_t limits_capacity) {
  const char *end = manifest + length;
  const char *cursor = manifest;
  for (size_t at = 0; at <= index; at++) {
    const char *found = find_text(cursor, end, "\"kind\": \"invalid\"");
    if (found == NULL) {
      return 0;
    }
    cursor = found + 1;
  }
  const char *at = find_text(cursor, end, "\"limits\": \"");
  if (at == NULL) {
    return 0;
  }
  const char *code = find_text(cursor, end, "\"expected_code\": \"");
  if (code != NULL && at > code) {
    return 0;
  }
  at += strlen("\"limits\": \"");
  const char *quote = memchr(at, '"', (size_t)(end - at));
  if (quote == NULL || limits_capacity == 0) {
    return 0;
  }
  size_t len = (size_t)(quote - at);
  if (len >= limits_capacity) {
    len = limits_capacity - 1;
  }
  memcpy(limits, at, len);
  limits[len] = '\0';
  return 1;
}

/* Validate under a narrowed budget given as "field:value". Returns the FFI
 * status, or -1 on a bad spec. */
int ai_cobol_validate_with_limits(const uint8_t *image, size_t length,
                                  const char *spec) {
  active_infinity_limits limits;
  if (active_infinity_limits_default(&limits) != 0) {
    return -1;
  }
  const char *colon = strchr(spec, ':');
  if (colon == NULL) {
    return -1;
  }
  char field[32];
  size_t field_len = (size_t)(colon - spec);
  if (field_len == 0 || field_len >= sizeof field) {
    return -1;
  }
  memcpy(field, spec, field_len);
  field[field_len] = '\0';
  char *end = NULL;
  unsigned long long value = strtoull(colon + 1, &end, 10);
  if (end == colon + 1 || *end != '\0') {
    return -1;
  }
  if (strcmp(field, "max_nodes") == 0) { limits.max_nodes = (uint32_t)value; }
  else if (strcmp(field, "max_edges") == 0) { limits.max_edges = (uint32_t)value; }
  else if (strcmp(field, "max_children") == 0) { limits.max_children = (uint32_t)value; }
  else if (strcmp(field, "max_fields") == 0) { limits.max_fields = (uint32_t)value; }
  else if (strcmp(field, "max_parts") == 0) { limits.max_parts = (uint32_t)value; }
  else if (strcmp(field, "max_strings") == 0) { limits.max_strings = (uint32_t)value; }
  else if (strcmp(field, "max_string_bytes") == 0) { limits.max_string_bytes = (uint32_t)value; }
  else if (strcmp(field, "max_blobs") == 0) { limits.max_blobs = (uint32_t)value; }
  else if (strcmp(field, "max_blob_bytes") == 0) { limits.max_blob_bytes = (uint32_t)value; }
  else if (strcmp(field, "max_annotations") == 0) { limits.max_annotations = (uint32_t)value; }
  else if (strcmp(field, "max_units") == 0) { limits.max_units = (uint32_t)value; }
  else if (strcmp(field, "max_types") == 0) { limits.max_types = (uint32_t)value; }
  else if (strcmp(field, "max_aux") == 0) { limits.max_aux = (uint32_t)value; }
  else if (strcmp(field, "max_numbers") == 0) { limits.max_numbers = (uint32_t)value; }
  else if (strcmp(field, "max_secrets") == 0) { limits.max_secrets = (uint32_t)value; }
  else if (strcmp(field, "max_secret_bytes") == 0) { limits.max_secret_bytes = (uint32_t)value; }
  else if (strcmp(field, "max_extensions") == 0) { limits.max_extensions = (uint32_t)value; }
  else if (strcmp(field, "max_prov_bytes") == 0) { limits.max_prov_bytes = (uint32_t)value; }
  else if (strcmp(field, "max_prov_entries") == 0) { limits.max_prov_entries = (uint32_t)value; }
  else if (strcmp(field, "max_hashes") == 0) { limits.max_hashes = (uint32_t)value; }
  else if (strcmp(field, "max_bindings") == 0) { limits.max_bindings = (uint32_t)value; }
  else if (strcmp(field, "max_total_bytes") == 0) { limits.max_total_bytes = (uint64_t)value; }
  else if (strcmp(field, "max_decoded_bytes") == 0) { limits.max_decoded_bytes = (uint64_t)value; }
  else if (strcmp(field, "max_depth") == 0) { limits.max_depth = (uint32_t)value; }
  else {
    return -1;
  }
  return active_infinity_validate_with_limits(image, length, &limits);
}

/* Fetch the name, path and content hash of the index-th valid case. */
int ai_cobol_case(const char *manifest, size_t length, size_t index, char *path,
                  size_t path_capacity, char *name, size_t name_capacity,
                  char *hash, size_t hash_capacity) {
  const char *end = manifest + length;
  const char *cursor = manifest;
  for (size_t at = 0; at <= index; at++) {
    const char *found = find_text(cursor, end, "\"kind\": \"valid\"");
    if (found == NULL) {
      return 0;
    }
    cursor = found + 1;
  }
  if (!quoted_after(&cursor, end, "\"name\": \"", name, name_capacity)) {
    return 0;
  }
  if (!quoted_after(&cursor, end, "\"path\": \"", path, path_capacity)) {
    return 0;
  }
  const char *hashed = find_text(cursor, end, "\"content_hash\": \"");
  if (hashed == NULL || hash_capacity < 65) {
    return 0;
  }
  hashed += strlen("\"content_hash\": \"");
  if (hashed + 64 > end) {
    return 0;
  }
  for (int at = 0; at < 64; at++) {
    char c = hashed[at];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return 0;
    }
  }
  memcpy(hash, hashed, 64);
  hash[64] = '\0';
  return 1;
}
