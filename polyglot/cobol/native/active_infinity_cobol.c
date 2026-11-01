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
