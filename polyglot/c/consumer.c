/*
 * Active Infinity C consumer: validate, hash, canonical re-encode, redaction.
 *
 * Build (from the repository root, after the static library exists):
 *   zig cc -I ffi/active-infinity-ffi/include \
 *       polyglot/c/consumer.c \
 *       ffi/active-infinity-ffi/target/release/active_infinity_ffi.lib \
 *       -o polyglot/c/consumer.exe
 *
 * Run:
 *   polyglot/c/consumer.exe tests/vectors/valid/full.ainf
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "active_infinity.h"

static uint8_t *read_file(const char *path, size_t *len) {
  FILE *file = fopen(path, "rb");
  if (file == NULL) {
    fprintf(stderr, "cannot open %s\n", path);
    return NULL;
  }
  if (fseek(file, 0, SEEK_END) != 0) {
    fclose(file);
    return NULL;
  }
  long size = ftell(file);
  if (size < 0) {
    fclose(file);
    return NULL;
  }
  rewind(file);
  uint8_t *buffer = (uint8_t *)malloc((size_t)size);
  if (buffer == NULL) {
    fclose(file);
    return NULL;
  }
  if (fread(buffer, 1, (size_t)size, file) != (size_t)size) {
    free(buffer);
    fclose(file);
    return NULL;
  }
  fclose(file);
  *len = (size_t)size;
  return buffer;
}

static int expect(int32_t status, const char *what) {
  if (status != ACTIVE_INFINITY_OK) {
    fprintf(stderr, "%s failed (%d): %s\n", what, status,
            active_infinity_last_error());
    return 0;
  }
  return 1;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <image.ainf>\n", argv[0]);
    return 2;
  }
  if (active_infinity_abi_version() != ACTIVE_INFINITY_ABI_VERSION) {
    fprintf(stderr, "ABI mismatch: library %u, header %u\n",
            active_infinity_abi_version(), ACTIVE_INFINITY_ABI_VERSION);
    return 2;
  }

  size_t len = 0;
  uint8_t *image = read_file(argv[1], &len);
  if (image == NULL) {
    return 2;
  }

  if (!expect(active_infinity_validate(image, len), "validate")) {
    free(image);
    return 1;
  }

  uint8_t hash[32];
  if (!expect(active_infinity_content_hash(image, len, hash), "content hash")) {
    free(image);
    return 1;
  }
  printf("hash=");
  for (size_t index = 0; index < sizeof hash; index++) {
    printf("%02x", hash[index]);
  }
  printf("\n");

  size_t out_len = 0;
  int32_t status = active_infinity_reencode(image, len, NULL, &out_len);
  if (status != ACTIVE_INFINITY_BUFFER_TOO_SMALL || out_len == 0) {
    fprintf(stderr, "size query failed: %s\n", active_infinity_last_error());
    free(image);
    return 1;
  }
  uint8_t *canonical = (uint8_t *)malloc(out_len);
  if (canonical == NULL) {
    free(image);
    return 2;
  }
  size_t capacity = out_len;
  if (!expect(active_infinity_reencode(image, len, canonical, &capacity),
              "reencode")) {
    free(canonical);
    free(image);
    return 1;
  }
  if (capacity != len || memcmp(canonical, image, len) != 0) {
    fprintf(stderr, "re-encoded bytes differ from the vector\n");
    free(canonical);
    free(image);
    return 1;
  }
  free(canonical);

  size_t json_len = 0;
  status = active_infinity_redacted_json(image, len, NULL, &json_len);
  if (status != ACTIVE_INFINITY_BUFFER_TOO_SMALL || json_len == 0) {
    fprintf(stderr, "json size query failed: %s\n",
            active_infinity_last_error());
    free(image);
    return 1;
  }
  uint8_t *json = (uint8_t *)malloc(json_len + 1);
  if (json == NULL) {
    free(image);
    return 2;
  }
  size_t json_capacity = json_len;
  if (!expect(active_infinity_redacted_json(image, len, json, &json_capacity),
              "redacted json")) {
    free(json);
    free(image);
    return 1;
  }
  json[json_capacity] = '\0';
  if (strstr((const char *)json, "CANARY_SECRET_") != NULL) {
    fprintf(stderr, "redaction failed: secret canary survived\n");
    free(json);
    free(image);
    return 1;
  }
  free(json);
  free(image);
  printf("PASS\n");
  return 0;
}
