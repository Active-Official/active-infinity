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
 *   polyglot/c/consumer.exe tests/vectors/valid/full.ainf <content_hash>
 *   polyglot/c/consumer.exe tests/vectors/invalid/bad_magic.ainf --expect-code infinity/magic
 *
 * INF-POLY-02: the consumer used to print the content hash without
 * comparing it to the manifest, and it never ran on a hostile vector, so
 * a wrong hash or a wrong refusal code passed silently. The optional
 * expected-hash argument and the --expect-code hostile mode close both
 * gaps; CI passes the manifest hash for full.ainf and loops the invalid
 * vectors through this binary.
 *
 * INF-FFI-02: the --limits flag narrows one ceiling (e.g. --limits
 * max_nodes:1) and routes the hostile mode through validate_with_limits,
 * so the two limits-dependent vectors (limit, too_deep) are checked here
 * instead of being skipped.
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

/* INF-FFI-02: set one ceiling in a limits struct from a "field:value"
   spec (e.g. "max_nodes:1"). Returns 0 on success, -1 on a bad spec or an
   unknown field (fail closed: the caller refuses to run). */
static int set_limit(active_infinity_limits *limits, const char *spec) {
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
  if (strcmp(field, "max_nodes") == 0) { limits->max_nodes = (uint32_t)value; return 0; }
  if (strcmp(field, "max_edges") == 0) { limits->max_edges = (uint32_t)value; return 0; }
  if (strcmp(field, "max_children") == 0) { limits->max_children = (uint32_t)value; return 0; }
  if (strcmp(field, "max_fields") == 0) { limits->max_fields = (uint32_t)value; return 0; }
  if (strcmp(field, "max_parts") == 0) { limits->max_parts = (uint32_t)value; return 0; }
  if (strcmp(field, "max_strings") == 0) { limits->max_strings = (uint32_t)value; return 0; }
  if (strcmp(field, "max_string_bytes") == 0) { limits->max_string_bytes = (uint32_t)value; return 0; }
  if (strcmp(field, "max_blobs") == 0) { limits->max_blobs = (uint32_t)value; return 0; }
  if (strcmp(field, "max_blob_bytes") == 0) { limits->max_blob_bytes = (uint32_t)value; return 0; }
  if (strcmp(field, "max_annotations") == 0) { limits->max_annotations = (uint32_t)value; return 0; }
  if (strcmp(field, "max_units") == 0) { limits->max_units = (uint32_t)value; return 0; }
  if (strcmp(field, "max_types") == 0) { limits->max_types = (uint32_t)value; return 0; }
  if (strcmp(field, "max_aux") == 0) { limits->max_aux = (uint32_t)value; return 0; }
  if (strcmp(field, "max_numbers") == 0) { limits->max_numbers = (uint32_t)value; return 0; }
  if (strcmp(field, "max_secrets") == 0) { limits->max_secrets = (uint32_t)value; return 0; }
  if (strcmp(field, "max_secret_bytes") == 0) { limits->max_secret_bytes = (uint32_t)value; return 0; }
  if (strcmp(field, "max_extensions") == 0) { limits->max_extensions = (uint32_t)value; return 0; }
  if (strcmp(field, "max_prov_bytes") == 0) { limits->max_prov_bytes = (uint32_t)value; return 0; }
  if (strcmp(field, "max_prov_entries") == 0) { limits->max_prov_entries = (uint32_t)value; return 0; }
  if (strcmp(field, "max_hashes") == 0) { limits->max_hashes = (uint32_t)value; return 0; }
  if (strcmp(field, "max_bindings") == 0) { limits->max_bindings = (uint32_t)value; return 0; }
  if (strcmp(field, "max_total_bytes") == 0) { limits->max_total_bytes = (uint64_t)value; return 0; }
  if (strcmp(field, "max_decoded_bytes") == 0) { limits->max_decoded_bytes = (uint64_t)value; return 0; }
  if (strcmp(field, "max_depth") == 0) { limits->max_depth = (uint32_t)value; return 0; }
  return -1;
}

static int expect(int32_t status, const char *what) {
  if (status != ACTIVE_INFINITY_OK) {
    const char *code = active_infinity_last_error();
    fprintf(stderr, "%s failed (%d): %s\n", what, status,
            code != NULL ? code : "infinity/unknown");
    return 0;
  }
  return 1;
}

int main(int argc, char **argv) {
  const char *expected_hash = NULL;
  const char *expected_code = NULL;
  const char *limits_spec = NULL;
  if (argc < 2 || argc > 6) {
    fprintf(stderr, "usage: %s <image.ainf> [expected-hash-hex] [--expect-code <code>] [--limits <field:value>]\n", argv[0]);
    return 2;
  }
  for (int index = 2; index < argc; index++) {
    if (strcmp(argv[index], "--expect-code") == 0) {
      if (index + 1 >= argc) {
        fprintf(stderr, "--expect-code needs a code\n");
        return 2;
      }
      expected_code = argv[++index];
    } else if (strcmp(argv[index], "--limits") == 0) {
      if (index + 1 >= argc) {
        fprintf(stderr, "--limits needs a field:value spec\n");
        return 2;
      }
      limits_spec = argv[++index];
    } else if (expected_hash == NULL) {
      expected_hash = argv[index];
    } else {
      fprintf(stderr, "unexpected argument: %s\n", argv[index]);
      return 2;
    }
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

  /* INF-POLY-02: hostile mode -- the image must be refused by
     validate_canonical with exactly the expected code. INF-FFI-02: with
     --limits, the refusal goes through validate_with_limits under the
     narrowed budget instead. */
  if (expected_code != NULL) {
    int32_t status;
    if (limits_spec != NULL) {
      active_infinity_limits limits;
      if (active_infinity_limits_default(&limits) != 0 ||
          set_limit(&limits, limits_spec) != 0) {
        fprintf(stderr, "bad --limits spec: %s\n", limits_spec);
        free(image);
        return 2;
      }
      status = active_infinity_validate_with_limits(image, len, &limits);
    } else {
      status = active_infinity_validate_canonical(image, len);
    }
    if (status == ACTIVE_INFINITY_OK) {
      fprintf(stderr, "invalid image was accepted\n");
      free(image);
      return 1;
    }
    const char *code = active_infinity_last_error();
    if (code == NULL || strcmp(code, expected_code) != 0) {
      fprintf(stderr, "wrong code: %s, want %s\n",
              code != NULL ? code : "infinity/unknown", expected_code);
      free(image);
      return 1;
    }
    printf("PASS (refused with %s)\n", expected_code);
    free(image);
    return 0;
  }

  if (!expect(active_infinity_validate(image, len), "validate")) {
    free(image);
    return 1;
  }

  /* INF-POLY-03: `validate` already proves the canonical form (INF-02);
     this states the requirement explicitly. */
  if (!expect(active_infinity_validate_canonical(image, len),
              "validate canonical")) {
    free(image);
    return 1;
  }

  uint8_t hash[32];
  if (!expect(active_infinity_content_hash(image, len, hash), "content hash")) {
    free(image);
    return 1;
  }
  char hex[65];
  static const char digits[] = "0123456789abcdef";
  for (size_t index = 0; index < sizeof hash; index++) {
    hex[2 * index] = digits[hash[index] >> 4];
    hex[2 * index + 1] = digits[hash[index] & 0x0f];
  }
  hex[64] = '\0';
  printf("hash=%s\n", hex);
  /* INF-POLY-02: the consumer used to print the hash without comparing it
     to the manifest, so a wrong hash passed silently. */
  if (expected_hash != NULL && strcmp(hex, expected_hash) != 0) {
    fprintf(stderr, "hash mismatch: %s, want %s\n", hex, expected_hash);
    free(image);
    return 1;
  }

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
