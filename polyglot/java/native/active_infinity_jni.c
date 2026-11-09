/*
 * JNI glue for the Active Infinity C ABI.
 *
 * The Java/Kotlin/Scala binding loads this library, which links the Rust static
 * library. Keeping the glue in C means the JVM binding has no preview APIs and
 * no extra runtime dependency.
 */

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>

#include "active_infinity.h"

static void copy_error(JNIEnv *env, jclass clazz) {
  (void)env;
  (void)clazz;
}

/* Build the C limits struct from a Java long[24] in struct order, or the
   library defaults when the array is null. Returns 0 on success. */
static int limits_from_array(JNIEnv *env, jlongArray values,
                             active_infinity_limits *limits) {
  if (values == NULL) {
    return active_infinity_limits_default(limits) == 0 ? 0 : -1;
  }
  if ((*env)->GetArrayLength(env, values) < 24) {
    return -1;
  }
  jlong *elements = (*env)->GetLongArrayElements(env, values, NULL);
  if (elements == NULL) {
    return -3;
  }
  limits->max_nodes = (uint32_t)elements[0];
  limits->max_edges = (uint32_t)elements[1];
  limits->max_children = (uint32_t)elements[2];
  limits->max_fields = (uint32_t)elements[3];
  limits->max_parts = (uint32_t)elements[4];
  limits->max_strings = (uint32_t)elements[5];
  limits->max_string_bytes = (uint32_t)elements[6];
  limits->max_blobs = (uint32_t)elements[7];
  limits->max_blob_bytes = (uint32_t)elements[8];
  limits->max_annotations = (uint32_t)elements[9];
  limits->max_units = (uint32_t)elements[10];
  limits->max_types = (uint32_t)elements[11];
  limits->max_aux = (uint32_t)elements[12];
  limits->max_numbers = (uint32_t)elements[13];
  limits->max_secrets = (uint32_t)elements[14];
  limits->max_secret_bytes = (uint32_t)elements[15];
  limits->max_extensions = (uint32_t)elements[16];
  limits->max_prov_bytes = (uint32_t)elements[17];
  limits->max_prov_entries = (uint32_t)elements[18];
  limits->max_hashes = (uint32_t)elements[19];
  limits->max_bindings = (uint32_t)elements[20];
  limits->max_total_bytes = (uint64_t)elements[21];
  limits->max_decoded_bytes = (uint64_t)elements[22];
  limits->max_depth = (uint32_t)elements[23];
  (*env)->ReleaseLongArrayElements(env, values, elements, JNI_ABORT);
  return 0;
}

/* Write the C limits struct into a Java long[24] in struct order. */
static int limits_to_array(JNIEnv *env, jlongArray values,
                           const active_infinity_limits *limits) {
  if (values == NULL || (*env)->GetArrayLength(env, values) < 24) {
    return -1;
  }
  jlong elements[24] = {
      (jlong)limits->max_nodes,       (jlong)limits->max_edges,
      (jlong)limits->max_children,    (jlong)limits->max_fields,
      (jlong)limits->max_parts,       (jlong)limits->max_strings,
      (jlong)limits->max_string_bytes, (jlong)limits->max_blobs,
      (jlong)limits->max_blob_bytes,  (jlong)limits->max_annotations,
      (jlong)limits->max_units,       (jlong)limits->max_types,
      (jlong)limits->max_aux,         (jlong)limits->max_numbers,
      (jlong)limits->max_secrets,     (jlong)limits->max_secret_bytes,
      (jlong)limits->max_extensions,  (jlong)limits->max_prov_bytes,
      (jlong)limits->max_prov_entries, (jlong)limits->max_hashes,
      (jlong)limits->max_bindings,    (jlong)limits->max_total_bytes,
      (jlong)limits->max_decoded_bytes, (jlong)limits->max_depth,
  };
  (*env)->SetLongArrayRegion(env, values, 0, 24, elements);
  return 0;
}

/* output_call for the limits-parameterized outputs: the same two-phase
   probe, with the limits struct threaded through the call. */
static jint output_limits_call(
    JNIEnv *env, jbyteArray image, jbyteArray output, jintArray out_len,
    int32_t (*call)(const uint8_t *, size_t, const active_infinity_limits *,
                    uint8_t *, size_t *),
    const active_infinity_limits *limits) {
  if (image == NULL || out_len == NULL ||
      (*env)->GetArrayLength(env, out_len) < 1) {
    return -1;
  }
  jsize length = (*env)->GetArrayLength(env, image);
  jbyte *bytes = (*env)->GetByteArrayElements(env, image, NULL);
  if (bytes == NULL) {
    return -3;
  }
  jint capacity = 0;
  (*env)->GetIntArrayRegion(env, out_len, 0, 1, &capacity);
  /* The caller's claimed capacity is not trusted: clamp it to the real array
     length, or a Java caller can hand a small array with a huge capacity and
     the shim writes past the JVM heap buffer. */
  if (output != NULL) {
    jsize array_length = (*env)->GetArrayLength(env, output);
    if (capacity > array_length) {
      capacity = (jint)array_length;
    }
  }
  size_t out_capacity = capacity > 0 ? (size_t)capacity : 0;
  uint8_t *out = NULL;
  jbyte *out_bytes = NULL;
  if (output != NULL && out_capacity > 0) {
    out_bytes = (*env)->GetByteArrayElements(env, output, NULL);
    if (out_bytes == NULL) {
      (*env)->ReleaseByteArrayElements(env, image, bytes, JNI_ABORT);
      return -3;
    }
    out = (uint8_t *)out_bytes;
  }
  size_t written = out_capacity;
  int32_t status =
      call((const uint8_t *)bytes, (size_t)length, limits, out, &written);
  (*env)->ReleaseByteArrayElements(env, image, bytes, JNI_ABORT);
  if (out_bytes != NULL) {
    (*env)->ReleaseByteArrayElements(env, output, out_bytes,
                                     status == 0 ? 0 : JNI_ABORT);
  }
  jint reported = (jint)written;
  (*env)->SetIntArrayRegion(env, out_len, 0, 1, &reported);
  return (jint)status;
}

JNIEXPORT jint JNICALL Java_ai_activeinfinity_Native_abiVersion(JNIEnv *env,
                                                                jclass clazz) {
  (void)env;
  (void)clazz;
  return (jint)active_infinity_abi_version();
}

JNIEXPORT jstring JNICALL
Java_ai_activeinfinity_Native_lastError(JNIEnv *env, jclass clazz) {
  (void)clazz;
  const char *text = active_infinity_last_error();
  return (*env)->NewStringUTF(env, text == NULL ? "infinity/unknown" : text);
}

JNIEXPORT jint JNICALL Java_ai_activeinfinity_Native_validate(
    JNIEnv *env, jclass clazz, jbyteArray image) {
  (void)clazz;
  if (image == NULL) {
    return -1;
  }
  jsize length = (*env)->GetArrayLength(env, image);
  jbyte *bytes = (*env)->GetByteArrayElements(env, image, NULL);
  if (bytes == NULL) {
    return -3;
  }
  int32_t status =
      active_infinity_validate((const uint8_t *)bytes, (size_t)length);
  (*env)->ReleaseByteArrayElements(env, image, bytes, JNI_ABORT);
  return (jint)status;
}

JNIEXPORT jint JNICALL Java_ai_activeinfinity_Native_validateCanonical(
    JNIEnv *env, jclass clazz, jbyteArray image) {
  (void)clazz;
  if (image == NULL) {
    return -1;
  }
  jsize length = (*env)->GetArrayLength(env, image);
  jbyte *bytes = (*env)->GetByteArrayElements(env, image, NULL);
  if (bytes == NULL) {
    return -3;
  }
  int32_t status = active_infinity_validate_canonical((const uint8_t *)bytes,
                                                      (size_t)length);
  (*env)->ReleaseByteArrayElements(env, image, bytes, JNI_ABORT);
  return (jint)status;
}

JNIEXPORT jint JNICALL Java_ai_activeinfinity_Native_hash(JNIEnv *env,
                                                          jclass clazz,
                                                          jbyteArray image,
                                                          jbyteArray output) {
  (void)clazz;
  if (image == NULL || output == NULL ||
      (*env)->GetArrayLength(env, output) < 32) {
    return -1;
  }
  jsize length = (*env)->GetArrayLength(env, image);
  jbyte *bytes = (*env)->GetByteArrayElements(env, image, NULL);
  jbyte *out = (*env)->GetByteArrayElements(env, output, NULL);
  if (bytes == NULL || out == NULL) {
    if (bytes != NULL)
      (*env)->ReleaseByteArrayElements(env, image, bytes, JNI_ABORT);
    if (out != NULL)
      (*env)->ReleaseByteArrayElements(env, output, out, JNI_ABORT);
    return -3;
  }
  int32_t status = active_infinity_content_hash((const uint8_t *)bytes,
                                                (size_t)length, (uint8_t *)out);
  (*env)->ReleaseByteArrayElements(env, image, bytes, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, output, out, 0);
  return (jint)status;
}

static jint
output_call(JNIEnv *env, jbyteArray image, jbyteArray output, jintArray out_len,
            int32_t (*call)(const uint8_t *, size_t, uint8_t *, size_t *)) {
  if (image == NULL || out_len == NULL ||
      (*env)->GetArrayLength(env, out_len) < 1) {
    return -1;
  }
  jsize length = (*env)->GetArrayLength(env, image);
  jbyte *bytes = (*env)->GetByteArrayElements(env, image, NULL);
  if (bytes == NULL) {
    return -3;
  }
  jint capacity = 0;
  (*env)->GetIntArrayRegion(env, out_len, 0, 1, &capacity);
  /* The caller's claimed capacity is not trusted: clamp it to the real array
     length, or a Java caller can hand a small array with a huge capacity and
     the shim writes past the JVM heap buffer. */
  if (output != NULL) {
    jsize array_length = (*env)->GetArrayLength(env, output);
    if (capacity > array_length) {
      capacity = (jint)array_length;
    }
  }
  size_t out_capacity = capacity > 0 ? (size_t)capacity : 0;
  uint8_t *out = NULL;
  jbyte *out_bytes = NULL;
  if (output != NULL && out_capacity > 0) {
    out_bytes = (*env)->GetByteArrayElements(env, output, NULL);
    if (out_bytes == NULL) {
      (*env)->ReleaseByteArrayElements(env, image, bytes, JNI_ABORT);
      return -3;
    }
    out = (uint8_t *)out_bytes;
  }
  size_t written = out_capacity;
  int32_t status = call((const uint8_t *)bytes, (size_t)length, out, &written);
  (*env)->ReleaseByteArrayElements(env, image, bytes, JNI_ABORT);
  if (out_bytes != NULL) {
    (*env)->ReleaseByteArrayElements(env, output, out_bytes,
                                     status == 0 ? 0 : JNI_ABORT);
  }
  jint reported = (jint)written;
  (*env)->SetIntArrayRegion(env, out_len, 0, 1, &reported);
  return (jint)status;
}

JNIEXPORT jint JNICALL Java_ai_activeinfinity_Native_reencode(
    JNIEnv *env, jclass clazz, jbyteArray image, jbyteArray output,
    jintArray out_len) {
  (void)clazz;
  return output_call(env, image, output, out_len, active_infinity_reencode);
}


JNIEXPORT jint JNICALL Java_ai_activeinfinity_Native_limitsDefault(
    JNIEnv *env, jclass clazz, jlongArray values) {
  (void)clazz;
  active_infinity_limits limits;
  if (active_infinity_limits_default(&limits) != 0) {
    return -1;
  }
  return (jint)limits_to_array(env, values, &limits);
}

JNIEXPORT jint JNICALL Java_ai_activeinfinity_Native_validateWithLimits(
    JNIEnv *env, jclass clazz, jbyteArray image, jlongArray limits_values) {
  (void)clazz;
  if (image == NULL) {
    return -1;
  }
  active_infinity_limits limits;
  if (limits_from_array(env, limits_values, &limits) != 0) {
    return -1;
  }
  jsize length = (*env)->GetArrayLength(env, image);
  jbyte *bytes = (*env)->GetByteArrayElements(env, image, NULL);
  if (bytes == NULL) {
    return -3;
  }
  int32_t status = active_infinity_validate_with_limits(
      (const uint8_t *)bytes, (size_t)length, &limits);
  (*env)->ReleaseByteArrayElements(env, image, bytes, JNI_ABORT);
  return (jint)status;
}

JNIEXPORT jint JNICALL Java_ai_activeinfinity_Native_decodeWithLimits(
    JNIEnv *env, jclass clazz, jbyteArray image, jlongArray limits_values,
    jbyteArray output, jintArray out_len) {
  (void)clazz;
  active_infinity_limits limits;
  if (limits_from_array(env, limits_values, &limits) != 0) {
    return -1;
  }
  return output_limits_call(env, image, output, out_len,
                            active_infinity_decode_with_limits, &limits);
}

JNIEXPORT jint JNICALL Java_ai_activeinfinity_Native_redactedJson(
    JNIEnv *env, jclass clazz, jbyteArray image, jbyteArray output,
    jintArray out_len) {
  (void)clazz;
  return output_call(env, image, output, out_len,
                     active_infinity_redacted_json);
}

JNIEXPORT jint JNICALL Java_ai_activeinfinity_Native_fromActive(
    JNIEnv *env, jclass clazz, jbyteArray source, jbyteArray name,
    jbyteArray output, jintArray out_len) {
  (void)clazz;
  if (source == NULL || name == NULL || out_len == NULL) {
    return -1;
  }
  /* The Java side encodes the name as standard UTF-8 with a trailing NUL.
     Copy it into a bounded local buffer so a caller-supplied array that is
     missing the terminator cannot make the shim scan past its end. */
  jsize name_length = (*env)->GetArrayLength(env, name);
  if (name_length <= 0 ||
      name_length > (jsize)(ACTIVE_INFINITY_MAX_NAME_BYTES + 1)) {
    return -1;
  }
  char name_chars[ACTIVE_INFINITY_MAX_NAME_BYTES + 1];
  (*env)->GetByteArrayRegion(env, name, 0, name_length, (jbyte *)name_chars);
  if (name_chars[name_length - 1] != '\0') {
    if (name_length > (jsize)ACTIVE_INFINITY_MAX_NAME_BYTES) {
      return -1;
    }
    name_chars[name_length] = '\0';
  }
  jsize length = (*env)->GetArrayLength(env, source);
  jbyte *bytes = (*env)->GetByteArrayElements(env, source, NULL);
  if (bytes == NULL) {
    return -3;
  }
  jint capacity = 0;
  (*env)->GetIntArrayRegion(env, out_len, 0, 1, &capacity);
  if (output != NULL) {
    jsize array_length = (*env)->GetArrayLength(env, output);
    if (capacity > array_length) {
      capacity = (jint)array_length;
    }
  }
  size_t out_capacity = capacity > 0 ? (size_t)capacity : 0;
  jbyte *out_bytes = NULL;
  uint8_t *out = NULL;
  if (output != NULL && out_capacity > 0) {
    out_bytes = (*env)->GetByteArrayElements(env, output, NULL);
    if (out_bytes == NULL) {
      (*env)->ReleaseByteArrayElements(env, source, bytes, JNI_ABORT);
      return -3;
    }
    out = (uint8_t *)out_bytes;
  }
  size_t written = out_capacity;
  int32_t status = active_infinity_from_active(
      (const uint8_t *)bytes, (size_t)length, name_chars, out, &written);
  (*env)->ReleaseByteArrayElements(env, source, bytes, JNI_ABORT);
  if (out_bytes != NULL) {
    (*env)->ReleaseByteArrayElements(env, output, out_bytes,
                                     status == 0 ? 0 : JNI_ABORT);
  }
  jint reported = (jint)written;
  (*env)->SetIntArrayRegion(env, out_len, 0, 1, &reported);
  return (jint)status;
}
