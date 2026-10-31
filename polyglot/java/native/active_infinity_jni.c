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

JNIEXPORT jint JNICALL Java_ai_activeinfinity_Native_redactedJson(
    JNIEnv *env, jclass clazz, jbyteArray image, jbyteArray output,
    jintArray out_len) {
  (void)clazz;
  return output_call(env, image, output, out_len,
                     active_infinity_redacted_json);
}

JNIEXPORT jint JNICALL Java_ai_activeinfinity_Native_fromActive(
    JNIEnv *env, jclass clazz, jbyteArray source, jstring name,
    jbyteArray output, jintArray out_len) {
  (void)clazz;
  if (source == NULL || name == NULL || out_len == NULL) {
    return -1;
  }
  const char *name_chars = (*env)->GetStringUTFChars(env, name, NULL);
  if (name_chars == NULL) {
    return -3;
  }
  jsize length = (*env)->GetArrayLength(env, source);
  jbyte *bytes = (*env)->GetByteArrayElements(env, source, NULL);
  if (bytes == NULL) {
    (*env)->ReleaseStringUTFChars(env, name, name_chars);
    return -3;
  }
  jint capacity = 0;
  (*env)->GetIntArrayRegion(env, out_len, 0, 1, &capacity);
  size_t out_capacity = capacity > 0 ? (size_t)capacity : 0;
  jbyte *out_bytes = NULL;
  uint8_t *out = NULL;
  if (output != NULL && out_capacity > 0) {
    out_bytes = (*env)->GetByteArrayElements(env, output, NULL);
    if (out_bytes == NULL) {
      (*env)->ReleaseByteArrayElements(env, source, bytes, JNI_ABORT);
      (*env)->ReleaseStringUTFChars(env, name, name_chars);
      return -3;
    }
    out = (uint8_t *)out_bytes;
  }
  size_t written = out_capacity;
  int32_t status = active_infinity_from_active(
      (const uint8_t *)bytes, (size_t)length, name_chars, out, &written);
  (*env)->ReleaseByteArrayElements(env, source, bytes, JNI_ABORT);
  (*env)->ReleaseStringUTFChars(env, name, name_chars);
  if (out_bytes != NULL) {
    (*env)->ReleaseByteArrayElements(env, output, out_bytes,
                                     status == 0 ? 0 : JNI_ABORT);
  }
  jint reported = (jint)written;
  (*env)->SetIntArrayRegion(env, out_len, 0, 1, &reported);
  return (jint)status;
}
