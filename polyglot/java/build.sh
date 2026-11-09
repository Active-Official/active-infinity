#!/usr/bin/env bash
# Build and run the JVM binding in one step.
#
#   bash polyglot/java/build.sh
#
# Requires: cargo, gcc, a JDK (javac in JAVA_HOME or on PATH).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/polyglot/java"

# XPL-INF-06: the JNI include directory, the bridge output name, the linked
# FFI library and the link libraries are per-OS. The script used to hardcode
# `include/linux`, `libactive_infinity_jni.so`, `libactive_infinity_ffi.a`
# and `-ldl`, so it could not build on a Windows or macOS JDK at all
# (Windows keeps jni_md.h in `include/win32`, macOS in `include/darwin`;
# neither has libdl; and System.loadLibrary("active_infinity_jni") looks
# for `active_infinity_jni.dll` on Windows, with no `lib` prefix).
case "$(uname -s)" in
  Darwin*)
    JNI_OS="darwin"
    JNI_LIB="libactive_infinity_jni.dylib"
    FFI_LIB="libactive_infinity_ffi.a"
    EXTRA_LIBS=(-lpthread -lm)
    ;;
  MINGW*|MSYS*|CYGWIN*)
    JNI_OS="win32"
    JNI_LIB="active_infinity_jni.dll"
    # MinGW gcc cannot link the MSVC static library
    # (`active_infinity_ffi.lib`: MSVC objects, __chkstk / C++ RTTI), so the
    # bridge links the cdylib's import library instead; the FFI `.dll` is
    # copied next to it below so the JVM run finds it.
    FFI_LIB="active_infinity_ffi.dll.lib"
    EXTRA_LIBS=(-lpthread -lm)
    ;;
  *)
    JNI_OS="linux"
    JNI_LIB="libactive_infinity_jni.so"
    FFI_LIB="libactive_infinity_ffi.a"
    EXTRA_LIBS=(-lpthread -ldl -lm)
    ;;
esac

# JAVA_HOME: honour the environment, then the macOS launcher, then the
# javac on PATH. `readlink -f` is GNU-only and fails on macOS.
if [ -n "${JAVA_HOME:-}" ]; then
  :
elif [ "$JNI_OS" = "darwin" ] && [ -x /usr/libexec/java_home ]; then
  JAVA_HOME="$(/usr/libexec/java_home)"
else
  JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
fi

cargo build --release --manifest-path "$ROOT/ffi/active-infinity-ffi/Cargo.toml"

gcc -shared -fPIC -O2 \
  -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/$JNI_OS" \
  -I"$ROOT/ffi/active-infinity-ffi/include" \
  "$OUT/native/active_infinity_jni.c" \
  "$ROOT/ffi/active-infinity-ffi/target/release/$FFI_LIB" \
  "${EXTRA_LIBS[@]}" -o "$OUT/$JNI_LIB"

# On Windows the bridge links the shared library: copy the FFI `.dll` next
# to it so the JVM run finds it (Windows searches the loading module's
# directory for its dependencies).
if [ "$JNI_OS" = "win32" ]; then
  cp "$ROOT/ffi/active-infinity-ffi/target/release/active_infinity_ffi.dll" "$OUT/"
fi

rm -rf "$OUT/classes"
mkdir -p "$OUT/classes"
find "$OUT/src" -name '*.java' -print0 | xargs -0 javac --release 17 -d "$OUT/classes"

cd "$ROOT"
java -Djava.library.path="$OUT" -cp "$OUT/classes" ai.activeinfinity.Conformance
