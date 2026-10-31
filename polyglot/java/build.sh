#!/usr/bin/env bash
# Build and run the JVM binding in one step.
#
#   bash polyglot/java/build.sh
#
# Requires: cargo, gcc, a JDK (javac in JAVA_HOME or on PATH).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
JAVA_HOME="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")}"
OUT="$ROOT/polyglot/java"

cargo build --release --manifest-path "$ROOT/ffi/active-infinity-ffi/Cargo.toml"

gcc -shared -fPIC -O2 \
  -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
  -I"$ROOT/ffi/active-infinity-ffi/include" \
  "$OUT/native/active_infinity_jni.c" \
  "$ROOT/ffi/active-infinity-ffi/target/release/libactive_infinity_ffi.a" \
  -lpthread -ldl -lm -o "$OUT/libactive_infinity_jni.so"

rm -rf "$OUT/classes"
mkdir -p "$OUT/classes"
find "$OUT/src" -name '*.java' -print0 | xargs -0 javac --release 17 -d "$OUT/classes"

cd "$ROOT"
java -Djava.library.path="$OUT" -cp "$OUT/classes" ai.activeinfinity.Conformance
