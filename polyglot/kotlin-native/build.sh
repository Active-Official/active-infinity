#!/usr/bin/env bash
# Build and run the Kotlin/Native conformance test.
#
#   POLYGLOT_CACHE=/cache bash polyglot/kotlin-native/build.sh
#
# The Kotlin/Native compiler is downloaded once into POLYGLOT_CACHE (default
# /cache, meant to be a host-mounted cache directory).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/polyglot/kotlin-native"
CACHE="${POLYGLOT_CACHE:-/cache}"
VERSION="${KOTLIN_NATIVE_VERSION:-2.0.21}"
KONAN="$CACHE/kotlin-native"

if [ ! -x "$KONAN/bin/konanc" ]; then
  mkdir -p "$CACHE"
  archive="$CACHE/kotlin-native-$VERSION.tar.gz"
  if [ ! -f "$archive" ]; then
    curl -fL "https://github.com/JetBrains/kotlin/releases/download/v${VERSION}/kotlin-native-prebuilt-linux-x86_64-${VERSION}.tar.gz" \
      -o "$archive"
  fi
  tar -xzf "$archive" -C "$CACHE"
  mv "$CACHE/kotlin-native-prebuilt-linux-x86_64-${VERSION}" "$KONAN"
fi

cargo build --release --manifest-path "$ROOT/ffi/active-infinity-ffi/Cargo.toml"

cd "$OUT"
"$KONAN/bin/konanc" -o conformance src/Conformance.kt

cd "$ROOT"
LD_LIBRARY_PATH="$ROOT/ffi/active-infinity-ffi/target/release${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  "$OUT/conformance.kexe"
