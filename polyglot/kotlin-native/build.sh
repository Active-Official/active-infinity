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
KONAN="$CACHE/kotlin-native"
# Keep the LLVM/libffi dependency downloads with the compiler so a fresh
# container reuses them instead of re-downloading ~110 MB.
export KONAN_DATA_DIR="${KONAN_DATA_DIR:-$CACHE/konan-data}"

POLYGLOT_CACHE="$CACHE" bash "$OUT/install.sh"

cargo build --release --manifest-path "$ROOT/ffi/active-infinity-ffi/Cargo.toml"

cd "$OUT"
"$KONAN/bin/konanc" -o conformance src/Conformance.kt

cd "$ROOT"
LD_LIBRARY_PATH="$ROOT/ffi/active-infinity-ffi/target/release${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  "$OUT/conformance.kexe"
