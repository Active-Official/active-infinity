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

# XPL-INF-06: the loader is per-OS. Windows has no `dlopen`, so the mingw
# target compiles WindowsLoader.kt (LoadLibraryW) instead of
# PosixLoader.kt (dlopen); the two files implement the same
# openNativeLibrary/loadSymbol surface, and exactly one is compiled.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    LOADER="WindowsLoader.kt"
    ;;
  *)
    LOADER="PosixLoader.kt"
    ;;
esac

cd "$OUT"
"$KONAN/bin/konanc" -o conformance src/Conformance.kt "src/$LOADER"

cd "$ROOT"
# The reference library is found through the platform loader's search:
# LD_LIBRARY_PATH on Linux, DYLD_LIBRARY_PATH on macOS, PATH on Windows.
# konanc emits `conformance.kexe` on POSIX targets and `conformance.exe`
# on Windows.
BIN="$OUT/conformance.kexe"
[ -x "$BIN" ] || BIN="$OUT/conformance.exe"
case "$(uname -s)" in
  Darwin*)
    DYLD_LIBRARY_PATH="$ROOT/ffi/active-infinity-ffi/target/release${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
      "$BIN"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    PATH="$ROOT/ffi/active-infinity-ffi/target/release:$PATH" \
      "$BIN"
    ;;
  *)
    LD_LIBRARY_PATH="$ROOT/ffi/active-infinity-ffi/target/release${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
      "$BIN"
    ;;
esac
