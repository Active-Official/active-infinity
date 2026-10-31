#!/usr/bin/env bash
# Build and run the Kotlin/Native thin RPC client.
# Requires POLYGLOT_CACHE (default /cache) with the compiler already downloaded
# by polyglot/kotlin-native/build.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE="${POLYGLOT_CACHE:-/cache}"
KONAN="$CACHE/kotlin-native"
export KONAN_DATA_DIR="${KONAN_DATA_DIR:-$CACHE/konan-data}"

if [ ! -x "$KONAN/bin/konanc" ]; then
  echo "Kotlin/Native is not installed; run polyglot/kotlin-native/build.sh first" >&2
  exit 1
fi

"$KONAN/bin/konanc" -o /tmp/rpc-client-kotlin-native "$ROOT/polyglot/rpc/kotlin_native_client.kt"
/tmp/rpc-client-kotlin-native.kexe
