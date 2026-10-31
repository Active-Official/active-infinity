#!/usr/bin/env bash
# Install the Kotlin/Native compiler into POLYGLOT_CACHE (idempotent).
#
#   POLYGLOT_CACHE=/cache bash polyglot/kotlin-native/install.sh
#
# Shared by the Kotlin/Native conformance build and the RPC client build so both
# work on a cold cache.
set -euo pipefail

CACHE="${POLYGLOT_CACHE:-/cache}"
VERSION="${KOTLIN_NATIVE_VERSION:-2.0.21}"
KONAN="$CACHE/kotlin-native"

if [ -x "$KONAN/bin/konanc" ]; then
	exit 0
fi

mkdir -p "$CACHE"
archive="$CACHE/kotlin-native-$VERSION.tar.gz"
if [ ! -f "$archive" ]; then
	curl -fL "https://github.com/JetBrains/kotlin/releases/download/v${VERSION}/kotlin-native-prebuilt-linux-x86_64-${VERSION}.tar.gz" \
		-o "$archive"
fi
tar -xzf "$archive" -C "$CACHE"
rm -rf "$KONAN"
mv "$CACHE/kotlin-native-prebuilt-linux-x86_64-${VERSION}" "$KONAN"
