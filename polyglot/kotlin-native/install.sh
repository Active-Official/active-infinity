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

# XPL-INF-06: the compiler download is per-OS. It used to fetch the Linux
# prebuilt unconditionally, so a macOS or Windows host downloaded a compiler
# it could not run. Asset names verified against the v2.0.21 release; the
# Windows prebuilt is a .zip, the rest are .tar.gz. The Linux row is
# unchanged, so a warm Linux cache keeps working.
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  PLATFORM="macos-aarch64"; EXT="tar.gz" ;;
  Darwin-x86_64) PLATFORM="macos-x86_64";  EXT="tar.gz" ;;
  MINGW*-x86_64|MSYS*-x86_64|CYGWIN*-x86_64) PLATFORM="windows-x86_64"; EXT="zip" ;;
  Linux-x86_64)  PLATFORM="linux-x86_64";  EXT="tar.gz" ;;
  *) echo "install.sh: unsupported host $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

mkdir -p "$CACHE"
archive="$CACHE/kotlin-native-$VERSION.$EXT"
if [ ! -f "$archive" ]; then
	curl -fL "https://github.com/JetBrains/kotlin/releases/download/v${VERSION}/kotlin-native-prebuilt-${PLATFORM}-${VERSION}.${EXT}" \
		-o "$archive"
fi
if [ "$EXT" = "zip" ]; then
	unzip -q -o "$archive" -d "$CACHE"
else
	tar -xzf "$archive" -C "$CACHE"
fi
rm -rf "$KONAN"
mv "$CACHE/kotlin-native-prebuilt-${PLATFORM}-${VERSION}" "$KONAN"
