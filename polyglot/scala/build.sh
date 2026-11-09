#!/usr/bin/env bash
# Build and run the Scala conformance test.
#
#   bash polyglot/scala/build.sh
#
# Requires the Java binding built by polyglot/java/build.sh and network access
# the first time (scala-cli downloads the compiler).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
JAVA_OUT="$ROOT/polyglot/java"
SCALA_CLI="${SCALA_CLI:-/tmp/scala-cli}"
VERSION="${SCALA_CLI_VERSION:-1.5.4}"

if [ ! -x "$SCALA_CLI" ]; then
  curl -fL "https://github.com/VirtusLab/scala-cli/releases/download/v${VERSION}/scala-cli-x86_64-pc-linux.gz" \
    | gunzip > "$SCALA_CLI"
  chmod +x "$SCALA_CLI"
fi

cd "$ROOT"
rm -rf polyglot/scala/.scala-build
# NF-XPL06-01: the JVM loads the JNI bridge via java.library.path, but the
# bridge's own dependency (active_infinity_ffi.dll on Windows) is found
# only via PATH — a plain LoadLibrary does not search the loaded module's
# directory. Without this the run fails with "Can't find dependent
# libraries".
PATH="$JAVA_OUT:$PATH" "$SCALA_CLI" run polyglot/scala \
  --classpath "$JAVA_OUT/classes" \
  --java-opt "-Djava.library.path=$JAVA_OUT" \
  --main-class Conformance \
  --jvm system \
  --server=false \
  --suppress-experimental-feature-warning
