#!/usr/bin/env bash
# Build and run the Kotlin/JVM conformance test.
#
#   bash polyglot/kotlin/build.sh
#
# Requires kotlinc and the Java binding built by polyglot/java/build.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
JAVA_OUT="$ROOT/polyglot/java"
JAR="${TMPDIR:-/tmp}/active-infinity-kotlin.jar"

kotlinc -cp "$JAVA_OUT/classes" -include-runtime -d "$JAR" \
  "$ROOT/polyglot/kotlin/src/Conformance.kt"

cd "$ROOT"
java -Djava.library.path="$JAVA_OUT" -cp "$JAR:$JAVA_OUT/classes" ConformanceKt
