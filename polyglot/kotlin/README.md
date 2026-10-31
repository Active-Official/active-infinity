# Kotlin/JVM binding

Kotlin uses the Java binding directly: `ai.activeinfinity.ActiveInfinity` is a
JNI layer over the Rust reference, so Kotlin gets the same canonical bytes,
hashes and redaction without a second canonicalizer.

## Prerequisites

- JDK 17 or newer
- `kotlinc` 2.0.x
- The Java binding built first: `bash polyglot/java/build.sh`

## Conformance

```text
bash polyglot/kotlin/build.sh
```

Compiles `polyglot/kotlin/src/Conformance.kt` against the Java classes and runs
it against `conformance/manifest.json`.

## Quickstart

```kotlin
import ai.activeinfinity.ActiveInfinity
import java.io.File

val image = File("module.ainf").readBytes()
ActiveInfinity.validate(image)
val hash = ActiveInfinity.contentHashHex(image)
val canonical = ActiveInfinity.reencode(image)
val json = ActiveInfinity.redactedJson(image)
val built = ActiveInfinity.fromActive("module demo { }", "demo.active")
```

Errors arrive as `ActiveInfinity.Error` with `.code()` and `.status()`.

## Active RPC

`polyglot/rpc/KotlinRpc.kt` reuses the Java client and is compiled and run by
the harness:

```text
bash polyglot/rpc/run_clients.sh /path/to/active-rpc "$PWD" kotlin
```
