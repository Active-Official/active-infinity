# Scala binding

Scala reuses the JNI-backed Java binding (`ai.activeinfinity.ActiveInfinity`).
There is no Scala-specific codec: one canonicalizer, one hash.

## Prerequisites

- JDK 17 or newer
- `scala-cli` 1.5.4 (`SCALA_CLI` points at the binary; the build script
  downloads it on first use)
- The Java binding built first: `bash polyglot/java/build.sh`

## Conformance

```text
bash polyglot/scala/build.sh
```

`scala-cli` compiles `polyglot/scala/Conformance.scala` against the Java classes
and runs it against the shared manifest. The first run downloads the Scala 3
compiler.

## Quickstart

```scala
import ai.activeinfinity.ActiveInfinity
import java.nio.file.{Files, Path}

val image = Files.readAllBytes(Path.of("module.ainf"))
ActiveInfinity.validate(image)
val hash = ActiveInfinity.contentHashHex(image)
val canonical = ActiveInfinity.reencode(image)
val json = ActiveInfinity.redactedJson(image)
```

## Active RPC

`polyglot/rpc/ScalaRpc.scala` drives the Java client from Scala:

```text
SCALA_CLI=/path/to/scala-cli \
  bash polyglot/rpc/run_clients.sh /path/to/active-rpc "$PWD" scala
```
