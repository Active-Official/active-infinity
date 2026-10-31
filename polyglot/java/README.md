# Java binding

`ai.activeinfinity.ActiveInfinity` is a thin JNI layer over the C ABI. Validation,
content hashes, canonical re-encoding and redacted JSON all run in the Rust
reference, so Java bytes and hashes cannot drift from every other language.

## Prerequisites

- JDK 17 or newer (`javac` on `PATH` or `JAVA_HOME` set)
- `gcc` (the JNI bridge is a small C file)
- `cargo`

## Build and run the conformance test

```text
bash polyglot/java/build.sh
```

The script builds the shared library, compiles the JNI bridge, compiles the Java
sources into `polyglot/java/classes`, and runs `ai.activeinfinity.Conformance`
against `conformance/manifest.json`.

## Quickstart

```java
import ai.activeinfinity.ActiveInfinity;
import java.nio.file.Path;

byte[] image = ActiveInfinity.readFile(Path.of("module.ainf"));
ActiveInfinity.validate(image);
String hash = ActiveInfinity.contentHashHex(image);
byte[] canonical = ActiveInfinity.reencode(image);
String json = ActiveInfinity.redactedJson(image);
byte[] built = ActiveInfinity.fromActive("module demo { }", "demo.active");
```

Failures raise `ActiveInfinity.Error`; `error.code()` is the stable
`infinity/...` code and `error.status()` is the ABI status (`-1` invalid, `-2`
buffer too small, `-3` panic).

The shared library must be discoverable: pass
`-Djava.library.path=ffi/active-infinity-ffi/target/release` (the build script
already points at `polyglot/java`, where the JNI bridge lives).

## Active RPC

`polyglot/rpc/RpcClient.java` is the thin ARP1 client: it presents a capability,
sends an AINF payload, verifies the echo, and surfaces
`rpc/method-not-granted` and `rpc/unknown-capability`.

```text
bash polyglot/rpc/run_clients.sh /path/to/active-rpc "$PWD" java
```
