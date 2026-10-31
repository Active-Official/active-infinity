# Kotlin/Native binding

Kotlin/Native loads the C ABI with `dlopen` instead of linking against it. That
avoids the compiler's bundled sysroot, which is older than the glibc the shared
library expects, and keeps the ABI surface identical to the other bindings.

## Prerequisites

- The Kotlin/Native 2.0.21 compiler. `polyglot/kotlin-native/build.sh`
  downloads it into `POLYGLOT_CACHE` (default `/cache`) on first use.
- `cargo` (the shared library is built by the script).

## Conformance

```text
POLYGLOT_CACHE=/path/to/cache bash polyglot/kotlin-native/build.sh
```

The script sets `KONAN_DATA_DIR` under the cache as well, so the LLVM and
sysroot downloads are reused across containers.

## Quickstart

The binding pattern lives in `src/Conformance.kt`: declare the six ABI
functions with `CFunction`, resolve them with `dlsym`, and copy byte arrays in
and out of `active_infinity_alloc` buffers.

```kotlin
val handle = dlopen("libactive_infinity_ffi.so", RTLD_NOW) ?: error("cannot load")
val validate = dlsym(handle, "active_infinity_validate")!!
    .reinterpret<CFunction<(CPointer<UByteVar>?, ULong) -> Int>>()
val status = validate(pointer, length.toULong())
```

Set `ACTIVE_INFINITY_LIB` to override the library name. Status codes are the
same as the C ABI: `0` ok, `-1` invalid, `-2` buffer too small, `-3` panic.

## Active RPC

`polyglot/rpc/kotlin_native_client.kt` is the thin ARP1 client, built and run by
`polyglot/rpc/build_kotlin_native.sh`:

```text
POLYGLOT_CACHE=/path/to/cache \
  bash polyglot/rpc/run_clients.sh /path/to/active-rpc "$PWD" ktnative
```
