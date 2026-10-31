# Polyglot bindings (Active Infinity)

One canonicalizer: every binding calls the Rust reference through the C ABI or
the shared WASM module, so canonical bytes and content hashes cannot drift.

- **C ABI**: `ffi/active-infinity-ffi/include/active_infinity.h`, ABI version 1.
- **WASM**: `ffi/active-infinity-ffi` built for `wasm32-unknown-unknown` with one
  host import (`env.active_random_fill`).
- **Vectors**: `conformance/manifest.json` is the shared oracle for every
  language.

Build the artifacts once (from the repository root):

```text
(cd ffi/active-infinity-ffi && cargo build --release)
(cd ffi/active-infinity-ffi && rustup target add wasm32-unknown-unknown \
  && cargo build --release --target wasm32-unknown-unknown)
```

## Status

| # | Language | Binding | Conformance test | CI job |
|---|----------|---------|------------------|--------|
| 1 | Rust | reference crate | full suite | `gates` |
| 2 | C | `polyglot/c` | `consumer.c` | `abi` |
| 3 | C++ | `polyglot/cpp` (RAII) | `test.cpp` | `polyglot-native` |
| 4 | Python | `polyglot/python` (ctypes) | `test_conformance.py` | `polyglot-native` |
| 5 | Go | `polyglot/go` (wazero) | `go test ./...` | `polyglot-go` |
| 6 | TypeScript | `polyglot/ts` | `conformance.ts` (`tsc --strict`) | `polyglot-ts` |
| 7 | JavaScript | `polyglot/js` | `test.js` | `wasm`, `polyglot-ts` |
| 8 | Java | `polyglot/java` (JNI) | `Conformance.java` | `polyglot-jvm` |
| 9 | C# / .NET | `polyglot/csharp` (P/Invoke) | `Conformance/Program.cs` | `polyglot-dotnet` |
| 10 | Kotlin/JVM | `polyglot/kotlin` (JNI) | `Conformance.kt` | `polyglot-jvm` |
| 11 | Swift | `polyglot/swift` (C interop) | `Sources/Conformance` | `polyglot-swift` |
| 12 | Zig | `polyglot/zig` (`@cImport`) | `zig build run` | `polyglot-native` |
| 13 | Ruby | `polyglot/ruby` (FFI gem) | `test_conformance.rb` | `polyglot-scripting` |
| 14 | PHP | `polyglot/php` (ext-ffi) | `test.php` | `polyglot-scripting` |
| 15 | Scala | `polyglot/scala` (JVM) | `Conformance.scala` | `polyglot-jvm` |
| 16 | Dart | `polyglot/dart` (`dart:ffi`) | `bin/conformance.dart` | `polyglot-scripting` |
| 17 | Kotlin/Native | `polyglot/kotlin-native` (dlopen) | `Conformance.kt` | `polyglot-kotlin-native` |
| 18 | AssemblyScript | `polyglot/assemblyscript` (WASM host) | `test.js` | `polyglot-assemblyscript` |
| 19 | Lua | `polyglot/lua` (LuaJIT FFI) | `test.lua` | `polyglot-scripting` |
| 20 | Shell / ops | `active-infinity-cli` | `polyglot/shell/test.sh` | `polyglot-shell` |

Every row validates an AINF image, reproduces the manifest content hash,
re-encodes to canonical bytes, compiles Active text, and asserts that the
redaction canary `CANARY_SECRET_` never appears. The RPC thin client for each
language is tracked separately in `polyglot/rpc/PROTOCOL.md` (C-8.3).

### Notes on toolchains

- Kotlin/Native links the ABI with `dlopen`, so it does not inherit the
  compiler's old sysroot at link time.
- AssemblyScript cannot host a second WASM module; `host.js` binds its imports to
  the reference module and copies across the two linear memories.
- The shared library must be findable at run time: set `ACTIVE_INFINITY_LIB`, or
  put `ffi/active-infinity-ffi/target/release` on the loader path.

## Quickstarts

### C

```text
gcc -I ffi/active-infinity-ffi/include polyglot/c/consumer.c \
    ffi/active-infinity-ffi/target/release/libactive_infinity_ffi.a \
    -lpthread -ldl -lm -o consumer
./consumer tests/vectors/valid/full.ainf
```

`active_infinity_validate`, `..._content_hash`, `..._reencode`,
`..._from_active` and `..._redacted_json` return 0 on success; a failure sets a
thread-local `infinity/...` code readable with `active_infinity_last_error`.

### C++

Header-only RAII over the C ABI (`polyglot/cpp/active_infinity.hpp`):

```cpp
#include "active_infinity.hpp"
auto image = active_infinity::Image::from_file("module.ainf");
image.validate();
auto hash = image.content_hash_hex();
auto canonical = image.reencode();
```

```text
g++ -std=c++17 -I ffi/active-infinity-ffi/include -I polyglot/cpp \
    polyglot/cpp/test.cpp <library> -o test_cpp
```

### Python

```python
from active_infinity import Image

image = Image(open("module.ainf", "rb").read()).validate()
print(image.content_hash_hex())
canonical = image.reencode()
json_text = image.redacted_json()
```

Point `ACTIVE_INFINITY_LIB` at the shared library, then
`python polyglot/python/test_conformance.py`.

### Go

```go
instance, _ := activeinfinity.New(ctx, "active_infinity_ffi.wasm")
defer instance.Close(ctx)
instance.Validate(ctx, image)
hash, _ := instance.ContentHashHex(ctx, image)
```

Requires only the WASM artifact; `go test ./...` in `polyglot/go` runs the
manifest.

### JavaScript

```js
const { ActiveInfinity } = require('./polyglot/js/active-infinity.js');
const binding = await ActiveInfinity.instantiate(wasmBytes);
binding.validate(image);
const hash = Buffer.from(binding.contentHash(image)).toString('hex');
```

### TypeScript

The same package ships `index.d.ts`; `polyglot/ts/conformance.ts` is compiled
with `tsc --strict` and executed against the manifest.

### Zig

```text
cd polyglot/zig && zig build
./zig-out/bin/active-infinity-zig ../../tests/vectors/valid/full.ainf
```

Uses `@cImport` of the C header and the same shared library.

## Redaction

Every binding exposes `redacted_json` (or the equivalent) and its conformance
test asserts that `CANARY_SECRET_` never appears. The canary is the same fixture
the Rust redaction suite uses.
