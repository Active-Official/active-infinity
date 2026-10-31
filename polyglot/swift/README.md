# Swift binding

The Swift module links the Rust reference directly through a
`systemLibrary` target (`CActiveInfinity`, which maps
`ffi/active-infinity-ffi/include/active_infinity.h`). The `Image` value type in
`Sources/Conformance/main.swift` wraps the ABI with typed, throwing calls.

## Prerequisites

- Swift 5.9 or newer (`swift build`)
- `cargo` (the package links `libactive_infinity_ffi`)

## Conformance

```text
(cd ffi/active-infinity-ffi && cargo build --release)
cd polyglot/swift && swift build -c release && cd ../..
LD_LIBRARY_PATH="$PWD/ffi/active-infinity-ffi/target/release" \
  polyglot/swift/.build/release/Conformance
```

## Quickstart

Add `CActiveInfinity` as a dependency, then use the same calls the conformance
runner uses:

```swift
let image = try Image.fromFile("module.ainf")
try image.validate()
let hash = try image.contentHashHex()       // 64 hex characters
let canonical = try image.reencode()        // [UInt8]
let json = try image.redactedJSON()         // String
let built = try Image.fromActive("module demo { }", name: "demo.active")
```

Failures throw `ActiveInfinityError.failure(code:status:)` with the stable
`infinity/...` code. `Image` lives in `Sources/Conformance/main.swift`; copy
that file (or move it into a library target) when embedding the binding.

## Active RPC

`polyglot/rpc/rpc_client.swift` is the thin ARP1 client:

```text
bash polyglot/rpc/run_clients.sh /path/to/active-rpc "$PWD" swift
```
