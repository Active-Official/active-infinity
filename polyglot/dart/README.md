# Dart binding

`package:active_infinity` wraps the C ABI with `dart:ffi`. Validation, hashing,
canonical re-encoding and redacted JSON call the Rust reference.

## Prerequisites

- Dart 3.x (`dart` on `PATH`)
- `cargo` (build `libactive_infinity_ffi`)

## Conformance

```text
(cd ffi/active-infinity-ffi && cargo build --release)
ACTIVE_INFINITY_LIB="$PWD/ffi/active-infinity-ffi/target/release/libactive_infinity_ffi.so" \
  dart run polyglot/dart/bin/conformance.dart
```

## Quickstart

```dart
import 'package:active_infinity/active_infinity.dart';

final image = Image.fromFile('module.ainf').validate();
print(image.contentHashHex());
final canonical = image.reencode();
final json = image.redactedJson();
final built = Image.fromActive('module demo { }', name: 'demo.active');
```

Failures throw `ActiveInfinityException` with `code` (`infinity/...`) and
`status`. Without `ACTIVE_INFINITY_LIB`, the binding opens the platform library
name (`libactive_infinity_ffi.so`, `.dylib`, `active_infinity_ffi.dll`).

## Active RPC

`polyglot/rpc/dart_client.dart` is the thin ARP1 client:

```text
bash polyglot/rpc/run_clients.sh /path/to/active-rpc "$PWD" dart
```
