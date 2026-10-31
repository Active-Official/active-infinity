# PHP binding

`ActiveInfinity` is an `ext-ffi` binding over the C ABI. PHP never re-implements
the codec; the Rust reference validates, hashes, re-encodes and redacts.

## Prerequisites

- PHP 8.1 or newer with `ext-ffi` (bundled in CLI builds; enable
  `ffi.enable=1` for web SAPIs)
- `cargo` (build `libactive_infinity_ffi`)

## Conformance

```text
(cd ffi/active-infinity-ffi && cargo build --release)
ACTIVE_INFINITY_LIB="$PWD/ffi/active-infinity-ffi/target/release/libactive_infinity_ffi.so" \
  php polyglot/php/test.php
```

The test also asserts that every symbol declared in the PHP `CDEF` exists in
`ffi/active-infinity-ffi/include/active_infinity.h`, so the two cannot drift
silently.

## Quickstart

```php
require __DIR__ . '/polyglot/php/ActiveInfinity.php';

$binding = new ActiveInfinity();
$image = file_get_contents('module.ainf');
$binding->validate($image);
$hash = $binding->contentHashHex($image);
$canonical = $binding->reencode($image);
$json = $binding->redactedJson($image);
$built = ActiveInfinity::fromActive('module demo { }', 'demo.active');
```

Failures throw `ActiveInfinityError` with `->code` and `->status`. Point
`ACTIVE_INFINITY_LIB` at the shared library, or keep it on the loader path.

## Active RPC

`polyglot/rpc/php_client.php` is the thin ARP1 client:

```text
bash polyglot/rpc/run_clients.sh /path/to/active-rpc "$PWD" php
```
