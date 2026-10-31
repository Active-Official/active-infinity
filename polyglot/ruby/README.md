# Ruby binding

`ActiveInfinity::Image` wraps the C ABI with the `ffi` gem. The Rust reference
does the canonicalization, so Ruby hashes match every other language.

## Prerequisites

- Ruby 3.x with the `ffi` gem (`gem install ffi`)
- `cargo` (build `libactive_infinity_ffi`)

## Conformance

```text
(cd ffi/active-infinity-ffi && cargo build --release)
ACTIVE_INFINITY_LIB="$PWD/ffi/active-infinity-ffi/target/release/libactive_infinity_ffi.so" \
  ruby polyglot/ruby/test/test_conformance.rb
```

## Quickstart

```ruby
require_relative "lib/active_infinity"

image = ActiveInfinity::Image.new(File.binread("module.ainf"))
image.validate
puts image.content_hash_hex
canonical = image.reencode
json = image.redacted_json
built = ActiveInfinity::Image.from_active("module demo { }", "demo.active")
```

Failures raise `ActiveInfinity::Error` with `#code` and `#status`. Without
`ACTIVE_INFINITY_LIB` the binding falls back to the platform library name
(`libactive_infinity_ffi.so`, `.dylib`, `active_infinity_ffi.dll`).

## Active RPC

`polyglot/rpc/ruby_client.rb` is the thin ARP1 client:

```text
bash polyglot/rpc/run_clients.sh /path/to/active-rpc "$PWD" ruby
```
