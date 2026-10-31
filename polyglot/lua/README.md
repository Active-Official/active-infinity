# Lua binding

`active_infinity.lua` is a LuaJIT FFI binding over the C ABI. Plain Lua 5.x
needs a C bridge; the supported runtime is LuaJIT, which ships `ffi`.

## Prerequisites

- LuaJIT 2.1
- `cargo` (build `libactive_infinity_ffi`)

## Conformance

```text
(cd ffi/active-infinity-ffi && cargo build --release)
ACTIVE_INFINITY_LIB="$PWD/ffi/active-infinity-ffi/target/release/libactive_infinity_ffi.so" \
  luajit polyglot/lua/test.lua
```

## Quickstart

```lua
local ai = require("active_infinity")

local image = ai.read_file("module.ainf")
ai.validate(image)
print(ai.content_hash_hex(image))
local canonical = ai.reencode(image)
local json = ai.redacted_json(image)
local built = ai.from_active("module demo { }", "demo.active")
```

The module loads `active_infinity_ffi` by default; set `ACTIVE_INFINITY_LIB` to
point at a specific shared library. Failures raise a Lua error whose message
starts with the stable `infinity/...` code.

## Active RPC

`polyglot/rpc/lua_client.lua` is the thin ARP1 client:

```text
bash polyglot/rpc/run_clients.sh /path/to/active-rpc "$PWD" lua
```
