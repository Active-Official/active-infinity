# AssemblyScript binding

AssemblyScript cannot host a second WebAssembly module inside its own instance,
so the binding is a typed shim (`assembly/index.ts`) plus a host
(`host.js`) that owns both linear memories. The shim forwards pointers to host
functions; the host copies bytes into the Rust reference module and copies the
result back. The codec, hashes and redaction stay in Rust.

## Prerequisites

- Node 20 or newer
- `npx` (the compiler is fetched as `assemblyscript@0.27.31`)
- The reference WASM artifact:
  `(cd ffi/active-infinity-ffi && rustup target add wasm32-unknown-unknown && cargo build --release --target wasm32-unknown-unknown)`

## Build and run the conformance test

```text
mkdir -p polyglot/assemblyscript/build
npx --yes -p assemblyscript@0.27.31 asc polyglot/assemblyscript/assembly/index.ts \
  -o polyglot/assemblyscript/build/conformance.wasm --optimize
node polyglot/assemblyscript/test.js
```

## Quickstart

```js
const fs = require("node:fs");
const { load } = require("./polyglot/assemblyscript/host");

const { assembly } = await load(
  "ffi/active-infinity-ffi/target/wasm32-unknown-unknown/release/active_infinity_ffi.wasm",
  "polyglot/assemblyscript/build/conformance.wasm",
);
const image = fs.readFileSync("module.ainf");
const input = assembly.exports.allocate(image.length);
new Uint8Array(assembly.exports.memory.buffer, input, image.length).set(image);
const hashOut = assembly.exports.allocate(32);
const status = assembly.exports.contentHash(input, image.length, hashOut);
if (status !== 0) throw new Error("content hash failed");
const hash = Buffer.from(
  new Uint8Array(assembly.exports.memory.buffer, hashOut, 32),
).toString("hex");
assembly.exports.releaseAll();
```

Allocations are retained by the shim until `releaseAll()`, so the host can read
results after the call. Read `memory.buffer` after every call: a growing module
memory detaches earlier views.

## Active RPC

`polyglot/rpc/as_request.ts` encodes ARP1 in AssemblyScript and
`polyglot/rpc/as_client.js` performs the socket I/O:

```text
bash polyglot/rpc/run_clients.sh /path/to/active-rpc "$PWD" assemblyscript golden
```
