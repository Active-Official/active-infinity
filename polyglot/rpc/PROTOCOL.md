# Thin RPC clients (polyglot)

Every language in the polyglot matrix ships a thin Active RPC client. The kernel
stays in Rust; a client proves it can put a real ARP1 envelope on the wire, read
the response, and surface a refusal code.

## Wire

TCP, one request per connection:

```text
u32 LE frame length
ARP1 | version u8 | kind u8 | flags u16 LE | request_id u64 LE
     | method_len u32 | method bytes
     | args_count u32 | args...
     | payload_len u32 | payload bytes
     | caps_count u32 | caps...
```

`kind`: 1 request, 2 response, 3 error. A thin client sends a request with no
arguments and no capabilities; a refusal is an error envelope whose `method`
field carries the stable `rpc/...` code.

The test server (`active-rpc/examples/thin_peer.rs`) answers `echo` with a
response and any other method with `rpc/method-not-granted`.

## Harness

```text
# Active-RPC
cargo run --example thin_peer > /tmp/peer.addr &
ADDR=$(head -1 /tmp/peer.addr)
export ACTIVE_RPC_ADDR=$ADDR
# then run each client, for example:
python polyglot/python/rpc_smoke.py
```

A client passes when:

1. `echo` returns kind 2 and the same request id, with the payload echoed.
2. `refuse` returns kind 3 with `rpc/method-not-granted`.
