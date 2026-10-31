# Thin RPC clients (polyglot)

Every language in the polyglot matrix ships a thin Active RPC client. The kernel
stays in Rust; a client proves it can put a real ARP1 envelope with a capability
on the wire, carry an AINF payload, read the response, and surface a refusal
code.

Modern transports (QUIC/HTTP3, HTTP/2) are implemented once, in the Rust stack.
Thin clients use native ARP1 over TCP, the lowest common denominator that every
language can implement correctly. The Connect/gRPC bridge stays an interop
adapter, not the native protocol, and no example here uses it.

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

`kind`: 1 request, 2 response, 3 error. A refusal is an error envelope whose
`method` field carries the stable `rpc/...` code.

Field widths are normative. The header after the magic is 12 bytes exactly:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 4 | magic | ASCII `ARP1` |
| 4 | 1 | version | 1 |
| 5 | 1 | kind | 1 request, 2 response, 3 error |
| 6 | 2 | flags | `u16` LE; bit 0 read-only, bit 1 redact, bit 2 cap delta |
| 8 | 8 | request id | `u64` LE, echoed by the response |
| 16 | 4 | method length | `u32` LE |
| 20 | n | method | UTF-8 |
| .. | 4 | argument count | `u32` LE |
| .. | .. | arguments | tag `u8` + body |
| .. | 4 | payload length | `u32` LE |
| .. | n | payload | AINF bytes |
| .. | 4 | capability count | `u32` LE |
| .. | .. | capability descriptors | see below |

Writing any field wider than the table says shifts every following field and
the peer fails closed by closing the connection; that is the intended behavior.
Endianness is little-endian throughout.

### Capability descriptor

```text
id [16]
methods_count u32 | (len u32 | method bytes)...
budget: 7 x u64 LE (calls, bytes, wall_ms, nodes, depth, array_len, value_size)
read_only u8 | redact u8
path_scope: 0 | 1 + (len u32 | path bytes)
```

Default budget values: calls 10,000; bytes 67,108,864; wall 5,000 ms; nodes
100,000; depth 256; array 100,000; value 10,000,000. A descriptor is
informational on the wire; the receiving registry is the authority.

## Test peer

`active-rpc/examples/thin_peer.rs` mints one `echo` capability, prints the bound
address and the capability id, and serves one request per connection:

```text
127.0.0.1:54321
cap 0123456789abcdef0123456789abcdef
```

It answers `echo` with a response envelope that echoes the payload, refuses any
other method with `rpc/method-not-granted`, and refuses a request without a
capability with `rpc/unknown-capability`.

## Harness

```text
# Active-RPC
cargo run --example thin_peer > /tmp/peer.out &
ADDR=$(head -1 /tmp/peer.out)
CAP=$(awk '/^cap /{print $2}' /tmp/peer.out)

# Active-Infinity
export ACTIVE_RPC_ADDR=$ADDR
export ACTIVE_RPC_CAP=$CAP
export ACTIVE_RPC_PAYLOAD=tests/vectors/valid/full.ainf
# run each client, for example:
python polyglot/rpc/python_client.py
```

`polyglot/rpc/run_clients.sh` automates that for every runtime it finds:

```text
bash polyglot/rpc/run_clients.sh /path/to/active-rpc "$PWD" [client...]
```

A client passes when:

1. `echo` with the capability returns kind 2, the same request id, the echoed
   payload and the text value `ok`.
2. `refuse` with the capability returns kind 3 and `rpc/method-not-granted`.
3. `echo` without a capability returns kind 3 and `rpc/unknown-capability`.

## Encoder conformance (golden vectors)

Passing the live round trip proves the peer *understood* the request; it does
not prove the bytes are canonical. The descriptor method set, for example, is
not consulted for dispatch, so a wrong encoding of it still round-trips. Two
checks pin the bytes:

```text
# Byte-exact reference for the fixed call: id 42, `echo`, AINF payload,
# one capability descriptor with a fixed id and the default budget.
cd active-rpc && cargo run --example arp1_request_vector -- <payload> <cap-hex>

# Every available client is pointed at a recording socket and its first frame
# is compared with that reference.
bash polyglot/rpc/encoder_check.sh /path/to/active-rpc "$PWD"
```

The AssemblyScript module has the same check standalone:

```text
bash polyglot/rpc/check_golden.sh /path/to/active-rpc
```

`record_request.py` is the recording socket: it accepts one connection, stores
the frame hex, and closes. The client is expected to fail afterwards; only the
request bytes are judged. A mismatch reports the first differing byte offset.

Encoder changes must keep this check green for every runtime.
