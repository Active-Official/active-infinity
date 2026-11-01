#!/usr/bin/env julia
# Thin Active RPC client over native ARP1 on TCP (Julia).
#
# Run against `active-rpc/examples/thin_peer.rs`:
#
#   ACTIVE_RPC_ADDR=127.0.0.1:54321 \
#   ACTIVE_RPC_CAP=<32 hex chars> \
#   ACTIVE_RPC_PAYLOAD=tests/vectors/valid/full.ainf \
#   julia polyglot/rpc/julia_client.jl
#
# ARP1 is little-endian; `htol`/`ltoh` convert, so the client is correct on a
# big-endian host as well.

using Sockets

const MAGIC = b"ARP1"
const VERSION = UInt8(1)
const KIND_REQUEST = UInt8(1)
const KIND_RESPONSE = UInt8(2)
const KIND_ERROR = UInt8(3)
const BUDGET = UInt64[10_000, 64 << 20, 5_000, 100_000, 256, 100_000, 10_000_000]

fail(message) = (println(stderr, message); exit(1))

put_u16(io, value::Integer) = write(io, htol(UInt16(value)))
put_u32(io, value::Integer) = write(io, htol(UInt32(value)))
put_u64(io, value::Integer) = write(io, htol(UInt64(value)))

function get_u16(bytes, offset)
    ltoh(reinterpret(UInt16, bytes[offset+1:offset+2])[1])
end

function get_u32(bytes, offset)
    ltoh(reinterpret(UInt32, bytes[offset+1:offset+4])[1])
end

function get_u64(bytes, offset)
    ltoh(reinterpret(UInt64, bytes[offset+1:offset+8])[1])
end

function put_string(io, text::AbstractString)
    encoded = codeunits(text)
    put_u32(io, length(encoded))
    write(io, encoded)
end

function put_cap(io, cap::Vector{UInt8})
    write(io, cap)
    put_u32(io, 1)          # one method
    put_string(io, "echo")
    for value in BUDGET
        put_u64(io, value)
    end
    write(io, UInt8[0, 0, 0])  # read_only, redact, no path scope
end

function request_frame(request_id::Integer, method::AbstractString,
                       payload::Vector{UInt8}, cap)
    io = IOBuffer()
    write(io, MAGIC)
    write(io, UInt8[VERSION, KIND_REQUEST])
    put_u16(io, 0)                    # flags
    put_u64(io, request_id)
    put_string(io, method)
    put_u32(io, 0)                    # no positional arguments
    put_u32(io, length(payload))
    write(io, payload)
    if cap === nothing
        put_u32(io, 0)
    else
        put_u32(io, 1)
        put_cap(io, cap)
    end
    take!(io)
end

# Value tags of ARP1: skipping is enough, the client checks the payload.
function skip_value(bytes, offset::Int, depth::Int = 0)
    depth > 64 && fail("value nesting exceeds the ceiling")
    tag = bytes[offset+1]
    offset += 1
    if tag == 0x01
        return offset + 1
    elseif tag == 0x02 || tag == 0x03
        return offset + 8
    elseif tag == 0x04 || tag == 0x08 || tag == 0x09
        return offset + 4 + Int(get_u32(bytes, offset))
    elseif tag == 0x05
        count = Int(get_u32(bytes, offset))
        offset += 4
        for _ in 1:count
            offset = skip_value(bytes, offset, depth + 1)
        end
        return offset
    elseif tag == 0x06
        count = Int(get_u32(bytes, offset))
        offset += 4
        for _ in 1:count
            key_length = Int(get_u32(bytes, offset))
            offset = skip_value(bytes, offset + 4 + key_length, depth + 1)
        end
        return offset
    elseif tag == 0x00 || tag == 0x07
        return offset
    end
    fail("unknown value tag $tag")
end

function skip_args(bytes, offset, count)
    for _ in 1:count
        tag = bytes[offset+1]
        offset += 1
        if tag == 0x00
            offset = skip_value(bytes, offset)
        elseif tag == 0x01
            offset += 8      # promise id
        elseif tag == 0x02
            offset += 16     # channel id and sequence
        else
            fail("unknown argument tag $tag")
        end
    end
    offset
end

function payload_of(body)
    method_length = Int(get_u32(body, 16))
    offset = 20 + method_length
    count = Int(get_u32(body, offset))
    offset = skip_args(body, offset + 4, count)
    length_of_payload = Int(get_u32(body, offset))
    offset += 4
    offset + length_of_payload > length(body) && fail("truncated response payload")
    body[offset+1:offset+length_of_payload]
end

function call(address::AbstractString, frame::Vector{UInt8})
    host, port_text = rsplit(address, ':'; limit = 2)
    socket = connect(host, parse(Int, port_text))
    try
        write(socket, htol(UInt32(length(frame))))
        write(socket, frame)
        header = read(socket, 4)
        length(header) == 4 || fail("connection closed before the frame header")
        length_of_body = Int(ltoh(reinterpret(UInt32, header)[1]))
        length_of_body <= 1 << 20 || fail("response frame exceeds the ceiling")
        body = read(socket, length_of_body)
        length(body) == length_of_body || fail("connection closed mid-frame")
        body
    finally
        close(socket)
    end
end

function main()
    address = get(ENV, "ACTIVE_RPC_ADDR", "")
    isempty(address) && fail("ACTIVE_RPC_ADDR is not set")
    cap_text = get(ENV, "ACTIVE_RPC_CAP", "")
    length(cap_text) == 32 || fail("ACTIVE_RPC_CAP must be 32 hex characters")
    cap = hex2bytes(cap_text)
    payload_path = get(ENV, "ACTIVE_RPC_PAYLOAD", "tests/vectors/valid/full.ainf")
    payload = read(payload_path)

    echoed = call(address, request_frame(42, "echo", payload, cap))
    echoed[6] == KIND_RESPONSE || fail("echo was not a response")
    get_u64(echoed, 8) == 42 || fail("echo echoed a different request id")
    payload_of(echoed) == payload || fail("the AINF payload was not echoed")

    refused = call(address, request_frame(43, "refuse", payload, cap))
    refused[6] == KIND_ERROR || fail("an unknown method was not refused")
    method_length = Int(get_u32(refused, 16))
    String(refused[21:20+method_length]) == "rpc/method-not-granted" ||
        fail("wrong refusal code: $(String(refused[21:20+method_length]))")

    anonymous = call(address, request_frame(44, "echo", payload, nothing))
    anonymous[6] == KIND_ERROR || fail("a call without a capability was not refused")
    method_length = Int(get_u32(anonymous, 16))
    String(anonymous[21:20+method_length]) == "rpc/unknown-capability" ||
        fail("wrong refusal code: $(String(anonymous[21:20+method_length]))")

    println("Julia thin RPC PASS (echo, refusal, missing capability)")
end

main()
