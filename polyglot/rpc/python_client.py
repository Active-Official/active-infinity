"""Thin Active RPC client over native ARP1 on TCP (Python).

Run against `active-rpc/examples/thin_peer.rs`:

    ACTIVE_RPC_ADDR=127.0.0.1:54321 \
    ACTIVE_RPC_CAP=<32 hex chars> \
    ACTIVE_RPC_PAYLOAD=tests/vectors/valid/full.ainf \
    python polyglot/rpc/python_client.py
"""

from __future__ import annotations

import os
import socket
import struct
import sys

MAGIC = b"ARP1"
VERSION = 1
KIND_REQUEST = 1
KIND_RESPONSE = 2
KIND_ERROR = 3

BUDGET = (10_000, 64 << 20, 5_000, 100_000, 256, 100_000, 10_000_000)


def _string(value: str) -> bytes:
    encoded = value.encode()
    return struct.pack("<I", len(encoded)) + encoded


def _cap_descriptor(cap_id: bytes) -> bytes:
    out = bytearray(cap_id)
    out += struct.pack("<I", 1)
    out += _string("echo")
    out += struct.pack("<7Q", *BUDGET)
    out += b"\x00\x00"  # read_only, redact
    out += b"\x00"  # no path scope
    return bytes(out)


def encode_request(
    request_id: int, method: str, payload: bytes, cap_id: bytes | None
) -> bytes:
    out = bytearray(MAGIC)
    out += bytes([VERSION, KIND_REQUEST])
    out += struct.pack("<H", 0)
    out += struct.pack("<Q", request_id)
    out += _string(method)
    out += struct.pack("<I", 0)  # args
    out += struct.pack("<I", len(payload))
    out += payload
    if cap_id is None:
        out += struct.pack("<I", 0)
    else:
        out += struct.pack("<I", 1)
        out += _cap_descriptor(cap_id)
    return bytes(out)


def _skip_value(data: bytes, cursor: int) -> int:
    tag = data[cursor]
    cursor += 1
    if tag == 1:  # bool
        return cursor + 1
    if tag == 2:  # int
        return cursor + 8
    if tag == 3:  # float
        return cursor + 8
    if tag in (4, 9):  # text, path
        length = struct.unpack_from("<I", data, cursor)[0]
        return cursor + 4 + length
    if tag == 8:  # module
        length = struct.unpack_from("<I", data, cursor)[0]
        return cursor + 4 + length
    if tag == 5:  # list
        count = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        for _ in range(count):
            cursor = _skip_value(data, cursor)
        return cursor
    if tag == 6:  # map
        count = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        for _ in range(count):
            key_len = struct.unpack_from("<I", data, cursor)[0]
            cursor += 4 + key_len
            cursor = _skip_value(data, cursor)
        return cursor
    if tag in (0, 7):  # null, secret
        return cursor
    raise AssertionError(f"unknown value tag {tag}")


def _skip_args(data: bytes, cursor: int, count: int) -> int:
    for _ in range(count):
        tag = data[cursor]
        cursor += 1
        if tag == 0:
            cursor = _skip_value(data, cursor)
        elif tag == 1:
            cursor += 8
        elif tag == 2:
            cursor += 16
        else:
            raise AssertionError(f"unknown arg tag {tag}")
    return cursor


def decode_envelope(data: bytes) -> dict:
    if data[:4] != MAGIC or data[4] != VERSION:
        raise AssertionError("bad envelope magic or version")
    kind = data[5]
    request_id = struct.unpack_from("<Q", data, 8)[0]
    cursor = 16
    method_len = struct.unpack_from("<I", data, cursor)[0]
    cursor += 4
    method = data[cursor : cursor + method_len].decode()
    cursor += method_len
    args = struct.unpack_from("<I", data, cursor)[0]
    cursor += 4
    cursor = _skip_args(data, cursor, args)
    payload_len = struct.unpack_from("<I", data, cursor)[0]
    cursor += 4
    payload = data[cursor : cursor + payload_len]
    return {
        "kind": kind,
        "request_id": request_id,
        "method": method,
        "payload": payload,
    }


def call(address: str, envelope: bytes) -> dict:
    host, port = address.rsplit(":", 1)
    with socket.create_connection((host, int(port)), timeout=10) as connection:
        connection.sendall(struct.pack("<I", len(envelope)) + envelope)
        header = b""
        while len(header) < 4:
            chunk = connection.recv(4 - len(header))
            if not chunk:
                raise AssertionError("connection closed before the frame header")
            header += chunk
        length = struct.unpack("<I", header)[0]
        body = b""
        while len(body) < length:
            chunk = connection.recv(length - len(body))
            if not chunk:
                raise AssertionError("connection closed mid-frame")
            body += chunk
    return decode_envelope(body)


def main() -> int:
    address = os.environ["ACTIVE_RPC_ADDR"]
    cap_id = bytes.fromhex(os.environ["ACTIVE_RPC_CAP"])
    if len(cap_id) != 16:
        raise AssertionError("ACTIVE_RPC_CAP must be 32 hex characters")
    payload = open(
        os.environ.get("ACTIVE_RPC_PAYLOAD", "tests/vectors/valid/full.ainf"), "rb"
    ).read()

    response = call(address, encode_request(42, "echo", payload, cap_id))
    assert response["kind"] == KIND_RESPONSE, response
    assert response["request_id"] == 42
    assert response["payload"] == payload, "the AINF payload was not echoed"

    refused = call(address, encode_request(43, "refuse", payload, cap_id))
    assert refused["kind"] == KIND_ERROR, refused
    assert refused["method"] == "rpc/method-not-granted", refused

    anonymous = call(address, encode_request(44, "echo", payload, None))
    assert anonymous["kind"] == KIND_ERROR, anonymous
    assert anonymous["method"] == "rpc/unknown-capability", anonymous

    print("Python thin RPC PASS (echo, refusal, missing capability)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
