#!/usr/bin/env python3
"""Record the first ARP1 frame a thin client sends and save it as hex.

    python3 polyglot/rpc/record_request.py <out-hex-file>

Prints ``host:port`` on stdout once listening. Accepts one connection, reads
one length-prefixed frame, writes the envelope hex to the output file, closes
the connection and keeps listening until it is killed. The client under test is
expected to fail afterwards (there is no reply): the encoder bytes are the only
thing this harness observes.
"""

import socket
import sys
import threading


def serve(listener: socket.socket, out_path: str) -> None:
    written = False
    while True:
        connection, _ = listener.accept()
        with connection:
            try:
                header = recv_exact(connection, 4)
                if header is None:
                    continue
                length = int.from_bytes(header, "little")
                body = recv_exact(connection, length)
                if body is None:
                    continue
                if not written:
                    with open(out_path, "w", encoding="ascii") as handle:
                        handle.write(body.hex())
                    written = True
            except OSError:
                continue


def recv_exact(connection: socket.socket, size: int) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            return None
        chunks.extend(chunk)
    return bytes(chunks)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: record_request.py <out-hex-file>", file=sys.stderr)
        return 2
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    host, port = listener.getsockname()
    print(f"{host}:{port}", flush=True)
    thread = threading.Thread(target=serve, args=(listener, sys.argv[1]), daemon=True)
    thread.start()
    thread.join()
    return 0


if __name__ == "__main__":
    sys.exit(main())
