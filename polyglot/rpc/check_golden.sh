#!/usr/bin/env bash
# Byte-exact golden check for the AssemblyScript ARP1 encoder.
#
#   bash polyglot/rpc/check_golden.sh [rpc-repo] [payload-file]
#
# The Rust reference encoder in `active-rpc/examples/arp1_request_vector.rs` is
# the oracle. Both encoders must produce identical bytes for the same call:
# request id 42, method `echo`, no arguments, the AINF payload, one capability
# descriptor with a fixed id and the default budget.
set -euo pipefail

RPC="${1:-../Active-RPC}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PAYLOAD="${2:-$ROOT/tests/vectors/valid/full.ainf}"
CAP="00112233445566778899aabbccddeeff"
WASM="$ROOT/polyglot/rpc/build/as_request.wasm"

cd "$ROOT"
if [ ! -f "$WASM" ] || [ "$ROOT/polyglot/rpc/as_request.ts" -nt "$WASM" ]; then
	mkdir -p "$ROOT/polyglot/rpc/build"
	npx --yes -p assemblyscript@0.27.31 asc polyglot/rpc/as_request.ts \
		-o polyglot/rpc/build/as_request.wasm --optimize
fi

expected="$(cd "$RPC" && cargo run -q --example arp1_request_vector -- "$PAYLOAD" "$CAP")"
actual="$(node polyglot/rpc/as_golden.js "$PAYLOAD" "$CAP")"

if [ "$expected" = "$actual" ]; then
	echo "AssemblyScript ARP1 golden vector matches the Rust reference (${#actual} hex characters)"
	exit 0
fi

echo "AssemblyScript ARP1 golden vector MISMATCH" >&2
echo "  reference: ${#expected} hex characters" >&2
echo "  encoder:   ${#actual} hex characters" >&2
limit=${#expected}
if [ ${#actual} -lt "$limit" ]; then
	limit=${#actual}
fi
for ((index = 0; index < limit; index += 2)); do
	if [ "${expected:index:2}" != "${actual:index:2}" ]; then
		echo "  first differing byte at offset $((index / 2)): reference ${expected:index:2}, encoder ${actual:index:2}" >&2
		break
	fi
done
exit 1
