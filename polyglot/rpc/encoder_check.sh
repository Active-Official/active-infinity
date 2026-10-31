#!/usr/bin/env bash
# Byte-exact encoder conformance across every thin ARP1 client.
#
#   bash polyglot/rpc/encoder_check.sh [rpc-repo] [infinity-repo]
#
# Each client is pointed at a recording socket instead of the kernel peer. The
# bytes it puts on the wire must equal the Rust reference encoding of the same
# call (`active-rpc/examples/arp1_request_vector.rs`): request id 42, method
# `echo`, no arguments, the AINF payload, and one capability descriptor with
# the fixed id and the default budget. The client is expected to fail after the
# recorder closes the socket; only the request bytes are judged.
set -euo pipefail

RPC="${1:-/rpc}"
INFINITY="${2:-/work}"
cd "$INFINITY"
# shellcheck source=clients.sh
source polyglot/rpc/clients.sh

PAYLOAD="${ACTIVE_RPC_PAYLOAD:-$INFINITY/tests/vectors/valid/full.ainf}"
CAP="00112233445566778899aabbccddeeff"

reference="$(cd "$RPC" && cargo run -q --example arp1_request_vector -- "$PAYLOAD" "$CAP")"
if [ -z "$reference" ]; then
  echo "the Rust reference encoder produced no output" >&2
  exit 1
fi

export ACTIVE_RPC_CAP="$CAP"
export ACTIVE_RPC_PAYLOAD="$PAYLOAD"

pass=0
fail=0
failed=()

for client in "${CLIENTS[@]}"; do
  client_available "$client" || continue
  captured="/tmp/rpc-request-$client.hex"
  recorder_log="/tmp/rpc-recorder-$client.out"
  rm -f "$captured" "$recorder_log"
  python3 polyglot/rpc/record_request.py "$captured" >"$recorder_log" 2>&1 &
  recorder=$!
  for _ in $(seq 1 200); do
    if [ -s "$recorder_log" ]; then break; fi
    sleep 0.05
  done
  ACTIVE_RPC_ADDR="$(head -1 "$recorder_log")"
  export ACTIVE_RPC_ADDR

  set +e
  timeout 240 bash -c "source polyglot/rpc/clients.sh; run_$client" >/dev/null 2>&1
  set -e
  kill "$recorder" 2>/dev/null || true
  wait "$recorder" 2>/dev/null || true

  if [ ! -s "$captured" ]; then
    echo "encoder $client: FAIL (no request captured)"
    failed+=("$client")
    fail=$((fail + 1))
    continue
  fi
  actual="$(cat "$captured")"
  if [ "$actual" = "$reference" ]; then
    echo "encoder $client: PASS (${#actual} hex characters)"
    pass=$((pass + 1))
    continue
  fi
  echo "encoder $client: FAIL (reference ${#reference} hex, encoder ${#actual} hex)" >&2
  limit=${#reference}
  if [ ${#actual} -lt "$limit" ]; then
    limit=${#actual}
  fi
  for ((index = 0; index < limit; index += 2)); do
    if [ "${reference:index:2}" != "${actual:index:2}" ]; then
      echo "  first differing byte at offset $((index / 2)): reference ${reference:index:2}, encoder ${actual:index:2}" >&2
      break
    fi
  done
  failed+=("$client")
  fail=$((fail + 1))
done

if [ "$fail" -ne 0 ]; then
  echo "encoder conformance: $pass passed, $fail failed (${failed[*]})" >&2
  exit 1
fi
echo "encoder conformance: $pass clients match the Rust reference byte for byte"
