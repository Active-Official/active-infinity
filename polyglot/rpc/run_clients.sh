#!/usr/bin/env bash
# Start the real-kernel thin peer and run the requested language clients.
#
#   bash polyglot/rpc/run_clients.sh [rpc-repo] [infinity-repo] [client...]
#
# With no client names it runs every client whose runtime is installed. The
# special name `golden` byte-compares each available client's encoded request
# with the Rust reference encoder (see encoder_check.sh).
set -euo pipefail

RPC="${1:-/rpc}"
INFINITY="${2:-/work}"
shift 2 2>/dev/null || true

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rpc-target}"
TARGET="$CARGO_TARGET_DIR"
cd "$RPC"
cargo build -q --example thin_peer

if [ ! -x "$TARGET/debug/examples/thin_peer" ]; then
  echo "thin_peer did not build at $TARGET/debug/examples/thin_peer" >&2
  exit 1
fi

"$TARGET/debug/examples/thin_peer" > /tmp/peer.out &
PEER=$!
trap 'kill "$PEER" 2>/dev/null || true' EXIT

for _ in $(seq 1 100); do
  if [ -s /tmp/peer.out ] && grep -q '^cap ' /tmp/peer.out; then break; fi
  sleep 0.1
done

export ACTIVE_RPC_ADDR
ACTIVE_RPC_ADDR="$(head -1 /tmp/peer.out)"
export ACTIVE_RPC_CAP
ACTIVE_RPC_CAP="$(awk '/^cap /{print $2}' /tmp/peer.out)"
export ACTIVE_RPC_PAYLOAD="${ACTIVE_RPC_PAYLOAD:-$INFINITY/tests/vectors/valid/full.ainf}"

echo "peer $ACTIVE_RPC_ADDR (payload $ACTIVE_RPC_PAYLOAD)"

cd "$INFINITY"
# shellcheck source=clients.sh
source polyglot/rpc/clients.sh

requested=("$@")
if [ ${#requested[@]} -eq 0 ]; then
  requested=("${CLIENTS[@]}" golden)
fi

missing=0
for client in "${requested[@]}"; do
  if [ "$client" = golden ]; then
    command -v node >/dev/null || continue
    echo "--- golden"
    bash polyglot/rpc/encoder_check.sh "$RPC" "$INFINITY"
    continue
  fi
  if ! client_available "$client"; then
    if [ "${ACTIVE_RPC_STRICT:-0}" = "1" ]; then
      echo "client $client: FAIL (runtime not installed)" >&2
      missing=$((missing + 1))
    fi
    continue
  fi
  echo "--- $client"
  "run_$client"
done

if [ "$missing" -ne 0 ]; then
  echo "thin RPC matrix: $missing required runtime(s) missing" >&2
  exit 1
fi
