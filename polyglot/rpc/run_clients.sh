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

# Start the peer and export its address and capability.
#
# A long matrix can outlive one peer (a runner can reap it, or an aborted
# connection can race the accept loop). Restarting it keeps the row honest: the
# clients still talk to a real kernel, and the event is printed loudly so a
# genuine crash is never silent. The capability is re-minted, so the environment
# is refreshed for every later client.
PEER=""
trap '[ -n "$PEER" ] && kill "$PEER" 2>/dev/null || true' EXIT

start_peer() {
  : > /tmp/peer.out
  "$TARGET/debug/examples/thin_peer" >> /tmp/peer.out 2>> /tmp/peer.err &
  PEER=$!
  for _ in $(seq 1 100); do
    if [ -s /tmp/peer.out ] && grep -q '^cap ' /tmp/peer.out; then
      ACTIVE_RPC_ADDR="$(head -1 /tmp/peer.out)"
      ACTIVE_RPC_CAP="$(awk '/^cap /{print $2}' /tmp/peer.out)"
      export ACTIVE_RPC_ADDR ACTIVE_RPC_CAP
      return 0
    fi
    kill -0 "$PEER" 2>/dev/null || return 1
    sleep 0.1
  done
  return 1
}

if ! start_peer; then
  echo "thin RPC matrix: the peer printed no address or capability" >&2
  cat /tmp/peer.err >&2 2>/dev/null || true
  exit 1
fi
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
  # A peer that exited turns every later client into a misleading ECONNREFUSED.
  # Print the peer's own stderr, then restart it so the remaining clients still
  # exercise a real kernel.
  if ! kill -0 "$PEER" 2>/dev/null; then
    echo "thin RPC matrix: the peer exited before client '$client'; restarting" >&2
    if [ -s /tmp/peer.err ]; then
      echo "--- peer stderr" >&2
      cat /tmp/peer.err >&2
    fi
    if ! start_peer; then
      echo "thin RPC matrix: the peer could not be restarted" >&2
      exit 1
    fi
    echo "thin RPC matrix: peer restarted at $ACTIVE_RPC_ADDR" >&2
  fi
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
  if ! "run_$client"; then
    # A client that fails while the peer is alive is a real defect: report it
    # and stop. A client that fails because the peer went away is the peer's
    # problem, and the row can continue on a fresh one. The short wait lets the
    # shell reap an exited child before `kill -0` decides which case this is.
    sleep 0.2
    if kill -0 "$PEER" 2>/dev/null; then
      echo "thin RPC matrix: client '$client' failed" >&2
      exit 1
    fi
    echo "thin RPC matrix: the peer died during '$client'; restarting and retrying" >&2
    cat /tmp/peer.err >&2 2>/dev/null || true
    if ! start_peer; then
      echo "thin RPC matrix: the peer could not be restarted" >&2
      exit 1
    fi
    echo "thin RPC matrix: peer restarted at $ACTIVE_RPC_ADDR" >&2
    echo "--- $client (retry)"
    "run_$client"
  fi
done

if [ "$missing" -ne 0 ]; then
  echo "thin RPC matrix: $missing required runtime(s) missing" >&2
  exit 1
fi
