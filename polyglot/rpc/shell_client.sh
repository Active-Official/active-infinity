#!/usr/bin/env bash
# Thin Active RPC client over native ARP1 on TCP (POSIX shell).
#
# Linux only: uses bash's /dev/tcp, xxd, od and dd.
#
#   bash polyglot/rpc/shell_client.sh
set -euo pipefail

hex_u32() { printf '%08x' "$(( $1 & 0xffffffff ))"; }
hex_u64() {
  local v=$1
  printf '%02x%02x%02x%02x%02x%02x%02x%02x' \
    $(( v & 0xff )) $(( (v >> 8) & 0xff )) $(( (v >> 16) & 0xff )) $(( (v >> 24) & 0xff )) \
    $(( (v >> 32) & 0xff )) $(( (v >> 40) & 0xff )) $(( (v >> 48) & 0xff )) $(( (v >> 56) & 0xff ))
}
hex_le32() { printf '%02x%02x%02x%02x' $(( $1 & 0xff )) $(( ($1 >> 8) & 0xff )) $(( ($1 >> 16) & 0xff )) $(( ($1 >> 24) & 0xff )); }

hex_of_string() {
  printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'
}

hex_of_file() {
  od -An -v -tx1 "$1" | tr -d ' \n'
}

hex_to_file() {
  local hex=$1 out=$2 escaped="" index
  for ((index = 0; index < ${#hex}; index += 2)); do
    escaped+="\\x${hex:index:2}"
  done
  printf '%b' "$escaped" > "$out"
}

string_hex() {
  local text=$1
  printf '%s%s' "$(hex_le32 "${#text}")" "$(hex_of_string "$text")"
}

cap_hex_block() {
  local cap=$1
  local block="${cap}$(hex_le32 1)$(string_hex echo)"
  for value in 10000 67108864 5000 100000 256 100000 10000000; do
    block+=$(hex_u64 "$value")
  done
  printf '%s000000' "$block"
}

build_request() {
  local id=$1 method=$2 payload_file=$3 with_cap=$4 cap=${5:-}
  local payload_hex payload_len
  payload_hex=$(hex_of_file "$payload_file")
  payload_len=$(stat -c %s "$payload_file")
  local out="4152503101010000$(hex_u64 "$id")$(string_hex "$method")$(hex_le32 0)$(hex_le32 "$payload_len")${payload_hex}"
  if [ "$with_cap" = "1" ]; then
    out+="$(hex_le32 1)$(cap_hex_block "$cap")"
  else
    out+="$(hex_le32 0)"
  fi
  printf '%s' "$out"
}

rpc_call() {
  local host=$1 port=$2 request_hex=$3
  hex_to_file "$request_hex" /tmp/rpc-request.bin
  local length
  length=$(stat -c %s /tmp/rpc-request.bin)
  if [ -n "${SHELL_DEBUG:-}" ]; then
    echo "request bytes: $length" >&2
    od -An -tx1 -N24 /tmp/rpc-request.bin >&2
  fi
  exec 3<>"/dev/tcp/$host/$port"
  hex_to_file "$(hex_le32 "$length")" /tmp/rpc-header.bin
  { cat /tmp/rpc-header.bin; cat /tmp/rpc-request.bin; } >&3
  dd bs=1 count=4 <&3 2>/dev/null | od -An -tu4 -w4 | tr -d ' ' > /tmp/rpc-length
  local body_length
  body_length=$(cat /tmp/rpc-length)
  dd bs=1 count="$body_length" <&3 2>/dev/null > /tmp/rpc-response.bin
  exec 3<&-
  if [ "$(dd bs=1 count=4 < /tmp/rpc-response.bin 2>/dev/null)" != "ARP1" ]; then
    echo "bad magic" >&2
    return 1
  fi
}

response_kind() { od -An -tu1 -j5 -N1 /tmp/rpc-response.bin | tr -d ' '; }
response_method() {
  local length
  length=$(od -An -tu4 -j16 -N4 /tmp/rpc-response.bin | tr -d ' ')
  dd bs=1 skip=20 count="$length" < /tmp/rpc-response.bin 2>/dev/null
}

address=${ACTIVE_RPC_ADDR:?ACTIVE_RPC_ADDR is required}
cap=${ACTIVE_RPC_CAP:?ACTIVE_RPC_CAP is required}
payload=${ACTIVE_RPC_PAYLOAD:?ACTIVE_RPC_PAYLOAD is required}
[ "${#cap}" -eq 32 ] || { echo "ACTIVE_RPC_CAP must be 32 hex characters" >&2; exit 2; }
host=${address%:*}
port=${address##*:}

rpc_call "$host" "$port" "$(build_request 42 echo "$payload" 1 "$cap")"
kind=$(response_kind)
payload_size=$(stat -c %s "$payload")
body_size=$(stat -c %s /tmp/rpc-response.bin)
tail_size=$(( payload_size + 4 ))
dd bs=1 skip=$(( body_size - 4 )) count=4 < /tmp/rpc-response.bin 2>/dev/null | od -An -tu4 -w4 | tr -d ' ' > /tmp/rpc-caps
[ "$kind" = "2" ] || { echo "echo failed: kind=$kind" >&2; exit 1; }
[ "$(cat /tmp/rpc-caps)" = "0" ] || { echo "response carried capabilities" >&2; exit 1; }
dd bs=1 skip=$(( body_size - 4 - payload_size )) count="$payload_size" < /tmp/rpc-response.bin 2>/dev/null > /tmp/rpc-payload
cmp -s /tmp/rpc-payload "$payload" || { echo "payload was not echoed" >&2; exit 1; }

rpc_call "$host" "$port" "$(build_request 43 refuse "$payload" 1 "$cap")"
[ "$(response_kind)" = "3" ] && [ "$(response_method)" = "rpc/method-not-granted" ] || {
  echo "refusal mismatch" >&2; exit 1;
}

rpc_call "$host" "$port" "$(build_request 44 echo "$payload" 0)"
[ "$(response_kind)" = "3" ] && [ "$(response_method)" = "rpc/unknown-capability" ] || {
  echo "missing capability mismatch" >&2; exit 1;
}

rm -f /tmp/rpc-request.bin /tmp/rpc-response.bin /tmp/rpc-payload /tmp/rpc-length /tmp/rpc-caps /tmp/rpc-header.bin
echo "Shell thin RPC PASS (echo, refusal, missing capability)"
