#!/usr/bin/env bash
# Shell / ops conformance: the CLI is the binding.
#
#   bash polyglot/shell/test.sh
#
# Requires cargo and python3 (the standard library only reads the manifest).
# Every manifest vector must validate and reproduce its content hash, and the
# redacted projection must not leak the secret canary.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

cargo build --release --manifest-path cli/active-infinity-cli/Cargo.toml
CLI="$ROOT/cli/active-infinity-cli/target/release/active-infinity-cli"

"$CLI" doctor
"$CLI" conformance run --manifest conformance/manifest.json

rows=$(python3 - <<'PY'
import json

with open("conformance/manifest.json", encoding="utf-8") as handle:
    manifest = json.load(handle)
for case in manifest["cases"]:
    if case["kind"] == "valid":
        print(f'{case["path"]}\t{case["content_hash"]}')
PY
)

checked=0
while IFS=$'\t' read -r path expected_hash; do
  [ -n "$path" ] || continue
  "$CLI" validate "$path" >/dev/null
  actual_hash=$("$CLI" hash "$path")
  if [ "$actual_hash" != "$expected_hash" ]; then
    echo "content hash mismatch for $path: expected $expected_hash, got $actual_hash" >&2
    exit 1
  fi
  checked=$((checked + 1))
done <<<"$rows"

if [ "$checked" -lt 5 ]; then
  echo "expected at least 5 valid vectors, saw $checked" >&2
  exit 1
fi

redacted=$("$CLI" decode tests/vectors/valid/full.ainf)
if printf '%s' "$redacted" | grep -q 'CANARY_SECRET_'; then
  echo "secret canary survived the redacted decode" >&2
  exit 1
fi
printf '%s' "$redacted" | python3 -c 'import json, sys; json.load(sys.stdin)' ||
  { echo "redacted decode did not produce valid JSON" >&2; exit 1; }

full_hash=$("$CLI" hash tests/vectors/valid/full.ainf)
echo "Shell conformance PASS ($checked vectors, hash $full_hash, redaction clean)"
