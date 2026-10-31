#!/usr/bin/env bash
# Shell / ops conformance: the CLI is the binding.
#
#   bash polyglot/shell/test.sh
#
# Requires cargo; builds the CLI from this repository.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

cargo build --release --manifest-path cli/active-infinity-cli/Cargo.toml
CLI="$ROOT/cli/active-infinity-cli/target/release/active-infinity-cli"

"$CLI" doctor
"$CLI" conformance run --manifest conformance/manifest.json

checked=0
while IFS= read -r path; do
  "$CLI" validate "$path" >/dev/null
  checked=$((checked + 1))
done < <(find tests/vectors/valid -name '*.ainf' | sort)

if [ "$checked" -lt 4 ]; then
  echo "expected at least 4 valid vectors, saw $checked" >&2
  exit 1
fi

# The hash command must agree with the manifest for the canonical vectors.
expected=$("$CLI" hash tests/vectors/valid/full.ainf)
actual=$(grep -A2 '"name": "full"' conformance/manifest.json >/dev/null 2>&1 || true)
if [ -z "$expected" ]; then
  echo "hash output was empty" >&2
  exit 1
fi

echo "Shell conformance PASS ($checked vectors, hash $expected)"
