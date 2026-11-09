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
# Windows builds carry the .exe suffix; prefer it so one script runs on both.
if [ -x "$CLI.exe" ]; then
  CLI="$CLI.exe"
fi
# Pick an interpreter that actually runs: on Windows the `python3` name can be a
# Store stub that exits non-zero.
PY=
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "" >/dev/null 2>&1; then
    PY="$candidate"
    break
  fi
done
if [ -z "$PY" ]; then
  echo "the shell lane needs python3 or python" >&2
  exit 1
fi

"$CLI" doctor
"$CLI" conformance run --manifest conformance/manifest.json

rows=$("$PY" - <<'PY'
import json

with open("conformance/manifest.json", encoding="utf-8") as handle:
    manifest = json.load(handle)
for case in manifest["cases"]:
    if case["kind"] == "valid":
        print(f'{case["path"]}\t{case["content_hash"]}')
PY
)
rows=${rows//$'\r'/}

checked=0
while IFS=$'\t' read -r path expected_hash; do
  [ -n "$path" ] || continue
  if [[ "$path" == *non_canonical* ]]; then
    # NF-INF02-01: validate and hash prove the canonical form (INF-02),
    # so a non-canonical image is refused; the repair itself is proven by
    # `conformance run` above, which checks the vector leniently and
    # re-encodes it.
    if out=$("$CLI" validate "$path" 2>&1); then
      echo "non-canonical image was validated: $path" >&2
      exit 1
    fi
    case "$out" in
      *infinity/not-canonical*) ;;
      *) echo "validate refused $path with the wrong code: $out" >&2; exit 1 ;;
    esac
    if out=$("$CLI" hash "$path" 2>&1); then
      echo "non-canonical image was hashed: $path" >&2
      exit 1
    fi
    case "$out" in
      *infinity/not-canonical*) ;;
      *) echo "hash refused $path with the wrong code: $out" >&2; exit 1 ;;
    esac
    # INF-POLY-03: the CLI surfaces validate-canonical; it must refuse
    # the non-canonical image with the same code.
    if out=$("$CLI" validate-canonical "$path" 2>&1); then
      echo "non-canonical image passed validate-canonical: $path" >&2
      exit 1
    fi
    case "$out" in
      *infinity/not-canonical*) ;;
      *) echo "validate-canonical refused $path with the wrong code: $out" >&2; exit 1 ;;
    esac
  else
    "$CLI" validate "$path" >/dev/null
    "$CLI" validate-canonical "$path" >/dev/null
    actual_hash=$("$CLI" hash "$path" | tr -d '\r')
    if [ "$actual_hash" != "$expected_hash" ]; then
      echo "content hash mismatch for $path: expected $expected_hash, got $actual_hash" >&2
      exit 1
    fi
  fi
  checked=$((checked + 1))
done <<<"$rows"

# INF-POLY-03: pin the exact count, derived from the manifest -- a
# slack floor let a dropped vector pass silently.
valid_count=$("$PY" - <<'PY'
import json

with open("conformance/manifest.json", encoding="utf-8") as handle:
    manifest = json.load(handle)
print(sum(1 for case in manifest["cases"] if case["kind"] == "valid"))
PY
)
if [ "$checked" -ne "$valid_count" ]; then
  echo "expected $valid_count valid vectors, saw $checked" >&2
  exit 1
fi

redacted=$("$CLI" decode tests/vectors/valid/full.ainf)
if printf '%s' "$redacted" | grep -q 'CANARY_SECRET_'; then
  echo "secret canary survived the redacted decode" >&2
  exit 1
fi
printf '%s' "$redacted" | "$PY" -c 'import json, sys; json.load(sys.stdin)' ||
  { echo "redacted decode did not produce valid JSON" >&2; exit 1; }

full_hash=$("$CLI" hash tests/vectors/valid/full.ainf)
echo "Shell conformance PASS ($checked vectors, hash $full_hash, redaction clean)"
