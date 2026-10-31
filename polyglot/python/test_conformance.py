"""Conformance test for the Python binding.

Run from the repository root after building the shared library:

    python polyglot/python/test_conformance.py
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import active_infinity as ai

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main() -> int:
    manifest = json.loads((ROOT / "conformance" / "manifest.json").read_text())
    checked = 0
    for case in manifest["cases"]:
        if case["kind"] != "valid":
            continue
        image = ai.Image((ROOT / case["path"]).read_bytes())
        image.validate()
        assert image.content_hash_hex() == case["content_hash"], case["name"]
        canonical = image.reencode()
        if case["name"] == "non_canonical":
            assert canonical != image.data
        else:
            assert canonical == image.data, case["name"]
        checked += 1
    assert checked >= 4

    source = b'port = 8080\nname = "py"\n'
    first = ai.Image.from_active(source, "py.active")
    second = ai.Image.from_active(source, "py.active")
    assert first == second
    ai.Image(first).validate()

    full = ai.Image((ROOT / "tests/vectors/valid/full.ainf").read_bytes())
    redacted = full.redacted_json()
    assert "CANARY_SECRET_" not in redacted
    json.loads(redacted)

    try:
        ai.Image(b"\xff\xff\xff").validate()
    except ai.ActiveInfinityError as error:
        assert error.code.startswith("infinity/")
    else:  # pragma: no cover
        raise AssertionError("malformed input was accepted")

    print(f"Python conformance PASS ({checked} vectors, ABI {ai.ABI_VERSION})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
