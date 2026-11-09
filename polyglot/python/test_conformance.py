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
        if case["name"] == "non_canonical":
            # NF-INF02-01: validate and content_hash prove the canonical
            # form (INF-02), so a non-canonical image is refused; reencode
            # is the repair path.
            try:
                image.validate()
            except ai.ActiveInfinityError as error:
                assert error.code == "infinity/not-canonical", case["name"]
            else:  # pragma: no cover
                raise AssertionError("non-canonical image was validated")
            try:
                image.content_hash_hex()
            except ai.ActiveInfinityError as error:
                assert error.code == "infinity/not-canonical", case["name"]
            else:  # pragma: no cover
                raise AssertionError("non-canonical image was hashed")
            # INF-POLY-03: the binding surfaces validate_canonical; it must
            # refuse the non-canonical image with the same code.
            try:
                image.validate_canonical()
            except ai.ActiveInfinityError as error:
                assert error.code == "infinity/not-canonical", case["name"]
            else:  # pragma: no cover
                raise AssertionError("non-canonical image passed validate_canonical")
        else:
            image.validate()
            image.validate_canonical()
            assert image.content_hash_hex() == case["content_hash"], case["name"]
        canonical = image.reencode()
        if case["name"] == "non_canonical":
            assert canonical != image.data
            ai.Image(canonical).validate()
        else:
            assert canonical == image.data, case["name"]
        checked += 1
    # INF-POLY-03: pin the exact count, derived from the manifest --
    # a slack `>=` let a dropped vector pass silently.
    assert checked == len(
        [case for case in manifest["cases"] if case["kind"] == "valid"]
    )

    # INF-POLY-02: every invalid vector except the two limits-dependent
    # ones (limit, too_deep) must be refused by validate_canonical with
    # exactly the manifest's expected_code. The FFI exposes no limits
    # parameter, so those two need narrowed limits (max_nodes:1,
    # max_depth:8) and are covered by the CLI's `conformance run` and the
    # Rust suite instead. invalid_stream vectors are CLI-only: no stream
    # decode exists in the FFI.
    invalid_checked = 0
    invalid_skipped = 0
    for case in manifest["cases"]:
        if case["kind"] != "invalid":
            continue
        if case["name"] in ("limit", "too_deep"):
            invalid_skipped += 1
            continue
        image = ai.Image((ROOT / case["path"]).read_bytes())
        try:
            image.validate_canonical()
        except ai.ActiveInfinityError as error:
            assert error.code == case["expected_code"], case["name"]
        else:  # pragma: no cover
            raise AssertionError(f"{case['name']}: invalid image was accepted")
        invalid_checked += 1
    invalid_total = len(
        [case for case in manifest["cases"] if case["kind"] == "invalid"]
    )
    assert invalid_checked + invalid_skipped == invalid_total
    assert invalid_skipped == 2

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
