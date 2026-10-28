#!/usr/bin/env python3
"""Prove that each security-critical check fails when its guard is removed.

A test that passes on a broken build proves nothing. This runner copies the
working tree (including uncommitted changes), confirms every mapped check
passes there, then applies one precise source mutation per control, runs the
mapped check, and requires a real test failure (not a compile error). The copy
is removed afterwards, so the working tree is never touched.

Usage:
    python scripts/negative_controls.py --check
    python scripts/negative_controls.py --only I-3-redaction --keep
    python scripts/negative_controls.py --list
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CONTROLS = [
    {
        "id": "I-3-redaction",
        "invariant": "I-3",
        "file": "src/canonical.rs",
        "find": "pub(crate) fn redact_text(text: &str, secrets: &[String]) -> String {\n    let marker_tainted = secrets\n",
        "replace": "pub(crate) fn redact_text(text: &str, secrets: &[String]) -> String {\n    return text.to_string();\n    #[allow(unreachable_code)]\n    let marker_tainted = secrets\n",
        "suite": "api_surface",
        "test": "the_allowlisted_label_helper_never_returns_secret_material",
        "why": "The canonical redactor returns its input, so the tainted binding label carries the literal.",
    },
    {
        "id": "I-3-debug",
        "invariant": "I-3",
        "file": "src/canonical.rs",
        "find": "pub(crate) fn redact_text(text: &str, secrets: &[String]) -> String {\n    let marker_tainted = secrets\n",
        "replace": "pub(crate) fn redact_text(text: &str, secrets: &[String]) -> String {\n    return text.to_string();\n    #[allow(unreachable_code)]\n    let marker_tainted = secrets\n",
        "suite": "unit_tests",
        "test": "debug_redacts_secret_copies_in_metadata",
        "why": "Debug redaction uses the same canonical redactor; identity leaks metadata copies.",
    },
    {
        "id": "I-8-depth",
        "invariant": "I-8",
        "file": "src/validate.rs",
        "find": "                if next > limits.max_depth {\n",
        "replace": "                if false {\n",
        "suite": "redteam_tests",
        "test": "threat_deep_and_wide_modules_hit_limits_not_the_stack",
        "why": "The depth ceiling never fires, so a 20k-deep chain validates under the shipped limit.",
    },
    {
        "id": "I-9-canonical",
        "invariant": "I-9",
        "file": "src/validate.rs",
        "find": "            if image != buf {\n",
        "replace": "            if false {\n",
        "suite": "unit_tests",
        "test": "canonical_proof_is_unconditional",
        "why": "The canonical proof stops comparing the re-encode, so a non-canonical image passes.",
    },
    {
        "id": "I-10-trailing",
        "invariant": "I-10",
        "edits": [
            {
                "file": "src/validate.rs",
                "find": "    if header.total_size < buf.len() as u64 {\n        return Err(Error::TrailingBytes {\n            at: header.total_size,\n        });\n    }\n",
                "replace": "    if false {\n        return Err(Error::TrailingBytes {\n            at: header.total_size,\n        });\n    }\n",
            },
            {
                "file": "src/validate.rs",
                "find": "        if header.total_size < buf.len() as u64 {\n            return Err(Error::TrailingBytes {\n                at: header.total_size,\n            });\n        }\n",
                "replace": "        if false {\n            return Err(Error::TrailingBytes {\n                at: header.total_size,\n            });\n        }\n",
            },
        ],
        "suite": "conformance_tests",
        "test": "invalid_vectors_are_rejected_with_their_declared_code",
        "why": "Both trailing-byte guards are removed, so the trailing vector is accepted or mis-coded.",
    },
]


def run(
    cmd: list[str], cwd: Path, env: dict[str, str], timeout: int = 600
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout
    )


def run_test(
    tree: Path, env: dict[str, str], control: dict
) -> subprocess.CompletedProcess:
    return run(
        [
            "cargo",
            "test",
            "--locked",
            "--all-features",
            "--test",
            control["suite"],
            "--",
            "--exact",
            control["test"],
        ],
        tree,
        env,
    )


def failure_names(output: str) -> str:
    marker = "failures:"
    if marker not in output:
        return ""
    return output.split(marker, 1)[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="run every control")
    parser.add_argument("--only", help="run one control by id")
    parser.add_argument("--list", action="store_true", help="list controls and exit")
    parser.add_argument(
        "--keep", action="store_true", help="keep the worktree for debugging"
    )
    args = parser.parse_args()

    if args.list:
        for control in CONTROLS:
            print(f"{control['id']:18} {control['invariant']:5} {control['file']}")
        return 0

    selected = CONTROLS
    if args.only:
        selected = [c for c in CONTROLS if c["id"] == args.only]
        if not selected:
            print(f"unknown control: {args.only}", file=sys.stderr)
            return 2

    root = Path(__file__).resolve().parent.parent
    base = Path(tempfile.mkdtemp(prefix="active-negative-"))
    tree = base / "tree"
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(base / "target")
    env["CARGO_TERM_COLOR"] = "never"

    failures: list[str] = []
    try:
        # Copy the working tree, including uncommitted changes. A control must
        # test the code under review, not the last commit; a git worktree would
        # silently run the old tree and turn a new test into a vacuous pass.
        shutil.copytree(
            root,
            tree,
            ignore=shutil.ignore_patterns(
                ".git", "target", "fuzz", ".scratch", "__pycache__"
            ),
            symlinks=True,
        )

        print("== baseline: the unmutated checks must pass ==")
        for control in selected:
            result = run_test(tree, env, control)
            if result.returncode != 0:
                failures.append(
                    f"{control['id']}: baseline failed on the unmutated tree"
                )
                print(f"FAIL {control['id']}: baseline failed")
                print(result.stdout[-2000:])
            else:
                print(f"ok   {control['id']}: baseline passes")

        print("== controls: the mutated checks must fail ==")
        for control in selected:
            edits = control.get("edits")
            if edits is None:
                edits = [
                    {
                        "file": control["file"],
                        "find": control["find"],
                        "replace": control["replace"],
                    }
                ]
            originals: dict[Path, str] = {}
            applied = True
            for edit in edits:
                path = tree / edit["file"]
                if path not in originals:
                    originals[path] = path.read_text(encoding="utf-8")
                current = path.read_text(encoding="utf-8")
                occurrences = current.count(edit["find"])
                if occurrences != 1:
                    failures.append(
                        f"{control['id']}: mutation anchor occurs {occurrences} times in {edit['file']}"
                    )
                    print(
                        f"FAIL {control['id']}: anchor occurs {occurrences} times in {edit['file']}"
                    )
                    applied = False
                    break
                path.write_text(
                    current.replace(edit["find"], edit["replace"], 1),
                    encoding="utf-8",
                    newline="\n",
                )
            if not applied:
                for path, original in originals.items():
                    path.write_text(original, encoding="utf-8", newline="\n")
                continue
            try:
                result = run_test(tree, env, control)
            finally:
                for path, original in originals.items():
                    path.write_text(original, encoding="utf-8", newline="\n")
            output = result.stdout + result.stderr
            if result.returncode == 0:
                failures.append(
                    f"{control['id']}: the check still passed on a broken build"
                )
                print(f"FAIL {control['id']}: check still passed")
                continue
            if "error[E" in output or "could not compile" in output:
                failures.append(f"{control['id']}: the mutation did not compile")
                print(f"FAIL {control['id']}: mutation did not compile")
                print(output[-2000:])
                continue
            if "test result: FAILED" not in output:
                failures.append(
                    f"{control['id']}: the mapped test did not run to a failure"
                )
                print(f"FAIL {control['id']}: no test failure in output")
                print(output[-2000:])
                continue
            if control["test"] not in failure_names(output):
                failures.append(f"{control['id']}: a different test failed")
                print(f"FAIL {control['id']}: wrong test in the failure list")
                continue
            print(f"PASS {control['id']}: {control['test']} failed as required")

        print()
        if failures:
            print(f"{len(failures)} control(s) failed:")
            for failure in failures:
                print(f"  - {failure}")
            return 1
        print(f"all {len(selected)} negative controls behaved as required")
        return 0
    finally:
        if args.keep:
            print(f"tree kept at {tree}")
        else:
            shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
