"""Run every cargo-fuzz target in a Linux container.

cargo-fuzz does not launch on Windows MSVC (libFuzzer reports
STATUS_DLL_NOT_FOUND), so the reproducible lane is Docker. The image carries
clang, a nightly toolchain and cargo-fuzz; the repository is mounted read-write
so cargo-fuzz can grow the committed corpus.

Usage:
    python scripts/fuzz_docker.py --build
    python scripts/fuzz_docker.py --all --runs 20000
    python scripts/fuzz_docker.py --target fuzz_decode_infinity --runs 2000
    python scripts/fuzz_docker.py --list
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

IMAGE = "active-fuzz:1.88"
TARGETS = [
    "fuzz_decode_infinity",
    "fuzz_stream_reassembly",
    "fuzz_canonical_roundtrip",
    "fuzz_layout_sections",
    "fuzz_graph_cycles",
    "fuzz_secret_positions",
    "fuzz_unit_discriminants",
    "fuzz_projection_agreement",
    "fuzz_compressed_frame",
]


def run(
    cmd: list[str], cwd: Path, timeout: int | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def cargo_targets(manifest: Path) -> list[str]:
    """The `[[bin]]` names declared by the fuzz crate, sorted."""
    names: list[str] = []
    in_bin = False
    for line in manifest.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "[[bin]]":
            in_bin = True
            continue
        if stripped.startswith("[") and stripped != "[[bin]]":
            in_bin = False
            continue
        if in_bin and stripped.startswith("name = "):
            value = stripped.split("=", 1)[1].strip().strip('"')
            if value and value not in names:
                names.append(value)
    return sorted(names)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", action="store_true", help="build the fuzz image")
    parser.add_argument("--all", action="store_true", help="run every target")
    parser.add_argument("--target", action="append", default=[], help="run one target")
    parser.add_argument(
        "--runs", type=int, default=20000, help="libFuzzer -runs budget"
    )
    parser.add_argument("--list", action="store_true")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify TARGETS matches fuzz/Cargo.toml and exit",
    )
    parser.add_argument("--timeout", type=int, default=1800, help="seconds per target")
    parser.add_argument(
        "--libfuzzer-timeout",
        type=int,
        default=25,
        help="libFuzzer -timeout (seconds per input)",
    )
    parser.add_argument(
        "--rss-limit-mb",
        type=int,
        default=2048,
        help="libFuzzer -rss_limit_mb",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent

    if args.list:
        print(json.dumps(TARGETS, indent=2))
        return 0

    if args.check:
        declared = cargo_targets(root / "fuzz" / "Cargo.toml")
        if declared != sorted(TARGETS):
            print(
                "TARGETS does not match fuzz/Cargo.toml:\n"
                f"  script: {sorted(TARGETS)}\n  cargo:  {declared}",
                file=sys.stderr,
            )
            return 1
        print(f"{len(TARGETS)} targets agree with fuzz/Cargo.toml")
        return 0

    if args.build:
        built = run(
            [
                "docker",
                "build",
                "-t",
                IMAGE,
                "-f",
                str(root / "docker" / "fuzz.Dockerfile"),
                str(root / "docker"),
            ],
            root,
        )
        if built.returncode != 0:
            print(built.stdout + built.stderr, file=sys.stderr)
            return 1
        print(f"built {IMAGE}")

    selected = list(TARGETS) if args.all else args.target
    if not selected:
        parser.error("choose --all, --build or --target")
    unknown = [target for target in selected if target not in TARGETS]
    if unknown:
        parser.error(f"unknown targets: {', '.join(unknown)}")

    failures: list[str] = []
    for target in selected:
        print(f"== {target} ({args.runs} runs) ==")
        command = (
            f"cargo +nightly fuzz build {target} && "
            f"cargo +nightly fuzz run {target} -- -runs={args.runs} "
            f"-timeout={args.libfuzzer_timeout} -rss_limit_mb={args.rss_limit_mb} "
            "-print_final_stats=1"
        )
        try:
            result = run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--mount",
                    f"type=bind,source={root},target=/work",
                    "-w",
                    "/work/fuzz",
                    IMAGE,
                    "bash",
                    "-c",
                    "export PATH=/usr/local/cargo/bin:$PATH; " + command,
                ],
                root,
                timeout=args.timeout,
            )
        except subprocess.TimeoutExpired as expired:
            failures.append(target)
            partial = expired.stdout or ""
            if isinstance(partial, bytes):
                partial = partial.decode(errors="replace")
            print(partial[-6000:])
            print(f"FAIL {target} (timed out after {args.timeout}s)")
            continue
        output = result.stdout + result.stderr
        if result.returncode != 0:
            failures.append(target)
            print(output[-6000:])
            print(f"FAIL {target}")
        else:
            tail = [
                line
                for line in output.splitlines()
                if "stat::" in line or "Done" in line
            ]
            print("\n".join(tail[-12:]))
            print(f"ok   {target}")

    print()
    if failures:
        print(f"{len(failures)} target(s) failed: {', '.join(failures)}")
        return 1
    print(f"all {len(selected)} targets completed without a crash")
    return 0


if __name__ == "__main__":
    sys.exit(main())
