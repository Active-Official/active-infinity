#!/usr/bin/env python3
"""Pin lint (R2-CI-01 / R2-NEW-01): fail when any `uses:` in
`.github/workflows/*.yml` is not a full 40-hex commit SHA, or when any
`cargo install` lacks `--version`.

This is the W15 verification probe (`probe_ci01_unpinned.py`), checked in
as the enforcing gate: the `pin-lint` job in `.github/workflows/ci.yml`
runs it on every push/PR. Exit 1 with a `RESULT: ...` line when anything
is unpinned, exit 0 when every reference is pinned.

Usage: check_action_pins.py [<workflows-dir> ...]
Default: <repo-root>/.github/workflows (repo root resolved from this file).
"""
import re
import sys
from pathlib import Path

SHA = re.compile(r"@[0-9a-f]{40}\b")
USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)", re.M)
INSTALL = re.compile(r"cargo install\s+([^\n|;&]+)")


def scan(d):
    """Return (unpinned_uses, unpinned_installs) for one workflows dir."""
    unpinned_uses, unpinned_installs = [], []
    for f in sorted(Path(d).glob("*.yml")):
        text = f.read_text(encoding="utf-8")
        for m in USES.finditer(text):
            ref = m.group(1)
            if not SHA.search(ref):
                unpinned_uses.append(f"{f.name}: {ref}")
        for m in INSTALL.finditer(text):
            cmd = m.group(1).strip()
            if "--version" not in cmd:
                unpinned_installs.append(f"{f.name}: cargo install {cmd}")
    return unpinned_uses, unpinned_installs


def main(argv):
    if argv[1:]:
        dirs = [Path(a) for a in argv[1:]]
    else:
        dirs = [Path(__file__).resolve().parent.parent / ".github" / "workflows"]
    total_uses, total_installs = 0, 0
    for d in dirs:
        u, i = scan(d)
        total_uses += len(u)
        total_installs += len(i)
        print(f"== {d} ==")
        print(f"  unpinned uses: ({len(u)})")
        for x in u:
            print(f"    {x}")
        print(f"  cargo install without --version: ({len(i)})")
        for x in i:
            print(f"    {x}")
    print()
    print(f"RESULT: unpinned uses={total_uses} unpinned installs={total_installs}")
    if total_uses or total_installs:
        print("PIN LINT FAILED: pin every `uses:` to a full 40-hex commit SHA "
              "and give every `cargo install` a `--version` "
              "(see `.github/dependabot.yml` for the update story).")
        return 1
    print("clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
