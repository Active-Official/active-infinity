#!/usr/bin/env python3
"""Semantic public-surface gate: no public API may return secret plaintext.

Reads the rustdoc JSON for the crate and fails if a public item (free function,
inherent method, trait method) whose name mentions secrets returns raw text or
bytes, or if a public re-export exposes one of the known accessor names.

The textual scan in `tests/api_surface.rs` is a fast tripwire; this script is the
authoritative check because it sees the resolved API, including methods, trait
items and re-exports.

Usage:
    cargo +nightly rustdoc --lib --all-features -- \\
        -Zunstable-options --output-format json
    python3 scripts/api_surface.py target/doc/active_infinity.json
"""

from __future__ import annotations

import json
import sys

# Names this crate must never export again.
BLACKLIST = {
    "secret_texts",
    "secret_bytes",
    "secret_literals",
    "secret_values",
    "secret",
}

# Functions whose name mentions secrets but whose return is not secret material.
ALLOW = {
    "secret_tainted_paths": "returns redacted dotted labels, never secret bytes",
}

# Return-type tokens that mean raw text or bytes.
RAW_TOKENS = {"String", "str", "u8", "char"}


# The rustdoc index, set once in `main`, so alias resolution can look items up.
_INDEX: dict = {}


def type_tokens(node, out: set[str], depth: int = 0) -> None:
    """Collect type names, following crate-local `type` aliases.

    Alias resolution matters: `type Bytes = Vec<u8>; pub fn secret_x() -> Bytes`
    would otherwise contribute only the token `Bytes`.
    """
    if depth > 24 or node is None:
        return
    if isinstance(node, dict):
        if "primitive" in node and isinstance(node["primitive"], str):
            out.add(node["primitive"])
        if "generic" in node and isinstance(node["generic"], str):
            out.add(node["generic"])
        if "resolved_path" in node:
            path = node["resolved_path"].get("path") or ""
            out.add(path.split("::")[-1])
            target = _INDEX.get(str(node["resolved_path"].get("id")))
            # Rustdoc JSON spells a type alias `inner.type_alias` with the
            # aliased type under `.type`; follow it so an alias cannot hide a
            # raw return type.
            alias = (target or {}).get("inner", {}).get("type_alias")
            if alias:
                type_tokens(alias.get("type"), out, depth + 1)
        for value in node.values():
            type_tokens(value, out, depth + 1)
    elif isinstance(node, list):
        for value in node:
            type_tokens(value, out, depth + 1)


def returns_raw(function: dict) -> set[str]:
    tokens: set[str] = set()
    output = function.get("sig", {}).get("output")
    type_tokens(output, tokens)
    return tokens & RAW_TOKENS


def location(item: dict) -> str:
    span = item.get("span") or {}
    filename = span.get("filename", "?")
    begin = span.get("begin") or [0, 0]
    return f"{filename}:{begin[0]}"


def check_function(item: dict, public: bool, where: str) -> list[str]:
    findings = []
    name = item.get("name") or ""
    if not public or not name:
        return findings
    if name in BLACKLIST:
        findings.append(f"{where}: public item `{name}` is blacklisted")
        return findings
    if "secret" not in name:
        return findings
    if name in ALLOW:
        return findings
    raw = returns_raw(item.get("inner", {}).get("function", {}))
    if raw:
        findings.append(
            f"{where}: public `{name}` returns raw {sorted(raw)}; "
            "secrets must leave only through a redaction marker"
        )
    return findings


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: api_surface.py <rustdoc.json>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as handle:
        doc = json.load(handle)
    index = doc.get("index", {})
    global _INDEX
    _INDEX = index

    findings: list[str] = []
    for item in index.values():
        inner = item.get("inner", {})
        visibility = item.get("visibility")

        if "function" in inner:
            findings += check_function(item, visibility == "public", location(item))

        if "trait" in inner and visibility == "public":
            for member_id in inner["trait"].get("items", []):
                member = index.get(str(member_id))
                if member and "function" in member.get("inner", {}):
                    findings += check_function(member, True, location(member))

        if "impl" in inner:
            # Inherent impls only: trait impls cannot add a new public name.
            if inner["impl"].get("trait") is None:
                for member_id in inner["impl"].get("items", []):
                    member = index.get(str(member_id))
                    if member and "function" in member.get("inner", {}):
                        findings += check_function(
                            member,
                            member.get("visibility") == "public",
                            location(member),
                        )

        if "use" in inner and visibility == "public":
            use = inner["use"]
            name = use.get("name") or ""
            source = (use.get("source") or "").split("::")[-1]
            if use.get("is_glob"):
                findings.append(
                    f"{location(item)}: public glob re-export cannot be audited; "
                    "re-export the names explicitly"
                )
            elif name in BLACKLIST or source in BLACKLIST:
                findings.append(
                    f"{location(item)}: public re-export of `{name or source}`"
                )
            else:
                target = index.get(str(use.get("id")))
                if target and "function" in target.get("inner", {}):
                    findings += check_function(target, True, location(item))

    if findings:
        print("public secret surface violations:", file=sys.stderr)
        for finding in findings:
            print("  " + finding, file=sys.stderr)
        return 1
    print(
        f"api surface clean: {len(index)} items, "
        f"{len(ALLOW)} justified allowlist entries"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
