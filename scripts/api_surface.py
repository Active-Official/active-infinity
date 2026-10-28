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


# The rustdoc JSON format this script understands. A nightly bump that changes
# the schema must fail loudly instead of silently reporting a clean surface.
SUPPORTED_FORMAT = 61


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: api_surface.py <rustdoc.json>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as handle:
        doc = json.load(handle)

    # Fail closed on schema drift: a renamed key would otherwise make every
    # branch below skip and print "clean".
    findings: list[str] = []
    format_version = doc.get("format_version")
    if format_version != SUPPORTED_FORMAT:
        findings.append(
            f"{argv[1]}: unsupported rustdoc format_version {format_version!r} "
            f"(expected {SUPPORTED_FORMAT}); update scripts/api_surface.py"
        )
    index = doc.get("index")
    if not isinstance(index, dict) or not index:
        findings.append(f"{argv[1]}: rustdoc JSON has no item index")
        index = {}
    root = str(doc.get("root"))
    if index and root not in index:
        findings.append(f"{argv[1]}: crate root {root} missing from the index")
    global _INDEX
    _INDEX = index

    functions_seen = 0
    for item_id, item in index.items():
        inner = item.get("inner")
        if not isinstance(inner, dict):
            findings.append(f"item {item_id}: missing `inner`")
            continue
        visibility = item.get("visibility")
        if not isinstance(visibility, str):
            findings.append(f"item {item_id}: missing `visibility`")

        if "function" in inner:
            functions_seen += 1
            findings += check_function(item, visibility == "public", location(item))

        if "trait" in inner and visibility == "public":
            items = inner["trait"].get("items")
            if not isinstance(items, list):
                findings.append(
                    f"{location(item)}: public trait has no `items` array; "
                    "the rustdoc schema changed"
                )
                items = []
            for member_id in items:
                member = index.get(str(member_id))
                if member and "function" in member.get("inner", {}):
                    functions_seen += 1
                    findings += check_function(member, True, location(member))

        if "impl" in inner:
            # Inherent impls only: trait impls cannot add a new public name.
            if inner["impl"].get("trait") is None:
                items = inner["impl"].get("items")
                if not isinstance(items, list):
                    findings.append(
                        f"{location(item)}: inherent impl has no `items` array; "
                        "the rustdoc schema changed"
                    )
                    items = []
                for member_id in items:
                    member = index.get(str(member_id))
                    if member and "function" in member.get("inner", {}):
                        functions_seen += 1
                        findings += check_function(
                            member,
                            member.get("visibility") == "public",
                            location(member),
                        )

        if "use" in inner and visibility == "public":
            use = inner["use"]
            name = use.get("name") or ""
            source = (use.get("source") or "").split("::")[-1]
            target = index.get(str(use.get("id")))
            if use.get("is_glob"):
                findings.append(
                    f"{location(item)}: public glob re-export cannot be audited; "
                    "re-export the names explicitly"
                )
                continue
            if name in BLACKLIST or source in BLACKLIST:
                findings.append(
                    f"{location(item)}: public re-export of `{name or source}`"
                )
                continue
            # The *public* name is what a caller sees: apply the shape rule to
            # the alias, not only to the target's own name, so
            # `pub use innocent as secret_x` cannot launder a raw return.
            if "secret" in name:
                if target is None:
                    findings.append(
                        f"{location(item)}: public alias `{name}` cannot be "
                        "resolved; refusing to guess"
                    )
                    continue
                reuse = dict(target)
                reuse["name"] = name
                findings += check_function(reuse, True, location(item))
            elif target is not None and "function" in target.get("inner", {}):
                functions_seen += 1
                findings += check_function(target, True, location(item))

    # A schema rename would leave the counters at zero; that is drift, not a
    # clean surface.
    if index and functions_seen < 10:
        findings.append(
            f"{argv[1]}: only {functions_seen} functions recognised; "
            "the rustdoc schema probably changed"
        )

    # Deduplicate: a trait method can be reached from more than one branch.
    findings = list(dict.fromkeys(findings))

    if findings:
        print("public secret surface violations:", file=sys.stderr)
        for finding in findings:
            print("  " + finding, file=sys.stderr)
        return 1
    print(
        f"api surface clean: {len(index)} items, {functions_seen} functions, "
        f"{len(ALLOW)} justified allowlist entries"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
