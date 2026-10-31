# Polyglot status — pass / fail

Every language in `POLYGLOT.md` is required. This table is the release gate: a
single `FAIL` means phase C-8 is incomplete. There are no tiers and no optional
rows.

Verified 2026-10-31 at `ebec21d` (Infinity) and `66f9fef` (Active RPC), in the
`active-all-toolchains:phase2` container (Ubuntu 24.04).

| # | Language | Validate + hash | Redaction | Encode | RPC thin client | Result |
|---|----------|-----------------|-----------|--------|-----------------|--------|
| 1 | Rust | PASS | PASS | PASS | PASS (full kernel) | PASS |
| 2 | C | PASS | PASS | PASS | PASS | PASS |
| 3 | C++ | PASS | PASS | PASS | PASS | PASS |
| 4 | Python | PASS | PASS | PASS | PASS | PASS |
| 5 | Go | PASS | PASS | PASS | PASS | PASS |
| 6 | TypeScript | PASS | PASS | PASS | PASS | PASS |
| 7 | JavaScript (Node) | PASS | PASS | PASS | PASS | PASS |
| 8 | Java | PASS | PASS | PASS | PASS | PASS |
| 9 | C# / .NET | PASS | PASS | PASS | PASS | PASS |
| 10 | Kotlin (JVM) | PASS | PASS | PASS | PASS | PASS |
| 11 | Swift | PASS | PASS | PASS | PASS | PASS |
| 12 | Zig | PASS | PASS | PASS | PASS | PASS |
| 13 | Ruby | PASS | PASS | PASS | PASS | PASS |
| 14 | PHP | PASS | PASS | PASS | PASS | PASS |
| 15 | Scala | PASS | PASS | PASS | PASS | PASS |
| 16 | Dart | PASS | PASS | PASS | PASS | PASS |
| 17 | Kotlin/Native | PASS | PASS | PASS | PASS | PASS |
| 18 | AssemblyScript | PASS | PASS | PASS | PASS | PASS |
| 19 | Lua | PASS | PASS | PASS | PASS | PASS |
| 20 | Shell / ops | PASS | PASS | PASS | PASS | PASS |

## What each column means

- **Validate + hash**: the binding validates every valid manifest vector and
  reproduces its `content_hash` exactly.
- **Redaction**: `redacted_json` (or the CLI's `decode`) is asserted to exclude
  the `CANARY_SECRET_` canary; Dart and shell assert the same fixture.
- **Encode**: `reencode` returns canonical bytes, and active-source compilation
  (`fromActive` / `encode`) produces an image the binding validates.
- **RPC thin client**: native ARP1 over TCP against `active-rpc`'s real kernel
  peer — one successful `echo` with a server-minted capability carrying an AINF
  payload, one `rpc/method-not-granted` refusal, one `rpc/unknown-capability`
  refusal. Shell uses `polyglot/rpc/shell_client.sh`. Every language has its own
  client: Rust hand-encodes ARP1 with the standard library only
  (`polyglot/rpc/rust_client.rs`), and TypeScript is compiled from
  `polyglot/rpc/ts_client.ts` with `tsc --strict` rather than reusing the
  JavaScript script.

## CI jobs

`abi`, `wasm`, `polyglot-native`, `polyglot-go`, `polyglot-ts`,
`polyglot-scripting`, `polyglot-dotnet`, `polyglot-jvm`, `polyglot-swift`,
`polyglot-kotlin-native`, `polyglot-assemblyscript`, `polyglot-shell`, and
`polyglot-rpc` (live matrix plus byte-exact encoder conformance). The
`polyglot-rpc` job runs with `ACTIVE_RPC_STRICT=1` and names all 20 clients
(`python c cpp rust zig js ts go ruby php lua dart java kotlin scala csharp
swift ktnative assemblyscript shell`), so a missing runtime fails the job
instead of skipping a language.

## Reproduce

```text
# Infinity conformance for every language (per-language runners in the table
# above; the CI jobs run each one).
bash polyglot/shell/test.sh

# Thin RPC matrix and encoder conformance (needs the Active RPC checkout).
bash polyglot/rpc/run_clients.sh /path/to/active-rpc "$PWD"
```

Encoder bytes are compared with the Rust reference; on a mismatch the check
prints the first differing byte offset. All 20 languages produce identical
request bytes: the 18 earlier clients, the TypeScript client compiled with
`tsc --strict`, and a Rust thin client that hand-encodes ARP1 with the standard
library only (so the reference language is checked by an implementation that
does not use the kernel codec).
