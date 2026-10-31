# Shell / ops binding

For shell and ops the CLI is the binding: `active-infinity-cli` is the
production surface, and it calls the same Rust reference as every other
language.

## Prerequisites

- `cargo`
- `python3` (the test reads the manifest and validates JSON; standard library
  only)

## Conformance

```text
bash polyglot/shell/test.sh
```

The script builds the CLI, runs `doctor` and the conformance suite, then checks
every valid manifest vector for two properties: it validates, and `hash`
reproduces the manifest content hash. It finishes with the redaction check:
`decode` must return valid JSON without the `CANARY_SECRET_` canary.

## Quickstart

```text
active-infinity-cli validate module.ainf
active-infinity-cli hash module.ainf
active-infinity-cli decode module.ainf          # redacted JSON
active-infinity-cli encode module.active --name demo.active --output demo.ainf
active-infinity-cli stream module.ainf          # AINS stream frames
active-infinity-cli store put module.ainf --root ./store
active-infinity-cli conformance run --manifest conformance/manifest.json
active-infinity-cli doctor
```

Build it with:

```text
cargo build --release --manifest-path cli/active-infinity-cli/Cargo.toml
```

## Active RPC

`polyglot/rpc/shell_client.sh` is the thin ARP1 client: POSIX `bash`, `/dev/tcp`
and `od`, no dependencies. It builds the envelope byte by byte, presents a
capability, verifies the payload echo, and checks both refusal codes.

```text
bash polyglot/rpc/run_clients.sh /path/to/active-rpc "$PWD" shell
```

The dedicated `active-rpc-cli` (checklist C-9.2) becomes the primary ops surface
for RPC calls once it ships; the shell client stays as the dependency-free
reference and encoder check.
