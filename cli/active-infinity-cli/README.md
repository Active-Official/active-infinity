# active-infinity-cli

Production command-line surface for the Active Infinity codec. Every command
calls the Rust reference, so bytes, hashes and redaction match the library.

## Synopsis

```text
active-infinity-cli <command> [options]

  encode <source.active> [--name NAME] [--output PATH]
  decode <image.ainf>
  validate <image.ainf>
  hash <image.ainf>
  stream <image.ainf>
  store put <image.ainf> [--root DIR]
  store get <hash> [--root DIR] [--output PATH]
  dict train --output <dict> [--size N] <sample>...
  dict apply --dictionary <dict> [--decompress] [--level N] [--max-bytes N] <input>
  proof issue <image> [--schema PATH] [--output PATH]
  proof verify <image> <proof> [--schema PATH]
  bench <encode|decode|validate|hash> <file> [--iterations N]
  conformance run [--manifest PATH]
  doctor
  help
```

Without `--output`, commands that emit bytes write to stdout.

## Commands

| Command | Behavior |
|---------|----------|
| `encode` | Compile Active text to canonical AINF. `--name` sets the module name (it does not affect the content hash). |
| `decode` | Validate, then print the redacted JSON projection. Secret values never appear. |
| `validate` | Fail-closed validation; prints node and byte counts on success. |
| `hash` | Blake3 content hash over the canonical image, 64 hex characters. |
| `stream` | Reassemble an AINS stream and print the image hash. |
| `store put` / `store get` | Content-addressed local store (default root `.active-store`). `put` prints the hash. |
| `dict train` | Train a zstd dictionary from representative images or frames. |
| `dict apply` | Compress with a dictionary, or decompress with `--decompress` and an output ceiling. |
| `proof issue` | Write a JSON sidecar: hash, size, counts, secret count, dialect and an optional companion-schema hash. |
| `proof verify` | Recompute every property and refuse a mismatch with `infinity/proof`. |
| `bench` | Local microbench; prints `p50_ns`, `p95_ns`, `p99_ns`. |
| `conformance run` | Run the vector pack; prints a JSON scorecard and fails on any case. |
| `doctor` | Version, compiled features, exit codes. |
| `help` | Full usage with examples. |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. |
| `1` | Validation, verification, I/O or codec failure (message starts with the stable `infinity/...` code). |
| `2` | Usage error (unknown command, missing argument, bad flag). |

## Examples

```bash
# Compile, hash and inspect
active-infinity-cli encode app.active --name app.active --output app.ainf
active-infinity-cli hash app.ainf
active-infinity-cli decode app.ainf

# Content-addressed store
active-infinity-cli store put app.ainf --root .active-store
active-infinity-cli store get <hash> --root .active-store --output restored.ainf

# Dictionary compression (hashes stay over uncompressed bytes)
active-infinity-cli dict train --output frames.dict tests/vectors/valid/*.ainf
active-infinity-cli dict apply --dictionary frames.dict --output app.ainf.zst app.ainf
active-infinity-cli dict apply --decompress --dictionary frames.dict \
  --output app.back app.ainf.zst

# Microbench and conformance
active-infinity-cli bench validate app.ainf --iterations 100
active-infinity-cli conformance run --manifest conformance/manifest.json

# Proof sidecar
active-infinity-cli proof issue app.ainf --output app.proof.json
active-infinity-cli proof verify app.ainf app.proof.json
```

## Notes

- `dict train` derives a workable default dictionary size from the corpus, and
  refuses a `--size` larger than the samples can support instead of failing
  inside zstd.
- Decompression always takes an explicit ceiling (`--max-bytes`, default
  64 MiB), so a hostile frame cannot expand without bound.
- Diagnostics never print secret payloads or raw capability authority.
