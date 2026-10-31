# Release signing and attestation

What protects an `active-infinity` release, and the result of the Sigstore/cosign
spike run for the Absolute Max program (M-5.3). The procedure lives in
`docs/release-runbook.md`; the RPC repository carries the same spike in
`docs/release/signing.md` with its own artifacts.

## What exists today

| Layer | Mechanism | Where |
|---|---|---|
| Source | SSH-signed git tags, identical object on both remotes | runbook step 2 |
| Build inputs | `Cargo.lock` committed, `--locked` in every job | `.github/workflows/ci.yml` |
| Bill of materials | CycloneDX 1.5 SBOM from `cargo metadata --locked`, attached to the GitHub Release | `scripts/sbom.py`, `.github/workflows/release.yml` |
| Supply-chain policy | `cargo audit --deny warnings` + `cargo deny check` | `supply-chain` job, `audit.toml`, `deny.toml` |
| Registry | crates.io publish by a human with a scoped token, then install-and-verify | runbook steps 3–5 |

The tag signature says who wrote the commit; the SBOM says what the locked graph
contained. Neither says the released bytes were built from that commit — that is
what an attestation adds.

## Spike result (2026-10-31)

Executed with `ghcr.io/sigstore/cosign/cosign:v2.4.1` in Docker against the SBOM
of a real tagged release:

- `generate-key-pair` writes `cosign.key` / `cosign.pub`.
- `sign-blob --key` defaults to uploading the signature to the **public Rekor
  transparency log** and prompts for consent; in a non-interactive job it fails
  with "user declined the prompt". Passing `--tlog-upload=false` signs offline.
- `verify-blob --key --insecure-ignore-tlog` prints `Verified OK` and one warning
  that transparency was skipped.
- A one-byte change to the SBOM with the same signature fails:
  `invalid signature when validating ASN.1 encoded signature`.
- Keyless signing (`cosign sign-blob --yes --bundle`) needs `id-token: write`,
  Fulcio and Rekor, so it could not be exercised offline; it is the intended CI
  path, with verification pinned to
  `--certificate-identity-regexp '^https://github\.com/Active-Official/active-infinity/'`
  and `--certificate-oidc-issuer https://token.actions.githubusercontent.com`.

## Decision

- SSH-signed tags stay the root of trust.
- The SBOM is the artifact inventory, attached automatically by `release.yml` and
  verified by the job (`gh release view --json assets`).
- No signing key is stored in CI: a long-lived key whose compromise is
  indistinguishable from a legitimate release is worse than the status quo.
- Keyless attestation is the planned upgrade once the organisation has a release
  environment: add `id-token: write` plus a `cosign sign-blob --yes --bundle`
  step to `release.yml` and upload the bundle beside the SBOM.

## Reproducible builds

Inputs are pinned (`Cargo.lock`, `--locked`, `rust-version`, the stable
toolchain action). Bit-identical binaries are not claimed: rustc embeds paths and
the standard library build. A verifier checks out the tag, builds with
`--locked`, and compares behavior; the release job's logs retain
`cargo --version` and `rustc --version`.

## Trusted publishing

crates.io trusted publishing (GitHub Actions OIDC) removes the registry token:
register `Active-Official/active-infinity` and `RatioArtificiosa/active-infinity`
as trusted publishers for workflow `release.yml` with environment `release`, then
add a `publish` job with `permissions: { id-token: write, contents: read }`
running `cargo publish`. Not enabled yet: the publisher must be registered on
crates.io first, and the runbook publishes by hand with a token that is never
stored in the repository.
