# Maturity release runbook — dual remote + crates.io

The program ships to two organizations (Active-Official and RatioArtificiosa)
and two crates (the library and its CLI). This runbook is executed for every
maturity release; the executed record lives in `STATUS.md`.

## Preconditions

1. Every CI job is green on both remotes at the candidate commit.
2. Versions are bumped in `Cargo.toml` (library and CLI) and the lockfiles are
   refreshed; `CHANGELOG.md` has a dated section; `REGISTRY.md` lists the
   versions.
3. `cargo publish --dry-run` succeeds for the library, and for the CLI once the
   library version is resolvable.
4. `STATUS.md` reflects the candidate state and its residual risks.

## Order

1. **Commit and push both remotes.**
   ```text
   git push official HEAD
   git push ratio HEAD
   git ls-remote official refs/heads/main
   git ls-remote ratio refs/heads/main
   ```
   Both SHAs must equal the local `HEAD`.
2. **Tag and push the tag.**
   ```text
   git tag -a vX.Y.Z -m "active-infinity X.Y.Z"
   git push official vX.Y.Z
   git push ratio vX.Y.Z
   ```
   Tag pushes run the full CI, including the audit, deny and SBOM release gates.
   A signed tag is produced when a signing key is available
   (`git tag -s`).
3. **Publish the library.** `cargo publish`, waiting for the registry to report
   the version available.
4. **Publish the CLI.** It pins the library version, so it must follow:
   `cd cli/active-infinity-cli && cargo publish`.
5. **Verify from the registry.**
   ```text
   cargo install active-infinity-cli --locked --root <temporary-root>
   <temporary-root>/bin/active-infinity-cli doctor
   <temporary-root>/bin/active-infinity-cli conformance run --manifest conformance/manifest.json
   ```
6. **Record.** Append the version, the two remote SHAs and the date to
   `STATUS.md`.

## Rollback

- A published version cannot be replaced: `cargo yank --version X.Y.Z` stops new
  resolutions while existing lockfiles keep working, then publish a fixed patch.
- Tags are immutable; a bad tag is superseded by a new patch release, and the
  release notes point at the replacement.

## Executed record

| Date | Library | CLI | Commit | Tag (both remotes) | crates.io |
|------|---------|-----|--------|--------------------|-----------|
| 2026-10-31 | 2.3.0 | 0.3.0 | `fd3f23d` (`v2.3.0^{}`) | `f67ba71` on Active-Official and RatioArtificiosa, identical peeled SHA | `active-infinity` 2.3.0, `active-infinity-cli` 0.3.0 |
| 2026-10-31 | 2.2.0 | 0.2.0 | `ddc4e3f` (`v2.2.0^{}`) | backfilled tag for the published 2.2.0 | `active-infinity` 2.2.0 |

Release commit `fd3f23d`: CI 41203155120 (Active-Official) and 41203157346
(RatioArtificiosa), both green. Tag object `f67ba71f86505fca2cd5b3bd0db8a2fa0de5884f`
on both remotes, peeled to `fd3f23dac0425106398adcd42b41a995b82994c3`.

Install verification: `cargo install active-infinity-cli --version 0.3.0
--locked` then `doctor` and `conformance run` from the registry build.

A CLI-only patch release is recorded here with its commit and does not move the
library tag: the tag names the library version, and the CLI has its own.

| 2026-10-31 | 2.3.0 | 0.3.1 | `5755064` | CLI-only patch; the library tag stays `v2.3.0` | `active-infinity-cli` 0.3.1 |

Registry verification: `cargo install active-infinity-cli --version 0.3.1
--locked` replaced 0.3.0, `active-infinity-cli --version` prints
`active-infinity-cli 0.3.1 (active-infinity 2.3.0)`, and `conformance run`
passes all 49 cases from the registry build. A consumer crate with
`active-infinity = "2.3.0"` encodes, validates, hashes and decodes a module and
reproduces the same bytes. The SBOM lists 161 components.
