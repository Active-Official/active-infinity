# `active-infinity-cli` crates.io release checklist

The CLI is a binary crate that depends on the published `active-infinity`
library. Release it only after the library version it pins is live.

## Preconditions

1. `Cargo.toml` `version` is higher than the reserved crate on crates.io
   (`cargo info active-infinity-cli`).
2. `active-infinity = { version = "X.Y.Z" }` names a published library version,
   and every feature the CLI enables (`active-core`, `json`, `zstd`) exists in
   that release.
3. `Cargo.lock` is committed (CI runs `cargo test --locked`).
4. `README.md`, description, keywords, categories and both license files are in
   the package.

## Gates

```text
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo publish --dry-run
```

`cargo publish --dry-run` packages the crate, resolves the registry dependency
and builds it from the packaged sources, which catches missing files that a
path build hides.

The repository `cli` CI job runs the format, test and lint gates on every push.

## Release

1. Tag the library release that the CLI pins.
2. `cargo publish` from `cli/active-infinity-cli`.
3. Verify: `cargo info active-infinity-cli` shows the new version and
   description, and `cargo install active-infinity-cli --locked` builds.
4. Smoke test the installed binary:

   ```text
   active-infinity-cli doctor
   active-infinity-cli conformance run --manifest conformance/manifest.json
   ```

5. Record the version and publish date in the release notes.

## Rollback

A published version cannot be replaced. `cargo yank --version X.Y.Z` stops new
resolutions while existing lockfiles keep working; publish a fixed version and
yank the bad one.

## Manual and install docs

- `docs/man/active-infinity-cli.1` (also linked from the top-level README).
- `cli/active-infinity-cli/README.md` carries the full command reference and
  examples; `--help` prints the same set.
