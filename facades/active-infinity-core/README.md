# active-infinity-core

The canonical encode, decode, validate and content-hash surface.

This crate is a thin, versioned facade over [`active-infinity`](https://crates.io/crates/active-infinity).
The implementation lives in the parent crate; this package keeps the module
name stable for downstream users and protects the namespace for the project.

- Repository: <https://github.com/Active-Official/active-infinity>
- Main crate: <https://crates.io/crates/active-infinity>
- License: MIT OR Apache-2.0

```toml
[dependencies]
active-infinity-core = "0.1"
```
