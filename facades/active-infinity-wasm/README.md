# active-infinity-wasm

The reserved WebAssembly binding namespace for Active Infinity.

There is no wasm API in this release. The canonical codec ships today in
[`active-infinity`](https://crates.io/crates/active-infinity). This package
keeps the binding name with the project while the WebAssembly surface is
designed; it deliberately has no dependency and exports only the name of the
implementation crate.

- Repository: <https://github.com/Active-Official/active-infinity>
- Main crate: <https://crates.io/crates/active-infinity>
- License: MIT OR Apache-2.0
