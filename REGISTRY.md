# Active Infinity crate family

The published crates keep the codec, streaming and interop names with the
project. Facade sources live in `facades/` and are excluded from the main
`active-infinity` package tarball.

| Crate | Version | Purpose |
|---|---|---|
| [`active-infinity`](https://crates.io/crates/active-infinity) | 2.1.0 | Canonical binary, graph-native, secret-safe module codec |
| [`active-infinity-core`](https://crates.io/crates/active-infinity-core) | 0.1.0 | Encode, decode, validate and content-hash surface |
| [`active-infinity-stream`](https://crates.io/crates/active-infinity-stream) | 0.1.0 | Bounded streaming frames and canonical reassembly |
| [`active-infinity-interop`](https://crates.io/crates/active-infinity-interop) | 0.1.0 | Active IR, redacted JSON and Protobuf projections |
| [`active-infinity-wasm`](https://crates.io/crates/active-infinity-wasm) | 0.1.0 | Reserved WebAssembly binding namespace |
| [`active-infinity-cli`](https://crates.io/crates/active-infinity-cli) | 0.1.0 | Reserved CLI name |

Each facade is a thin, versioned re-export of the shipped module. The main
crate remains the implementation and the source of truth.

Python and JavaScript registries are intentionally not reserved while these
are Rust-only libraries. Empty npm or PyPI packages would misrepresent the API;
the crates above are the supported distribution channel.
