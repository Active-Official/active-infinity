# Julia

`ActiveInfinity.jl` binds the frozen C ABI with `ccall`; `conformance.jl` is the
lane. There is no package dependency.

```sh
cargo build --release --manifest-path ffi/active-infinity-ffi/Cargo.toml
ACTIVE_INFINITY_LIB=$PWD/ffi/active-infinity-ffi/target/release/libactive_infinity_ffi.so \
  julia polyglot/julia/conformance.jl
```

Windows: point `ACTIVE_INFINITY_LIB` at `active_infinity_ffi.dll` and put its
directory on `Path`.

The lane validates every valid vector, reproduces its manifest content hash,
re-encodes canonically, compiles Active text through `from_active`, checks the
redacted JSON projection for the canary and refuses malformed input.
