# R

`active_infinity.R` binds the frozen C ABI with base R `.C` only (no packages).
Because `.C` passes a pointer for every argument, `native/active_infinity_r.c`
is a small shim that adapts the ABI's by-value `size_t` and `size_t *`
parameters to that convention. `test_conformance.R` is the lane.

```sh
cargo build --release --manifest-path ffi/active-infinity-ffi/Cargo.toml
gcc -shared -fPIC -O2 -I ffi/active-infinity-ffi/include \
  polyglot/r/native/active_infinity_r.c \
  ffi/active-infinity-ffi/target/release/libactive_infinity_ffi.a \
  -lpthread -ldl -lm -o polyglot/r/active_infinity_r.so
ACTIVE_INFINITY_LIB=$PWD/ffi/active-infinity-ffi/target/release/libactive_infinity_ffi.so \
  Rscript polyglot/r/test_conformance.R
```

Windows builds `active_infinity_r.dll` against `active_infinity_ffi.dll.lib`;
`Rscript` finds it next to the binding, or through `ACTIVE_INFINITY_R_SHIM`.

The lane validates every valid vector, reproduces its manifest content hash,
re-encodes canonically, compiles Active text, checks the redacted JSON
projection for the canary and refuses malformed input.
