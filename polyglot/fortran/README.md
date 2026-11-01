# Fortran

`active_infinity.f90` is an `iso_c_binding` module over the frozen C ABI;
`conformance.f90` is the lane.

```sh
cargo build --release --manifest-path ffi/active-infinity-ffi/Cargo.toml
gfortran -I polyglot/fortran polyglot/fortran/active_infinity.f90 \
  polyglot/fortran/conformance.f90 \
  ffi/active-infinity-ffi/target/release/libactive_infinity_ffi.a \
  -lpthread -ldl -lm -o conformance-fortran
LD_LIBRARY_PATH=$PWD/ffi/active-infinity-ffi/target/release ./conformance-fortran
```

Windows links the DLL import library
(`active_infinity_ffi.dll.lib`) and needs both that directory and the compiler
runtime directory on `Path`.

The lane validates every valid vector, reproduces its manifest content hash,
re-encodes canonically, compiles Active text, checks the redacted JSON
projection for the canary and refuses malformed input. The manifest is parsed by
a small scanner because Fortran has no JSON library.
