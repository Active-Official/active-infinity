# COBOL (GnuCOBOL 3.2+)

`conformance.cob` calls the frozen C ABI directly with `CALL STATIC`. GnuCOBOL
has no byte-oriented file, hex or JSON library, so `native/active_infinity_cobol.c`
supplies file reading, hex formatting, the error-code copy and a manifest scan.
Those helpers are lane scaffolding, not part of the binding.

```sh
cargo build --release --manifest-path ffi/active-infinity-ffi/Cargo.toml
gcc -shared -fPIC -O2 -I ffi/active-infinity-ffi/include \
  polyglot/cobol/native/active_infinity_cobol.c \
  ffi/active-infinity-ffi/target/release/libactive_infinity_ffi.a \
  -lpthread -ldl -lm -o polyglot/cobol/active_infinity_cobol.so
cobc -x -free -o conformance-cobol polyglot/cobol/conformance.cob \
  polyglot/cobol/active_infinity_cobol.so
LD_LIBRARY_PATH=$PWD/ffi/active-infinity-ffi/target/release ./conformance-cobol
```

Windows: build the shim with `gcc -shared ... -Wl,--out-implib,libactive_infinity_cobol.dll.a`
against `active_infinity_ffi.dll.lib`, then `cobc -x -free ... conformance.cob
libactive_infinity_cobol.dll.a active_infinity_ffi.dll.lib`; run with the shim
directory and the FFI directory on `Path`. `COB_CONFIG_DIR` may be needed when
`cobc` cannot find the MSYS2 configuration.

The lane validates every valid vector, reproduces its manifest content hash,
re-encodes canonically, compiles Active text, checks the redacted JSON
projection for the canary and refuses malformed input.
