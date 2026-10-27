# Fuzzing

Two targets exercise the untrusted-input surface:

- `decode` — `validate`, `decode`, re-encode equality, canonical proof and the
  zero-copy view over arbitrary bytes.

## Running

```bash
cargo install cargo-fuzz --locked
cargo +nightly fuzz run decode -- -runs=200000
```

On Linux the target builds with the libFuzzer runtime from `clang`
(`apt-get install clang`). On Windows MSVC the current cargo-fuzz/libFuzzer
combination fails to *launch* with `STATUS_DLL_NOT_FOUND`; that is an environment
limitation, not a target defect. Use a Linux container:

```bash
docker run --rm -v "$PWD:/work" -w /work rust:1.85-bookworm bash -c \
  "apt-get update -qq && apt-get install -y -qq clang && \
   rustup toolchain install nightly --profile minimal && \
   cargo +nightly install cargo-fuzz --locked && \
   cargo +nightly fuzz run decode -- -runs=20000"
```

## Corpus

Seed the corpus with the conformance vectors; they reach the parser deeply, so a
campaign starts from real structure instead of discovering `AINF` byte by byte:

```bash
mkdir -p fuzz/corpus/decode
cp tests/vectors/valid/*.ainf tests/vectors/invalid/*.ainf fuzz/corpus/decode/
```

`fuzz/corpus` and `fuzz/artifacts` are not committed: the vectors under
`tests/vectors` are the canonical, reviewed seed set.

## Invariants asserted by the target

1. `validate` answers for every input (no panic, no hang, no over-allocation).
2. A validated buffer decodes.
3. A validated image re-encodes to itself and `validate_canonical` agrees.
4. Views never panic on validated input.

A crash or an assertion failure is a release blocker; the artifact goes into the
issue with the input that produced it.
