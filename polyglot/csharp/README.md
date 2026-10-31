# C# / .NET binding

`ActiveInfinity.Image` is a P/Invoke wrapper over the C ABI. Validation,
canonical re-encoding, content hashes and redacted JSON run in the Rust
reference.

## Prerequisites

- .NET SDK 8
- `cargo` (to build `libactive_infinity_ffi`)

## Conformance

```text
(cd ffi/active-infinity-ffi && cargo build --release)
LD_LIBRARY_PATH="$PWD/ffi/active-infinity-ffi/target/release" \
  dotnet run -c Release --project polyglot/csharp/Conformance
```

## Quickstart

```csharp
using ActiveInfinity;

var image = Image.FromFile("module.ainf").Validate();
string hash = image.ContentHashHex();
byte[] canonical = image.Reencode();
string json = image.RedactedJson();
byte[] built = Image.FromActive("module demo { }", "demo.active");
```

Failures throw `ActiveInfinityException` with `Code` (`infinity/...`) and
`Status`. The native library is resolved by name `active_infinity_ffi`, so keep
it on `LD_LIBRARY_PATH` (Linux), `DYLD_LIBRARY_PATH` (macOS), or `PATH`
(Windows).

## Active RPC

`polyglot/rpc/csharp/Program.cs` is the thin ARP1 client:

```text
bash polyglot/rpc/run_clients.sh /path/to/active-rpc "$PWD" csharp
```
