//! Production CLI for Active Infinity.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use active_infinity::compress::{
    compress_with_dictionary, decompress_with_dictionary, train_dictionary,
};
use active_infinity::stream::StreamDecoder;
use active_infinity::{
    content_hash_hex, decode, encode, interop::from_active_source, validate, validate_canonical,
    Limits, Proof, Store, VERSION,
};
use serde_json::json;

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(if error.starts_with("usage:") { 2 } else { 1 })
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(usage());
    };
    match command {
        "validate" => {
            let path = args.get(1).ok_or_else(usage)?;
            let bytes = read(path)?;
            let meta = validate(&bytes).map_err(|error| format!("{}: {}", error.code(), error))?;
            println!("ok nodes={} bytes={}", meta.nodes, bytes.len());
            Ok(())
        }
        "hash" => {
            let path = args.get(1).ok_or_else(usage)?;
            let bytes = read(path)?;
            println!(
                "{}",
                content_hash_hex(&bytes).map_err(|error| error.code().to_string())?
            );
            Ok(())
        }
        "decode" => {
            let path = args.get(1).ok_or_else(usage)?;
            let bytes = read(path)?;
            validate(&bytes).map_err(|error| format!("{}: {}", error.code(), error))?;
            let module = decode(&bytes).map_err(|error| error.code().to_string())?;
            let json = active_infinity::interop::to_redacted_json(&module)
                .map_err(|error| error.code().to_string())?;
            println!("{json}");
            Ok(())
        }
        "encode" => {
            let path = args.get(1).ok_or_else(usage)?;
            let name = args
                .iter()
                .position(|arg| arg == "--name")
                .and_then(|index| args.get(index + 1))
                .cloned()
                .unwrap_or_else(|| "module.active".to_string());
            let source = fs::read_to_string(path).map_err(|error| error.to_string())?;
            let module = from_active_source(&source, &name)
                .map_err(|error| format!("{}: {}", error.code(), error))?;
            let image = encode(&module).map_err(|error| error.code().to_string())?;
            write_output(&args, &image)?;
            if let Some(output) = arg_value(&args, "--output") {
                eprintln!("wrote {output} ({} bytes)", image.len());
            }
            Ok(())
        }
        "stream" => stream_command(&args),
        "store" => store_command(&args),
        "dict" => dict_command(&args),
        "proof" => proof_command(&args),
        "bench" => bench_command(&args),
        "conformance" => conformance(&args),
        "help" | "--help" | "-h" => {
            println!("{}", help_text());
            Ok(())
        }
        "doctor" => {
            println!(
                "active-infinity-cli {} (active-infinity {})",
                env!("CARGO_PKG_VERSION"),
                VERSION
            );
            println!("features: json active-core zstd");
            println!("exit codes: 0 success, 1 failure, 2 usage");
            Ok(())
        }
        other => Err(format!("usage: unknown command {other}\n{}", usage())),
    }
}

fn stream_command(args: &[String]) -> Result<(), String> {
    let path = args.get(2).ok_or_else(usage)?;
    let bytes = read(path)?;
    let mut decoder = StreamDecoder::new();
    decoder
        .push_bytes(&bytes)
        .map_err(|error| format!("{}: {}", error.code(), error))?;
    let streamed = decoder
        .finish()
        .map_err(|error| format!("{}: {}", error.code(), error))?;
    println!(
        "ok bytes={} hash={}",
        streamed.image.len(),
        content_hash_hex(&streamed.image).map_err(|error| error.code().to_string())?
    );
    Ok(())
}

fn store_command(args: &[String]) -> Result<(), String> {
    let action = args.get(1).ok_or_else(usage)?;
    let root = arg_value(args, "--root").unwrap_or_else(|| ".active-store".to_string());
    let store = Store::open(root).map_err(|error| error.to_string())?;
    match action.as_str() {
        "put" => {
            let path = args.get(2).ok_or_else(usage)?;
            let image = read(path)?;
            let hash = store.put(&image).map_err(|error| error.to_string())?;
            println!("{}", hex(&hash));
            Ok(())
        }
        "get" => {
            let hash = args.get(2).ok_or_else(usage)?;
            let parsed = parse_hash(hash)?;
            let image = store.get(&parsed).map_err(|error| error.to_string())?;
            write_output(args, &image)
        }
        other => Err(format!("usage: unknown store action {other}\n{}", usage())),
    }
}

/// Split `--flag value` pairs from positionals.
///
/// `--decompress` is the only boolean flag, so a following path is never
/// swallowed as its value.
fn split_args(args: &[String]) -> (Vec<String>, BTreeMap<String, String>) {
    let mut positional = Vec::new();
    let mut flags = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(name) = arg.strip_prefix("--") {
            let key = format!("--{name}");
            let boolean = key == "--decompress";
            if !boolean {
                if let Some(value) = args.get(index + 1) {
                    if !value.starts_with("--") {
                        flags.insert(key, value.clone());
                        index += 2;
                        continue;
                    }
                }
            }
            flags.insert(key, String::new());
        } else {
            positional.push(arg.clone());
        }
        index += 1;
    }
    (positional, flags)
}

fn flag_number(
    flags: &BTreeMap<String, String>,
    name: &str,
    default: usize,
) -> Result<usize, String> {
    match flags.get(name) {
        None => Ok(default),
        Some(value) if value.is_empty() => Err(format!("{name} needs a value")),
        Some(value) => value
            .parse()
            .map_err(|_| format!("{name} expects a number")),
    }
}

fn proof_command(args: &[String]) -> Result<(), String> {
    let (positional, flags) = split_args(&args[1..]);
    let usage = "usage: proof issue <image> [--schema PATH] [--output PATH]\n       proof verify <image> <proof> [--schema PATH]";
    let action = positional.first().ok_or_else(|| usage.to_string())?;
    let schema = match flags.get("--schema").filter(|path| !path.is_empty()) {
        Some(path) => Some(read(path)?),
        None => None,
    };
    match action.as_str() {
        "issue" => {
            let image = read(positional.get(1).ok_or_else(|| usage.to_string())?)?;
            let proof = Proof::issue_with_schema(&image, schema.as_deref())
                .map_err(|error| format!("{}: {error}", error.code()))?;
            let json = proof.to_json();
            write_output(args, json.as_bytes())
        }
        "verify" => {
            let image = read(positional.get(1).ok_or_else(|| usage.to_string())?)?;
            let proof_path = positional.get(2).ok_or_else(|| usage.to_string())?;
            let text = fs::read_to_string(proof_path).map_err(|error| error.to_string())?;
            let proof =
                Proof::from_json(&text).map_err(|error| format!("{}: {error}", error.code()))?;
            proof
                .verify_with_schema(&image, schema.as_deref())
                .map_err(|error| format!("{}: {error}", error.code()))?;
            println!(
                "ok hash={} size={} nodes={} secrets={}",
                hex(&proof.content_hash),
                proof.size,
                proof.nodes,
                proof.secrets
            );
            Ok(())
        }
        other => Err(format!("usage: unknown proof action {other}\n{usage}")),
    }
}

fn dict_command(args: &[String]) -> Result<(), String> {
    let (positional, flags) = split_args(&args[1..]);
    let action = positional.first().ok_or_else(|| {
        "usage: dict train --output <path> [--size N] <sample>...\n       dict apply --dictionary <path> [--decompress] [--level N] <input>"
            .to_string()
    })?;
    match action.as_str() {
        "train" => {
            let samples: Vec<Vec<u8>> =
                positional[1..].iter().map(read).collect::<Result<_, _>>()?;
            if samples.len() < 2 {
                return Err("usage: dict train needs at least two sample files".to_string());
            }
            let total: usize = samples.iter().map(Vec::len).sum();
            // zstd's trainer needs headroom between the corpus and the
            // dictionary; derive a workable default instead of failing opaquely.
            let default_size = (total / 8).clamp(256, 110 * 1024);
            let size = flag_number(&flags, "--size", default_size)?;
            if size < 256 {
                return Err("usage: --size must be at least 256 bytes".to_string());
            }
            if size * 4 > total {
                return Err(format!(
                    "usage: --size {size} is too large for {total} bytes of samples; use at most {}",
                    total / 4
                ));
            }
            let dictionary = train_dictionary(&samples, size).map_err(|error| {
                format!(
                    "{}: add more or larger samples ({} bytes across {})",
                    error.code(),
                    total,
                    samples.len()
                )
            })?;
            write_output(args, &dictionary)?;
            eprintln!(
                "trained {} bytes from {} samples",
                dictionary.len(),
                samples.len()
            );
            Ok(())
        }
        "apply" => {
            let dictionary_path = flags
                .get("--dictionary")
                .filter(|value| !value.is_empty())
                .ok_or("usage: dict apply needs --dictionary <path>")?;
            let input = positional
                .get(1)
                .ok_or("usage: dict apply needs an input file")?;
            let dictionary = read(dictionary_path)?;
            let bytes = read(input)?;
            let output = if flags.contains_key("--decompress") {
                let ceiling = flag_number(&flags, "--max-bytes", 64 * 1024 * 1024)?;
                decompress_with_dictionary(&bytes, ceiling, &dictionary)
            } else {
                let level = flag_number(&flags, "--level", 3)? as i32;
                compress_with_dictionary(&bytes, level, &dictionary)
            }
            .map_err(|error| error.code().to_string())?;
            write_output(args, &output)
        }
        other => Err(format!("usage: unknown dict action {other}")),
    }
}

fn bench_command(args: &[String]) -> Result<(), String> {
    let (positional, flags) = split_args(&args[1..]);
    let operation = positional
        .first()
        .ok_or("usage: bench <encode|decode|validate|hash> <file> [--iterations N]")?;
    let path = positional.get(1).ok_or("usage: bench needs a file")?;
    let iterations = flag_number(&flags, "--iterations", 50)?.max(1);
    let bytes = read(path)?;
    let decoded = if operation == "encode" {
        Some(decode(&bytes).map_err(|error| error.code().to_string())?)
    } else {
        None
    };

    // Warm the allocator and the caches before timing.
    for _ in 0..3 {
        bench_once(operation, &bytes, decoded.as_ref())?;
    }
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        bench_once(operation, &bytes, decoded.as_ref())?;
        samples.push(start.elapsed().as_nanos() as u64);
    }
    samples.sort_unstable();
    println!(
        "op={operation} file={path} bytes={} iterations={iterations} p50_ns={} p95_ns={} p99_ns={}",
        bytes.len(),
        percentile(&samples, 50),
        percentile(&samples, 95),
        percentile(&samples, 99)
    );
    Ok(())
}

fn bench_once(
    operation: &str,
    bytes: &[u8],
    decoded: Option<&active_infinity::InfinityModule>,
) -> Result<(), String> {
    match operation {
        "encode" => {
            let module = decoded.ok_or("encode bench needs a decoded module")?;
            let image = encode(module).map_err(|error| error.code().to_string())?;
            std::hint::black_box(image);
        }
        "decode" => {
            let module = decode(bytes).map_err(|error| error.code().to_string())?;
            std::hint::black_box(module);
        }
        "validate" => {
            validate(bytes).map_err(|error| error.code().to_string())?;
        }
        "hash" => {
            let hash = content_hash_hex(bytes).map_err(|error| error.code().to_string())?;
            std::hint::black_box(hash);
        }
        other => return Err(format!("usage: unknown bench op {other}")),
    }
    Ok(())
}

fn percentile(sorted: &[u64], percent: usize) -> u64 {
    let last = sorted.len().saturating_sub(1);
    sorted[(last * percent) / 100]
}

fn conformance(args: &[String]) -> Result<(), String> {
    if args.get(1).map(String::as_str) != Some("run") {
        return Err(format!(
            "usage: conformance run [--manifest path]\n{}",
            usage()
        ));
    }
    let manifest_path =
        arg_value(args, "--manifest").unwrap_or_else(|| "conformance/manifest.json".to_string());
    let manifest = fs::read_to_string(&manifest_path).map_err(|error| error.to_string())?;
    let manifest: serde_json::Value =
        serde_json::from_str(&manifest).map_err(|error| error.to_string())?;
    let base = Path::new(&manifest_path)
        .parent()
        .and_then(|path| path.parent())
        .unwrap_or_else(|| Path::new("."));
    let cases = manifest["cases"]
        .as_array()
        .ok_or_else(|| "manifest has no cases array".to_string())?;
    let mut results = Vec::new();
    let mut passed = 0usize;
    for case in cases {
        let name = case["name"].as_str().unwrap_or("?");
        let kind = case["kind"].as_str().unwrap_or("");
        let relative = case["path"].as_str().unwrap_or("");
        let path = base.join(relative);
        let result = match fs::read(&path) {
            Ok(bytes) => check_case(kind, &bytes, case),
            Err(error) => Err(format!("cannot read {}: {error}", path.display())),
        };
        let ok = result.is_ok();
        if ok {
            passed += 1;
        }
        results.push(json!({
            "name": name,
            "kind": kind,
            "passed": ok,
            "detail": result.err(),
        }));
    }
    let total = results.len();
    let scorecard = json!({
        "format": "active-conformance-scorecard/1",
        "manifest": manifest["version"],
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "cases": results,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&scorecard).unwrap_or_default()
    );
    if passed == total {
        Ok(())
    } else {
        Err(format!("{}/{total} conformance cases passed", passed))
    }
}

fn limits_from(case: &serde_json::Value) -> Limits {
    let mut limits = Limits::default();
    let Some(spec) = case["options"]["limits"].as_str() else {
        return limits;
    };
    for pair in spec.split(',') {
        let Some((key, value)) = pair.split_once(':') else {
            continue;
        };
        let Ok(value) = value.parse::<u64>() else {
            continue;
        };
        match key {
            "max_nodes" => limits.max_nodes = value as u32,
            "max_edges" => limits.max_edges = value as u32,
            "max_children" => limits.max_children = value as u32,
            "max_fields" => limits.max_fields = value as u32,
            "max_parts" => limits.max_parts = value as u32,
            "max_strings" => limits.max_strings = value as u32,
            "max_string_bytes" => limits.max_string_bytes = value as u32,
            "max_blobs" => limits.max_blobs = value as u32,
            "max_blob_bytes" => limits.max_blob_bytes = value as u32,
            "max_annotations" => limits.max_annotations = value as u32,
            "max_units" => limits.max_units = value as u32,
            "max_types" => limits.max_types = value as u32,
            "max_aux" => limits.max_aux = value as u32,
            "max_numbers" => limits.max_numbers = value as u32,
            "max_secrets" => limits.max_secrets = value as u32,
            "max_secret_bytes" => limits.max_secret_bytes = value as u32,
            "max_extensions" => limits.max_extensions = value as u32,
            "max_prov_entries" => limits.max_prov_entries = value as u32,
            "max_total_bytes" => limits.max_total_bytes = value,
            "max_depth" => limits.max_depth = value as u32,
            _ => {}
        }
    }
    limits
}

fn check_case(kind: &str, bytes: &[u8], case: &serde_json::Value) -> Result<(), String> {
    match kind {
        "valid" => {
            validate(bytes).map_err(|error| error.code().to_string())?;
            let actual = content_hash_hex(bytes).map_err(|error| error.code().to_string())?;
            let expected = case["content_hash"].as_str().unwrap_or("");
            if actual != expected {
                return Err(format!("hash {actual} != {expected}"));
            }
            let canonical = case["options"]["canonical"].as_str() != Some("no");
            let decoded = decode(bytes).map_err(|error| error.code().to_string())?;
            if canonical && encode(&decoded).map_err(|error| error.code().to_string())? != bytes {
                return Err("re-encode differs".to_string());
            }
            Ok(())
        }
        "invalid" => {
            let limits = limits_from(case);
            let error = validate_canonical(bytes, limits)
                .err()
                .ok_or_else(|| "accepted invalid".to_string())?;
            let expected = case["expected_code"].as_str().unwrap_or("");
            if error.code() != expected {
                return Err(format!("{} != {expected}", error.code()));
            }
            Ok(())
        }
        "invalid_stream" => {
            let mut decoder = StreamDecoder::new();
            let error = match decoder.push_bytes(bytes) {
                Ok(()) => decoder
                    .finish()
                    .err()
                    .ok_or_else(|| "accepted invalid stream".to_string())?,
                Err(error) => error,
            };
            let expected = case["expected_code"].as_str().unwrap_or("");
            if error.code() != expected {
                return Err(format!("{} != {expected}", error.code()));
            }
            Ok(())
        }
        other => Err(format!("unknown case kind {other}")),
    }
}

fn read(path: impl AsRef<Path>) -> Result<Vec<u8>, String> {
    let mut file = fs::File::open(path.as_ref()).map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn write_output(args: &[String], bytes: &[u8]) -> Result<(), String> {
    if let Some(path) = arg_value(args, "--output") {
        fs::write(path, bytes).map_err(|error| error.to_string())
    } else {
        io::stdout()
            .write_all(bytes)
            .map_err(|error| error.to_string())
    }
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn parse_hash(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 {
        return Err("hash must be 64 hex characters".to_string());
    }
    let mut hash = [0u8; 32];
    for (index, chunk) in text.as_bytes().chunks(2).enumerate() {
        let value = std::str::from_utf8(chunk).map_err(|error| error.to_string())?;
        hash[index] = u8::from_str_radix(value, 16).map_err(|error| error.to_string())?;
    }
    Ok(hash)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn usage() -> String {
    "usage: active-infinity-cli <encode|decode|validate|hash|stream|store|dict|bench|conformance|doctor|help> ...\n       run `active-infinity-cli help` for examples"
        .to_string()
}

fn help_text() -> String {
    format!(
        "active-infinity-cli {} (active-infinity {VERSION})

usage: active-infinity-cli <command> [options]

  encode <source.active> [--name NAME] [--output PATH]
      Compile Active text to canonical AINF bytes.
  decode <image.ainf>
      Validate, then print the redacted JSON projection (never secrets).
  validate <image.ainf>
      Fail-closed validation; prints node and byte counts.
  hash <image.ainf>
      Print the Blake3 content hash over canonical bytes.
  stream <image.ainf>
      Reassemble an AINS stream and print its hash.
  store put <image.ainf> [--root DIR]
  store get <hash> [--root DIR] [--output PATH]
      Content-addressed local store (default root .active-store).
  dict train --output <dict> [--size N] <sample>...
  dict apply --dictionary <dict> [--decompress] [--level N] [--max-bytes N] <input>
      Train or apply a zstd dictionary. Hashes stay over uncompressed bytes.
  proof issue <image> [--schema PATH] [--output PATH]
      Write a JSON sidecar: content hash, size, counts, secrets, dialect and an
      optional companion-schema hash.
  proof verify <image> <proof> [--schema PATH]
      Recompute the properties and refuse any mismatch (infinity/proof).
  bench <encode|decode|validate|hash> <file> [--iterations N]
      Local microbench: prints p50/p95/p99 in nanoseconds.
  conformance run [--manifest PATH]
      Run the vector pack; prints a JSON scorecard.
  doctor
      Version, features and exit-code summary.
  help
      This text.

Exit codes: 0 success, 1 failure, 2 usage.

Examples:
  active-infinity-cli encode app.active --name app.active --output app.ainf
  active-infinity-cli hash app.ainf
  active-infinity-cli decode app.ainf
  active-infinity-cli conformance run --manifest conformance/manifest.json
  active-infinity-cli dict train --output frames.dict tests/vectors/valid/*.ainf
  active-infinity-cli bench validate app.ainf --iterations 100

Compression is transport and storage only; the content hash is always computed
over the uncompressed canonical image.",
        env!("CARGO_PKG_VERSION")
    )
}
