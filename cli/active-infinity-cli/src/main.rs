//! Production CLI for Active Infinity.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use active_infinity::compress::{
    compress_with_dictionary, decompress_with_dictionary, level_range, train_dictionary,
};
use active_infinity::stream::StreamDecoder;
use active_infinity::{
    content_hash_hex, decode_with, encode, interop::from_active_source, validate_canonical,
    validate_with, DecodeOpts, Limits, Proof, SignedImage, Store, VERSION,
};
use serde_json::json;
use zeroize::Zeroize;

/// Largest Active source the CLI compiles, in bytes.
const MAX_SOURCE_BYTES: u64 = 16 << 20;
/// Largest conformance manifest, in bytes.
const MAX_MANIFEST_BYTES: u64 = 1 << 20;
/// Largest signing-seed file, in bytes.
const MAX_SEED_BYTES: u64 = 4 << 10;
/// Largest `bench --iterations` value.
const MAX_BENCH_ITERATIONS: usize = 1_000_000;

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
            let (positional, flags) = split_args(&args[1..])?;
            check_flags(&flags, &[], "usage: validate <image.ainf>")?;
            check_positional(&positional, 1, "usage: validate <image.ainf>")?;
            let bytes = read(&positional[0])?;
            let meta = validate_with(&bytes, DecodeOpts::default())
                .map_err(|error| format!("{}: {}", error.code(), error))?;
            println!("ok nodes={} bytes={}", meta.nodes, bytes.len());
            Ok(())
        }
        "hash" => {
            let (positional, flags) = split_args(&args[1..])?;
            check_flags(&flags, &[], "usage: hash <image.ainf>")?;
            check_positional(&positional, 1, "usage: hash <image.ainf>")?;
            let bytes = read(&positional[0])?;
            println!(
                "{}",
                content_hash_hex(&bytes).map_err(|error| format!("{}: {}", error.code(), error))?
            );
            Ok(())
        }
        "decode" => {
            let (positional, flags) = split_args(&args[1..])?;
            check_flags(&flags, &[], "usage: decode <image.ainf>")?;
            check_positional(&positional, 1, "usage: decode <image.ainf>")?;
            let bytes = read(&positional[0])?;
            validate_with(&bytes, DecodeOpts::default())
                .map_err(|error| format!("{}: {}", error.code(), error))?;
            let module = decode_with(&bytes, DecodeOpts::default())
                .map_err(|error| format!("{}: {}", error.code(), error))?;
            let projection = active_infinity::interop::to_redacted_json(&module)
                .map_err(|error| format!("{}: {}", error.code(), error))?;
            println!("{projection}");
            Ok(())
        }
        "encode" => {
            let usage = "usage: encode <source.active> [--name NAME] [--output PATH]";
            let (positional, flags) = split_args(&args[1..])?;
            check_flags(&flags, &["--name", "--output"], usage)?;
            check_positional(&positional, 1, usage)?;
            let name = flags
                .get("--name")
                .filter(|value| !value.is_empty())
                .cloned()
                .unwrap_or_else(|| "module.active".to_string());
            let source = read_text(&positional[0], MAX_SOURCE_BYTES)?;
            let module = from_active_source(&source, &name)
                .map_err(|error| format!("{}: {}", error.code(), error))?;
            let image = encode(&module).map_err(|error| format!("{}: {}", error.code(), error))?;
            ensure_distinct(&positional[0], flags.get("--output").map(String::as_str))?;
            write_output(flags.get("--output").map(String::as_str), &image)?;
            if let Some(output) = flags.get("--output") {
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
            check_positional(&args[1..], 0, "usage: help")?;
            println!("{}", help_text());
            Ok(())
        }
        "version" | "--version" | "-V" => {
            check_positional(&args[1..], 0, "usage: version")?;
            println!(
                "active-infinity-cli {} (active-infinity {})",
                env!("CARGO_PKG_VERSION"),
                active_infinity::VERSION
            );
            Ok(())
        }
        "doctor" => {
            check_positional(&args[1..], 0, "usage: doctor")?;
            println!(
                "active-infinity-cli {} (active-infinity {})",
                env!("CARGO_PKG_VERSION"),
                VERSION
            );
            println!("features: json active-core zstd signatures");
            println!("exit codes: 0 success, 1 failure, 2 usage");
            Ok(())
        }
        other => Err(format!("usage: unknown command {other}\n{}", usage())),
    }
}

fn stream_command(args: &[String]) -> Result<(), String> {
    let usage = "usage: stream <stream.ains>";
    let (positional, flags) = split_args(&args[1..])?;
    check_flags(&flags, &[], usage)?;
    check_positional(&positional, 1, usage)?;
    let bytes = read(&positional[0])?;
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
        content_hash_hex(&streamed.image).map_err(|error| format!(
            "{}: {}",
            error.code(),
            error
        ))?
    );
    Ok(())
}

fn store_command(args: &[String]) -> Result<(), String> {
    let usage = "usage: store put <image> [--root DIR] [--sign SEED_HEX | --sign-file PATH]\n       store get <hash> [--root DIR] [--output PATH] [--verify] [--key PUBLIC_HEX]\n       store signature <hash> [--root DIR]";
    let (positional, flags) = split_args(&args[1..])?;
    let action = positional.first().ok_or_else(|| usage.to_string())?;
    let root = flags
        .get("--root")
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| ".active-store".to_string());
    let store = Store::open(root).map_err(|error| format!("{}: {}", error.code(), error))?;
    match action.as_str() {
        "put" => {
            check_flags(&flags, &["--root", "--sign", "--sign-file"], usage)?;
            check_positional(&positional, 2, usage)?;
            if flags.contains_key("--sign") && flags.contains_key("--sign-file") {
                return Err("usage: --sign and --sign-file are mutually exclusive".to_string());
            }
            let image = read(&positional[1])?;
            let hash = match signing_seed(&flags)? {
                Some(mut seed) => {
                    let signed = SignedImage::sign_with_seed(image, &seed);
                    seed.zeroize();
                    let signed = signed.map_err(|error| format!("{}: {error}", error.code()))?;
                    store
                        .put_signed(&signed)
                        .map_err(|error| format!("{}: {error}", error.code()))?
                }
                None => store
                    .put(&image)
                    .map_err(|error| format!("{}: {error}", error.code()))?,
            };
            println!("{}", hex(&hash));
            Ok(())
        }
        "get" => {
            check_flags(&flags, &["--root", "--output", "--verify", "--key"], usage)?;
            check_positional(&positional, 2, usage)?;
            let hash = parse_hash(&positional[1])?;
            let trusted = flags.get("--key").filter(|key| !key.is_empty());
            let verifying = flags.contains_key("--verify");
            if trusted.is_some() && !verifying {
                return Err("usage: --key needs --verify".to_string());
            }
            let image = if verifying {
                match trusted {
                    Some(public) => store
                        .get_verified_with_key(&hash, &parse_public_key(public)?)
                        .map_err(|error| format!("{}: {error}", error.code()))?,
                    None => store
                        .get_verified(&hash, None)
                        .map_err(|error| format!("{}: {error}", error.code()))?,
                }
            } else {
                if store.get_signature(&hash).ok().flatten().is_some() {
                    eprintln!("note: this object has a signature; pass --verify to require it");
                }
                store
                    .get(&hash)
                    .map_err(|error| format!("{}: {error}", error.code()))?
            };
            write_output(flags.get("--output").map(String::as_str), &image)
        }
        "signature" => {
            check_flags(&flags, &["--root"], usage)?;
            check_positional(&positional, 2, usage)?;
            let hash = parse_hash(&positional[1])?;
            let signed = store
                .get_signature(&hash)
                .map_err(|error| format!("{}: {error}", error.code()))?
                .ok_or_else(|| {
                    format!("infinity/signature: no signature stored for {}", hex(&hash))
                })?;
            let content = signed
                .content_hash()
                .map_err(|error| format!("{}: {error}", error.code()))?;
            println!("key {}", hex(&signed.public_key));
            println!("hash {}", hex(&content));
            Ok(())
        }
        other => Err(format!("usage: unknown store action {other}\n{usage}")),
    }
}

/// Split `--flag value` pairs from positionals.
///
/// `--decompress` and `--verify` are booleans; every other flag takes a value,
/// and a flag at the end (or followed by another flag) is a usage error instead
/// of a silently empty value. A repeated flag is refused so a caller cannot
/// smuggle a second value past a check.
fn split_args(args: &[String]) -> Result<(Vec<String>, BTreeMap<String, String>), String> {
    let mut positional = Vec::new();
    let mut flags = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(name) = arg.strip_prefix("--") {
            let key = format!("--{name}");
            if flags.contains_key(&key) {
                return Err(format!("usage: duplicate flag {key}"));
            }
            let boolean = key == "--decompress" || key == "--verify";
            if !boolean {
                match args.get(index + 1) {
                    Some(value) if !value.starts_with("--") => {
                        flags.insert(key, value.clone());
                        index += 2;
                        continue;
                    }
                    _ => return Err(format!("usage: {key} needs a value")),
                }
            }
            flags.insert(key, String::new());
        } else {
            positional.push(arg.clone());
        }
        index += 1;
    }
    Ok((positional, flags))
}

fn check_flags(
    flags: &BTreeMap<String, String>,
    allowed: &[&str],
    usage: &str,
) -> Result<(), String> {
    for key in flags.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("usage: unknown flag {key}\n{usage}"));
        }
    }
    Ok(())
}

fn check_positional(positional: &[String], expected: usize, usage: &str) -> Result<(), String> {
    if positional.len() != expected {
        return Err(format!(
            "usage: expected {expected} argument(s), found {}\n{usage}",
            positional.len()
        ));
    }
    Ok(())
}

fn flag_number(
    flags: &BTreeMap<String, String>,
    name: &str,
    default: usize,
) -> Result<usize, String> {
    match flags.get(name) {
        None => Ok(default),
        Some(value) if value.is_empty() => Err(format!("usage: {name} needs a value")),
        Some(value) => value
            .parse()
            .map_err(|_| format!("usage: {name} expects a number")),
    }
}

fn proof_command(args: &[String]) -> Result<(), String> {
    let (positional, flags) = split_args(&args[1..])?;
    let usage = "usage: proof issue <image> [--schema PATH] [--output PATH]\n       proof verify <image> <proof> [--schema PATH]";
    let action = positional.first().ok_or_else(|| usage.to_string())?;
    let schema = match flags.get("--schema").filter(|path| !path.is_empty()) {
        Some(path) => Some(read(path)?),
        None => None,
    };
    match action.as_str() {
        "issue" => {
            check_flags(&flags, &["--schema", "--output"], usage)?;
            check_positional(&positional, 2, usage)?;
            let image = read(&positional[1])?;
            let proof = Proof::issue_with_schema(&image, schema.as_deref())
                .map_err(|error| format!("{}: {error}", error.code()))?;
            let json = proof.to_json();
            ensure_distinct(&positional[1], flags.get("--output").map(String::as_str))?;
            write_output(flags.get("--output").map(String::as_str), json.as_bytes())
        }
        "verify" => {
            check_flags(&flags, &["--schema"], usage)?;
            check_positional(&positional, 3, usage)?;
            let image = read(&positional[1])?;
            let text = read_text(
                &positional[2],
                active_infinity::proof::MAX_SIDECAR_BYTES as u64,
            )?;
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
    let (positional, flags) = split_args(&args[1..])?;
    let usage = "usage: dict train --output <path> [--size N] <sample>...\n       dict apply --dictionary <path> [--decompress] [--level N] [--max-bytes N] [--output PATH] <input>";
    let action = positional.first().ok_or_else(|| usage.to_string())?;
    match action.as_str() {
        "train" => {
            check_flags(&flags, &["--output", "--size"], usage)?;
            if positional.len() < 3 {
                return Err("usage: dict train needs at least two sample files".to_string());
            }
            let samples: Vec<Vec<u8>> =
                positional[1..].iter().map(read).collect::<Result<_, _>>()?;
            let total = samples
                .iter()
                .fold(0usize, |sum, sample| sum.saturating_add(sample.len()));
            let default_size = (total / 8).clamp(256, 110 * 1024);
            let size = flag_number(&flags, "--size", default_size)?;
            if size < 256 {
                return Err("usage: --size must be at least 256 bytes".to_string());
            }
            let bound = size.checked_mul(4).ok_or_else(|| {
                format!("usage: --size {size} is too large for {total} bytes of samples")
            })?;
            if bound > total {
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
            for sample in &positional[1..] {
                ensure_distinct(sample, flags.get("--output").map(String::as_str))?;
            }
            write_output(flags.get("--output").map(String::as_str), &dictionary)?;
            eprintln!(
                "trained {} bytes from {} samples",
                dictionary.len(),
                samples.len()
            );
            Ok(())
        }
        "apply" => {
            check_flags(
                &flags,
                &[
                    "--dictionary",
                    "--decompress",
                    "--level",
                    "--max-bytes",
                    "--output",
                ],
                usage,
            )?;
            check_positional(&positional, 2, usage)?;
            let dictionary_path = flags
                .get("--dictionary")
                .filter(|value| !value.is_empty())
                .ok_or("usage: dict apply needs --dictionary <path>")?;
            let dictionary = read(dictionary_path)?;
            let bytes = read(&positional[1])?;
            let output = if flags.contains_key("--decompress") {
                let ceiling = flag_number(&flags, "--max-bytes", 64 * 1024 * 1024)?;
                let codec_ceiling = Limits::default().max_total_bytes;
                if ceiling == 0 || ceiling as u64 > codec_ceiling {
                    return Err(format!(
                        "usage: --max-bytes must be between 1 and the {codec_ceiling} byte codec ceiling"
                    ));
                }
                decompress_with_dictionary(&bytes, ceiling, &dictionary)
            } else {
                let level = flag_number(&flags, "--level", 3)?;
                let level = i32::try_from(level)
                    .map_err(|_| "usage: --level is outside the supported range".to_string())?;
                let (minimum, maximum) = level_range();
                if !(minimum..=maximum).contains(&level) {
                    return Err(format!(
                        "usage: --level must be between {minimum} and {maximum}"
                    ));
                }
                compress_with_dictionary(&bytes, level, &dictionary)
            }
            .map_err(|error| format!("{}: {error}", error.code()))?;
            ensure_distinct(&positional[1], flags.get("--output").map(String::as_str))?;
            write_output(flags.get("--output").map(String::as_str), &output)
        }
        other => Err(format!("usage: unknown dict action {other}\n{usage}")),
    }
}

fn bench_command(args: &[String]) -> Result<(), String> {
    let usage = "usage: bench <encode|decode|validate|hash> <file> [--iterations N]";
    let (positional, flags) = split_args(&args[1..])?;
    check_flags(&flags, &["--iterations"], usage)?;
    check_positional(&positional, 2, usage)?;
    let operation = positional[0].as_str();
    let path = &positional[1];
    let iterations = flag_number(&flags, "--iterations", 50)?;
    if !(1..=MAX_BENCH_ITERATIONS).contains(&iterations) {
        return Err(format!(
            "usage: --iterations must be between 1 and {MAX_BENCH_ITERATIONS}"
        ));
    }
    let bytes = read(path)?;
    let decoded = if operation == "encode" {
        Some(
            decode_with(&bytes, DecodeOpts::default())
                .map_err(|error| format!("{}: {error}", error.code()))?,
        )
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
            let image = encode(module).map_err(|error| format!("{}: {error}", error.code()))?;
            std::hint::black_box(image);
        }
        "decode" => {
            let module = decode_with(bytes, DecodeOpts::default())
                .map_err(|error| format!("{}: {error}", error.code()))?;
            std::hint::black_box(module);
        }
        "validate" => {
            validate_with(bytes, DecodeOpts::default())
                .map_err(|error| format!("{}: {error}", error.code()))?;
        }
        "hash" => {
            let hash =
                content_hash_hex(bytes).map_err(|error| format!("{}: {error}", error.code()))?;
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
    let usage = "usage: conformance run [--manifest path]";
    if args.get(1).map(String::as_str) != Some("run") {
        return Err(format!("{usage}\n{}", usage_line()));
    }
    let (positional, flags) = split_args(&args[1..])?;
    check_flags(&flags, &["--manifest"], usage)?;
    check_positional(&positional, 1, usage)?;
    let manifest_path = flags
        .get("--manifest")
        .cloned()
        .unwrap_or_else(|| "conformance/manifest.json".to_string());
    let manifest = read_text(&manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest)
        .map_err(|error| format!("manifest is not JSON: {error}"))?;
    // The manifest's own directory is the base for its relative case paths.
    let base = Path::new(&manifest_path)
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
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
        let relative = Path::new(relative);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            results.push(json!({
                "name": name,
                "kind": kind,
                "passed": false,
                "detail": "case path escapes the manifest directory",
            }));
            continue;
        }
        let path = base.join(relative);
        let result = match read(&path) {
            Ok(bytes) => check_case(kind, &bytes, case),
            Err(error) => Err(error),
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

fn limits_from(case: &serde_json::Value) -> Result<Limits, String> {
    let mut limits = Limits::default();
    let Some(spec) = case["options"]["limits"].as_str() else {
        return Ok(limits);
    };
    for pair in spec.split(',') {
        let (key, value) = pair
            .split_once(':')
            .ok_or_else(|| format!("usage: malformed limit {pair}"))?;
        let value: u64 = value
            .parse()
            .map_err(|_| format!("usage: limit {key} is not a number"))?;
        let narrow =
            || u32::try_from(value).map_err(|_| format!("usage: limit {key} is above u32::MAX"));
        match key {
            "max_nodes" => limits.max_nodes = narrow()?,
            "max_edges" => limits.max_edges = narrow()?,
            "max_children" => limits.max_children = narrow()?,
            "max_fields" => limits.max_fields = narrow()?,
            "max_parts" => limits.max_parts = narrow()?,
            "max_strings" => limits.max_strings = narrow()?,
            "max_string_bytes" => limits.max_string_bytes = narrow()?,
            "max_blobs" => limits.max_blobs = narrow()?,
            "max_blob_bytes" => limits.max_blob_bytes = narrow()?,
            "max_annotations" => limits.max_annotations = narrow()?,
            "max_units" => limits.max_units = narrow()?,
            "max_types" => limits.max_types = narrow()?,
            "max_aux" => limits.max_aux = narrow()?,
            "max_numbers" => limits.max_numbers = narrow()?,
            "max_secrets" => limits.max_secrets = narrow()?,
            "max_secret_bytes" => limits.max_secret_bytes = narrow()?,
            "max_extensions" => limits.max_extensions = narrow()?,
            "max_prov_entries" => limits.max_prov_entries = narrow()?,
            "max_total_bytes" => limits.max_total_bytes = value,
            "max_depth" => limits.max_depth = narrow()?,
            other => return Err(format!("usage: unknown limit {other}")),
        }
    }
    Ok(limits)
}

fn check_case(kind: &str, bytes: &[u8], case: &serde_json::Value) -> Result<(), String> {
    let limits = limits_from(case)?;
    match kind {
        "valid" => {
            validate_with(
                bytes,
                DecodeOpts {
                    limits,
                    ..DecodeOpts::default()
                },
            )
            .map_err(|error| format!("{}: {error}", error.code()))?;
            let actual =
                content_hash_hex(bytes).map_err(|error| format!("{}: {error}", error.code()))?;
            let expected = case["content_hash"].as_str().unwrap_or("");
            if actual != expected {
                return Err(format!("hash {actual} != {expected}"));
            }
            let canonical = case["options"]["canonical"].as_str() != Some("no");
            let decoded = decode_with(
                bytes,
                DecodeOpts {
                    limits,
                    ..DecodeOpts::default()
                },
            )
            .map_err(|error| format!("{}: {error}", error.code()))?;
            if canonical
                && encode(&decoded).map_err(|error| format!("{}: {error}", error.code()))? != bytes
            {
                return Err("re-encode differs".to_string());
            }
            Ok(())
        }
        "invalid" => {
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

/// Largest file the CLI reads: the codec's image ceiling plus envelope slack.
///
/// A larger file cannot be a valid input for this tool, and reading it first
/// would let a hostile path force an allocation before any check runs.
fn input_ceiling() -> u64 {
    Limits::default().max_total_bytes.saturating_add(4096)
}

fn read(path: impl AsRef<Path>) -> Result<Vec<u8>, String> {
    read_capped(path.as_ref(), input_ceiling())
}

fn read_text(path: &str, limit: u64) -> Result<String, String> {
    let bytes = read_capped(Path::new(path), limit)?;
    String::from_utf8(bytes).map_err(|_| format!("{path}: not UTF-8"))
}

fn read_capped(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let file = fs::File::open(path).map_err(|error| error.to_string())?;
    let meta = file.metadata().map_err(|error| error.to_string())?;
    if !meta.is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    if meta.len() > limit {
        return Err(format!(
            "{}: file is larger than the {limit} byte input ceiling",
            path.display()
        ));
    }
    // A sparse file can be large without holding data; do not reserve the whole
    // declared size up front. The read itself is bounded below.
    let reserve = usize::try_from(meta.len())
        .unwrap_or(usize::MAX)
        .min(1 << 20);
    let mut bytes = Vec::with_capacity(reserve);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > limit {
        return Err(format!(
            "{}: file grew past the {limit} byte input ceiling",
            path.display()
        ));
    }
    Ok(bytes)
}

fn write_output(output: Option<&str>, bytes: &[u8]) -> Result<(), String> {
    let Some(path) = output else {
        return io::stdout()
            .write_all(bytes)
            .map_err(|error| error.to_string());
    };
    let path = Path::new(path);
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("usage: --output needs a file name")?;
    static SLOT: AtomicU64 = AtomicU64::new(0);
    let mut temp = PathBuf::new();
    let mut file = None;
    for _ in 0..64 {
        let slot = SLOT.fetch_add(1, Ordering::Relaxed);
        temp = directory.join(format!(".{name}.tmp.{}.{slot}", std::process::id()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temp) {
            Ok(opened) => {
                file = Some(opened);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.to_string()),
        }
    }
    let Some(mut file) = file else {
        return Err("cannot create a temporary output file".to_string());
    };
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = fs::remove_file(&temp);
        return Err(error.to_string());
    }
    // `rename` replaces the destination entry (it does not write through a
    // symbolic link), so a crash leaves the old file intact.
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error.to_string());
    }
    Ok(())
}

/// Refuse an output path that names an input: a truncating write would destroy
/// the source before the command finished reading it.
fn ensure_distinct(input: &str, output: Option<&str>) -> Result<(), String> {
    let Some(output) = output else {
        return Ok(());
    };
    let same = match (fs::canonicalize(input), fs::canonicalize(output)) {
        (Ok(a), Ok(b)) => a == b,
        _ => input == output,
    };
    if same {
        return Err("usage: --output must differ from the input file".to_string());
    }
    Ok(())
}

fn signing_seed(flags: &BTreeMap<String, String>) -> Result<Option<[u8; 32]>, String> {
    if let Some(path) = flags.get("--sign-file") {
        let text = read_text(path, MAX_SEED_BYTES)?;
        return parse_seed(text.trim()).map(Some);
    }
    if let Some(seed) = flags.get("--sign") {
        return parse_seed(seed).map(Some);
    }
    match std::env::var("ACTIVE_INFINITY_SIGN_SEED") {
        Ok(seed) if !seed.is_empty() => parse_seed(&seed).map(Some),
        _ => Ok(None),
    }
}

fn parse_seed(text: &str) -> Result<[u8; 32], String> {
    parse_hash(text).map_err(|_| "usage: signing seed must be 64 hex characters".to_string())
}

fn parse_public_key(text: &str) -> Result<[u8; 32], String> {
    parse_hash(text).map_err(|_| "usage: public key must be 64 hex characters".to_string())
}

fn parse_hash(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 {
        return Err("usage: hash must be 64 hex characters".to_string());
    }
    let mut hash = [0u8; 32];
    for (index, chunk) in text.as_bytes().chunks(2).enumerate() {
        let value = std::str::from_utf8(chunk)
            .map_err(|_| "usage: hash must be hexadecimal".to_string())?;
        hash[index] = u8::from_str_radix(value, 16)
            .map_err(|_| "usage: hash must be hexadecimal".to_string())?;
    }
    Ok(hash)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn usage_line() -> &'static str {
    "usage: active-infinity-cli <encode|decode|validate|hash|stream|store|dict|proof|bench|conformance|doctor|version|help> ..."
}

fn usage() -> String {
    format!(
        "{}\n       run `active-infinity-cli help` for examples",
        usage_line()
    )
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
  stream <stream.ains>
      Reassemble an AINS stream and print its hash.
  store put <image.ainf> [--root DIR] [--sign SEED_HEX | --sign-file PATH]
  store get <hash> [--root DIR] [--output PATH] [--verify] [--key PUBLIC_HEX]
  store signature <hash> [--root DIR]
      Content-addressed local store (default root .active-store). --sign keeps a
      detached Ed25519 envelope next to the object; prefer --sign-file or
      ACTIVE_INFINITY_SIGN_SEED because a seed on argv is visible to other
      processes. --verify requires an envelope and --key pins the signer.
      `signature` prints the stored key and hash.
  dict train --output <dict> [--size N] <sample>...
  dict apply --dictionary <dict> [--decompress] [--level N] [--max-bytes N] [--output PATH] <input>
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

Every command rejects unknown flags and extra arguments. Exit codes: 0 success,
1 failure, 2 usage.

Examples:
  active-infinity-cli encode app.active --name app.active --output app.ainf
  active-infinity-cli hash app.ainf
  active-infinity-cli decode app.ainf
  active-infinity-cli store get <hash> --verify --key <public-key-hex>
  active-infinity-cli conformance run --manifest conformance/manifest.json
  active-infinity-cli dict train --output frames.dict tests/vectors/valid/*.ainf
  active-infinity-cli bench validate app.ainf --iterations 100

Compression is transport and storage only; the content hash is always computed
over the uncompressed canonical image.",
        env!("CARGO_PKG_VERSION")
    )
}
