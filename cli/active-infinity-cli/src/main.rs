//! Production CLI for Active Infinity.

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use active_infinity::stream::StreamDecoder;
use active_infinity::{
    content_hash_hex, decode, encode, interop::from_active_source, validate, validate_canonical,
    Limits, Store, VERSION,
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
            let path = args.get(1).ok_or_else(|| usage())?;
            let bytes = read(path)?;
            let meta = validate(&bytes).map_err(|error| format!("{}: {}", error.code(), error))?;
            println!("ok nodes={} bytes={}", meta.nodes, bytes.len());
            Ok(())
        }
        "hash" => {
            let path = args.get(1).ok_or_else(|| usage())?;
            let bytes = read(path)?;
            println!(
                "{}",
                content_hash_hex(&bytes).map_err(|error| error.code().to_string())?
            );
            Ok(())
        }
        "decode" => {
            let path = args.get(1).ok_or_else(|| usage())?;
            let bytes = read(path)?;
            validate(&bytes).map_err(|error| format!("{}: {}", error.code(), error))?;
            let module = decode(&bytes).map_err(|error| error.code().to_string())?;
            let json = active_infinity::interop::to_redacted_json(&module)
                .map_err(|error| error.code().to_string())?;
            println!("{json}");
            Ok(())
        }
        "encode" => {
            let path = args.get(1).ok_or_else(|| usage())?;
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
        "conformance" => conformance(&args),
        "doctor" => {
            println!(
                "active-infinity-cli {} (active-infinity {})",
                env!("CARGO_PKG_VERSION"),
                VERSION
            );
            println!("features: json active-core");
            println!("exit codes: 0 success, 1 failure, 2 usage");
            Ok(())
        }
        other => Err(format!("usage: unknown command {other}\n{}", usage())),
    }
}

fn stream_command(args: &[String]) -> Result<(), String> {
    let path = args.get(2).ok_or_else(|| usage())?;
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
    let action = args.get(1).ok_or_else(|| usage())?;
    let root = arg_value(args, "--root").unwrap_or_else(|| ".active-store".to_string());
    let store = Store::open(root).map_err(|error| error.to_string())?;
    match action.as_str() {
        "put" => {
            let path = args.get(2).ok_or_else(|| usage())?;
            let image = read(path)?;
            let hash = store.put(&image).map_err(|error| error.to_string())?;
            println!("{}", hex(&hash));
            Ok(())
        }
        "get" => {
            let hash = args.get(2).ok_or_else(|| usage())?;
            let parsed = parse_hash(hash)?;
            let image = store.get(&parsed).map_err(|error| error.to_string())?;
            write_output(args, &image)
        }
        other => Err(format!("usage: unknown store action {other}\n{}", usage())),
    }
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
    "usage: active-infinity-cli <validate|hash|decode|encode|stream|store|conformance|doctor> ..."
        .to_string()
}
