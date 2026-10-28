//! Table-driven red-team battery.
//!
//! Every case names the checklist item it implements and the invariant it
//! defends. The harness catches a panic per case, runs the whole table, and
//! reports every failure instead of stopping at the first one.
//!
//! Cases use the shipped public API and the committed conformance vectors. A
//! case passes only when the attack is refused with the documented code, or
//! when the invariant demonstrably holds.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::time::Instant;

use active_infinity::interop::SECRET_MARKER;
use active_infinity::{
    decode, encode, hash_image, validate, validate_with, AnnotationKind, DecodeOpts,
    InfinityModule, Inode, Limits, ProvEntry, ProvValue, Provenance, SecretBytes,
};

struct Case {
    id: &'static str,
    invariant: &'static str,
    threat: &'static str,
    check: fn() -> Result<(), String>,
}

const CASES: &[Case] = &[
    Case {
        id: "H2.1",
        invariant: "I-10",
        threat: "count field at u32::MAX on a tiny buffer",
        check: h2_01_count_bomb,
    },
    Case {
        id: "H2.2",
        invariant: "I-10",
        threat: "section offset overlaps the header",
        check: h2_02_overlap,
    },
    Case {
        id: "H2.3",
        invariant: "I-8",
        threat: "deep nesting against the depth ceiling",
        check: h2_03_depth,
    },
    Case {
        id: "H2.4",
        invariant: "I-8",
        threat: "billion-laughs expansion through shared references",
        check: h2_04_expansion,
    },
    Case {
        id: "H2.5",
        invariant: "I-8",
        threat: "sparse claim: a count the bytes cannot satisfy",
        check: h2_05_sparse,
    },
    Case {
        id: "H2.6",
        invariant: "I-10",
        threat: "invalid UTF-8 in the string heap",
        check: h2_06_utf8,
    },
    Case {
        id: "H2.7",
        invariant: "I-10",
        threat: "truncated stream frame",
        check: h2_07_stream,
    },
    Case {
        id: "H2.14",
        invariant: "I-3",
        threat: "secret copy in every metadata position",
        check: h2_14_secret_metadata,
    },
    Case {
        id: "H2.15",
        invariant: "I-3",
        threat: "force a secret literal into an error message",
        check: h2_15_error_echo,
    },
    Case {
        id: "H2.16",
        invariant: "I-2",
        threat: "equality or ordering oracle on secret bytes",
        check: h2_16_oracle,
    },
    Case {
        id: "H2.17",
        invariant: "I-3",
        threat: "smuggle a secret through an extension payload",
        check: h2_17_extension,
    },
    Case {
        id: "H2.24",
        invariant: "I-9",
        threat: "single-bit mutation changes nothing",
        check: h2_24_bit_flip,
    },
    Case {
        id: "H2.27",
        invariant: "I-9",
        threat: "projections disagree on redaction or hash",
        check: h2_27_projection,
    },
    Case {
        id: "H2.33",
        invariant: "I-11",
        threat: "security check compiled out in release",
        check: h2_33_cfg_audit,
    },
    Case {
        id: "H2.34",
        invariant: "I-10",
        threat: "the committed fuzz corpus as hostile input",
        check: h2_34_corpus,
    },
    Case {
        id: "H2.36",
        invariant: "I-8",
        threat: "rejection work proportional to a declared count",
        check: h2_36_allocation,
    },
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn vector(directory: &str, name: &str) -> Vec<u8> {
    std::fs::read(
        root()
            .join("tests")
            .join("vectors")
            .join(directory)
            .join(name),
    )
    .unwrap_or_else(|error| panic!("missing vector {directory}/{name}: {error}"))
}

fn expect_code<T>(result: active_infinity::Result<T>, code: &str) -> Result<(), String> {
    match result {
        Err(error) if error.code() == code => Ok(()),
        Err(error) => Err(format!("expected {code}, got {}", error.code())),
        Ok(_) => Err(format!("expected {code}, got Ok")),
    }
}

fn h2_01_count_bomb() -> Result<(), String> {
    expect_code(
        validate(&vector("invalid", "count_bomb.ainf")),
        "infinity/count",
    )
}

fn h2_02_overlap() -> Result<(), String> {
    expect_code(
        validate(&vector("invalid", "bad_offset.ainf")),
        "infinity/offset",
    )
}

fn h2_03_depth() -> Result<(), String> {
    let bytes = vector("invalid", "too_deep.ainf");
    let opts = DecodeOpts {
        limits: Limits {
            max_depth: 8,
            ..Limits::default()
        },
        verify_hash: true,
        verify_canonical: false,
    };
    expect_code(validate_with(&bytes, opts), "infinity/depth")
}

fn h2_04_expansion() -> Result<(), String> {
    // A diamond chain doubles the projected tree at every level. The module is
    // tiny; the projection must refuse rather than materialise the tree.
    let mut module = InfinityModule::new();
    let mut current = module.push(Inode::Int(1));
    for _ in 0..20 {
        let left = module.push(Inode::Ref(current));
        let right = module.push(Inode::Ref(current));
        current = module.push(Inode::Table {
            fields: vec![("l".into(), left), ("r".into(), right)],
        });
    }
    module.set_root(Some(current));
    let error = active_infinity::to_protobuf(&module).expect_err("exponential DAG");
    if error.code() != "infinity/encode" {
        return Err(format!("unexpected protobuf code {}", error.code()));
    }
    if !error.to_string().contains("node budget") {
        return Err(format!("the diagnostic did not name the budget: {error}"));
    }
    #[cfg(feature = "json")]
    {
        let error =
            active_infinity::interop::to_redacted_json(&module).expect_err("exponential DAG");
        if error.code() != "infinity/encode" {
            return Err(format!("unexpected JSON code {}", error.code()));
        }
    }
    Ok(())
}

fn h2_05_sparse() -> Result<(), String> {
    expect_code(
        validate(&vector("invalid", "short_count.ainf")),
        "infinity/count",
    )
}

fn h2_06_utf8() -> Result<(), String> {
    expect_code(
        validate(&vector("invalid", "bad_utf8.ainf")),
        "infinity/utf8",
    )
}

fn h2_07_stream() -> Result<(), String> {
    let bytes = vector("invalid_stream", "unterminated.ainf");
    match active_infinity::stream::decode_stream(&bytes) {
        Err(error) => {
            if error.code().starts_with("infinity/stream") {
                Ok(())
            } else {
                Err(format!("unexpected stream code {}", error.code()))
            }
        }
        Ok(_) => Err("a truncated stream decoded".into()),
    }
}

fn secret_module(literal: &str) -> InfinityModule {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from(literal)));
    let number = module.push(Inode::Int(7));
    let root = module.push(Inode::Table {
        fields: vec![(format!("key-{literal}"), secret), ("n".into(), number)],
    });
    module.set_root(Some(root));
    module.bind(format!("binding {literal}"), secret);
    module.annotate(secret, AnnotationKind::Intent(format!("note {literal}")));
    module.set_provenance(Some(Provenance {
        producer: Some(format!("producer {literal}")),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: None,
        entries: vec![ProvEntry {
            key: format!("entry-{literal}"),
            value: ProvValue::Text(format!("value {literal}")),
        }],
    }));
    module
}

fn h2_14_secret_metadata() -> Result<(), String> {
    let literal = "redteam-canary-14";
    let module = secret_module(literal);
    let mut exports = vec![format!("{module:?}")];
    exports.push(active_infinity::interop::to_redacted_json(&module).map_err(|e| e.to_string())?);
    let protobuf = active_infinity::to_protobuf(&module).map_err(|e| e.to_string())?;
    exports.push(String::from_utf8_lossy(&protobuf).into_owned());
    exports.extend(active_infinity::interop::provenance_lines(&module));
    exports.extend(active_infinity::interop::value_paths(&module).into_values());
    exports.extend(active_infinity::interop::secret_tainted_paths(&module));
    for text in exports {
        if text.contains(literal) {
            return Err(format!("an export leaked the literal: {text}"));
        }
    }
    Ok(())
}

fn h2_15_error_echo() -> Result<(), String> {
    let literal = "redteam-canary-15";
    let mut bytes = encode(&secret_module(literal)).map_err(|e| e.to_string())?;
    // Corrupt a section offset so validation fails; the diagnostic must not
    // echo the image bytes.
    bytes[64..68].copy_from_slice(&u32::MAX.to_le_bytes());
    let error = validate(&bytes).expect_err("a bad offset must be refused");
    let text = format!("{error}");
    if text.contains(literal) {
        return Err(format!("the error echoed the literal: {text}"));
    }
    if !text.starts_with("infinity/") && !error.code().starts_with("infinity/") {
        return Err(format!("unstable code {}", error.code()));
    }
    Ok(())
}

fn h2_16_oracle() -> Result<(), String> {
    let one = SecretBytes::from("same");
    let two = SecretBytes::from("same");
    if one == two {
        return Err("two secrets compared equal".into());
    }
    let mut first = InfinityModule::new();
    first.push(Inode::Secret(SecretBytes::from("first")));
    let mut second = InfinityModule::new();
    second.push(Inode::Secret(SecretBytes::from("second")));
    if first != second {
        return Err("structural equality depends on secret content".into());
    }
    Ok(())
}

fn h2_17_extension() -> Result<(), String> {
    let literal = "redteam-canary-17";
    let mut module = secret_module(literal);
    module.add_extension(9, format!("note {literal} note").into_bytes());
    match active_infinity::to_protobuf(&module) {
        Err(error) if error.code() == "infinity/encode" => {}
        Err(error) => return Err(format!("unexpected code {}", error.code())),
        Ok(_) => return Err("an extension copy of a secret was projected".into()),
    }
    let debug = format!("{module:?}");
    if debug.contains(literal) {
        return Err("Debug printed the extension payload".into());
    }
    Ok(())
}

fn h2_24_bit_flip() -> Result<(), String> {
    let base = encode(&secret_module("redteam-canary-24")).map_err(|e| e.to_string())?;
    let original = hash_image(&base).map_err(|e| e.to_string())?;
    for offset in (48..base.len()).step_by(7).take(48) {
        let mut mutated = base.clone();
        mutated[offset] ^= 0x01;
        if let Ok(hash) = hash_image(&mutated) {
            mutated[16..48].copy_from_slice(&hash);
        }
        if validate(&mutated).is_ok() {
            let after = hash_image(&mutated).map_err(|e| e.to_string())?;
            if after == original {
                return Err(format!("a bit flip at {offset} kept the content hash"));
            }
        }
    }
    Ok(())
}

fn h2_27_projection() -> Result<(), String> {
    let literal = "redteam-canary-27";
    let module = secret_module(literal);
    let json = active_infinity::interop::to_redacted_json(&module).map_err(|e| e.to_string())?;
    let protobuf = active_infinity::to_protobuf(&module).map_err(|e| e.to_string())?;
    if json.contains(literal) || String::from_utf8_lossy(&protobuf).contains(literal) {
        return Err("a projection leaked the literal".into());
    }
    if !json.contains(SECRET_MARKER)
        || !protobuf
            .windows(SECRET_MARKER.len())
            .any(|window| window == SECRET_MARKER.as_bytes())
    {
        return Err("a projection lost the secret marker".into());
    }
    let image = encode(&module).map_err(|e| e.to_string())?;
    let hash = hash_image(&image).map_err(|e| e.to_string())?;
    if !protobuf.windows(hash.len()).any(|window| window == hash) {
        return Err("the protobuf projection did not advertise the content hash".into());
    }
    Ok(())
}

fn source_files(directory: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            source_files(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn h2_33_cfg_audit() -> Result<(), String> {
    let mut files = Vec::new();
    source_files(&root().join("src"), &mut files);
    if files.is_empty() {
        return Err("no source files found".into());
    }
    for file in files {
        let text = std::fs::read_to_string(&file).map_err(|e| e.to_string())?;
        if text.contains("debug_assert!") || text.contains("cfg!(debug_assertions)") {
            return Err(format!(
                "{} contains a debug-only assertion or branch",
                file.display()
            ));
        }
    }
    Ok(())
}

fn h2_34_corpus() -> Result<(), String> {
    let mut files = Vec::new();
    let mut stack = vec![root().join("fuzz").join("corpus")];
    while let Some(directory) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }
    for file in files {
        let bytes = std::fs::read(&file).map_err(|e| e.to_string())?;
        let _ = validate(&bytes);
        if validate(&bytes).is_ok() {
            let module = decode(&bytes).map_err(|e| format!("{}: {e}", file.display()))?;
            let _ = encode(&module);
            let _ = active_infinity::interop::to_redacted_json(&module);
            let _ = active_infinity::to_protobuf(&module);
        }
    }
    Ok(())
}

fn h2_36_allocation() -> Result<(), String> {
    let bytes = vector("invalid", "count_bomb.ainf");
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = validate(&bytes);
    }
    if start.elapsed().as_millis() > 2_000 {
        return Err(format!(
            "1000 count-bomb rejections took {} ms",
            start.elapsed().as_millis()
        ));
    }
    Ok(())
}

#[test]
fn redteam_battery_is_green() {
    let mut failures = Vec::new();
    let mut passed = 0usize;
    for case in CASES {
        match catch_unwind(AssertUnwindSafe(case.check)) {
            Ok(Ok(())) => {
                passed += 1;
                println!("PASS {} ({}) {}", case.id, case.invariant, case.threat);
            }
            Ok(Err(message)) => failures.push(format!(
                "{} ({}) {}: {message}",
                case.id, case.invariant, case.threat
            )),
            Err(payload) => {
                let message = payload
                    .downcast_ref::<&str>()
                    .map(|text| text.to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "non-string panic".into());
                failures.push(format!(
                    "{} ({}) {}: panicked: {message}",
                    case.id, case.invariant, case.threat
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} red-team cases failed:\n{}",
        failures.len(),
        CASES.len(),
        failures.join("\n")
    );
    assert_eq!(passed, CASES.len());
}
