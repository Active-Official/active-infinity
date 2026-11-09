#![no_main]
//! The CLI parser is attacker-facing (argv from a shell, a script, or an
//! agent): every command's flag/positional validation must stay total, and
//! `run()` must never panic, never hang, and never touch files outside the
//! fuzz tempdir. The argv is built from a fixed command/flag vocabulary
//! over staged files (INF-POLY-05).
//!
//! Bounds by construction: bench iterations come from a capped vocabulary
//! (the 1,000,000 boundary is the CLI's own unit test), the conformance
//! manifest is at most the fuzz input, and every path names a staged file
//! inside the tempdir — never a fuzz-derived path.

use libfuzzer_sys::fuzz_target;

use active_infinity::{content_hash_hex, validate_canonical, Limits};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fresh directory per run, so no state leaks between iterations.
fn tempdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fuzz-cli-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("a temp CLI directory");
    dir
}

fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("a staged file writes");
}

/// Stage every file one command may name, all under `dir`, all derived
/// from the same payload bytes in different roles.
struct Stage {
    image: PathBuf,
    source: PathBuf,
    stream: PathBuf,
    manifest: PathBuf,
    dict: PathBuf,
    sample1: PathBuf,
    sample2: PathBuf,
    seed: PathBuf,
    proof: PathBuf,
    schema: PathBuf,
    store: PathBuf,
    out: PathBuf,
}

fn stage(dir: &Path, payload: &[u8], selector: &[u8; 8]) -> Stage {
    let image = dir.join("image.ainf");
    let source = dir.join("source.active");
    let stream = dir.join("stream.ains");
    let manifest = dir.join("manifest.json");
    let dict = dir.join("dict.bin");
    let sample1 = dir.join("sample1.bin");
    let sample2 = dir.join("sample2.bin");
    let seed = dir.join("seed.hex");
    let proof = dir.join("proof.json");
    let schema = dir.join("schema.ainf");
    let corrupt = dir.join("corrupt.ainf");
    let store = dir.join("store");
    let out = dir.join("out.bin");
    write(&image, payload);
    write(&source, payload);
    write(&stream, payload);
    write(&dict, payload);
    let half = payload.len() / 2;
    write(&sample1, &payload[..half]);
    write(&sample2, &payload[half..]);
    // A 64-hex seed file, derived from the payload (padded deterministically).
    let mut seed_bytes = [7u8; 32];
    seed_bytes[..payload.len().min(32)].copy_from_slice(&payload[..payload.len().min(32)]);
    let seed_hex: String = seed_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    write(&seed, seed_hex.as_bytes());
    write(&proof, payload);
    write(&schema, payload);
    // A corrupted copy of the image, for a manifest invalid case.
    let mut corrupt_bytes = payload.to_vec();
    if let Some(first) = corrupt_bytes.first_mut() {
        *first ^= 0xff;
    }
    write(&corrupt, &corrupt_bytes);
    // The manifest: fuzz JSON, or — one time in three — a manifest the
    // target builds around the staged files, with real pins computed
    // in-target, so the conformance runner's case checks run for real.
    // (Case paths resolve against the manifest's own directory.)
    if selector[6].is_multiple_of(3) {
        write(&manifest, &synthetic_manifest(payload, &corrupt_bytes));
    } else {
        write(&manifest, payload);
    }
    Stage {
        image,
        source,
        stream,
        manifest,
        dict,
        sample1,
        sample2,
        seed,
        proof,
        schema,
        store,
        out,
    }
}

/// A manifest with one valid case (the staged image, really pinned) and
/// one invalid case (the corrupted copy, with the code it really fails
/// with, computed in-target).
fn synthetic_manifest(payload: &[u8], corrupt: &[u8]) -> Vec<u8> {
    let mut text =
        String::from(r#"{"format":"active-conformance/1","version":"test","base":".","cases":["#);
    let hash = content_hash_hex(payload).unwrap_or_default();
    text.push_str(&format!(
        r#"{{"name":"valid","kind":"valid","path":"image.ainf","content_hash":"{hash}","size":{}}}"#,
        payload.len()
    ));
    if let Err(error) = validate_canonical(corrupt, Limits::default()) {
        text.push_str(&format!(
            r#",{{"name":"invalid","kind":"invalid","path":"corrupt.ainf","expected_code":"{}"}}"#,
            error.code()
        ));
    }
    text.push_str("]}");
    text.into_bytes()
}

fn sel(byte: u8, n: usize) -> usize {
    (byte as usize) % n
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    // The signing seed must not leak in from the fuzzer's environment: a
    // set-but-empty value would make `store put` fail for reasons outside
    // the argv under test.
    std::env::remove_var("ACTIVE_INFINITY_SIGN_SEED");
    let mut selector = [0u8; 8];
    selector[..data.len().min(8)].copy_from_slice(&data[..data.len().min(8)]);
    let payload = if data.len() > 8 { &data[8..] } else { &[][..] };

    let argv = |stage: &Stage, selector: &[u8; 8]| -> Vec<String> {
        let s = |path: &Path| path.to_string_lossy().into_owned();
        let hash = content_hash_hex(payload).unwrap_or_else(|_| "00".repeat(32));
        let hashes = [
            hash,
            "00".repeat(32),
            "zz".repeat(32),
            "ab".repeat(31) + "a",
            "ab".repeat(32) + "ab",
            String::new(),
        ];
        let hash = &hashes[sel(selector[5], hashes.len())];
        let iterations = ["0", "1", "2", "50", "1000", "1000001", "-1", "abc"];
        let iteration = iterations[sel(selector[1], iterations.len())];
        // Levels 19 and 22 are NOT in this vocabulary: they select zstd's
        // optimal parser, whose `ZSTD_selectBtGetAllMatches` (zstd 1.5.7,
        // `zstd_opt.c`) keeps its match-finder table as a `const` local
        // array that clang promotes to static storage while ASan still
        // poisons its shadow on return — so the second compression in one
        // process aborts with a `stack-use-after-scope` report on a
        // global address. Proven a sanitizer artifact, not a codec bug:
        // the same level-22 compression through the `zstd` crate alone
        // aborts on its second run under ASan, and levels 3/19/22 all
        // compress and round-trip correctly without ASan. (INF-POLY-05.)
        let levels = ["-22", "-1", "0", "3", "99", "x"];
        let level = levels[sel(selector[2], levels.len())];
        let max_bytes = ["0", "1", "1024", "67108864", "67108865", "x"];
        let max_byte = max_bytes[sel(selector[3], max_bytes.len())];
        let names = ["", "app.active", "a/b", "x"];
        let name = names[sel(selector[4], names.len())];
        let bench_ops = ["encode", "decode", "validate", "hash", "bogus"];
        let bench_op = bench_ops[sel(selector[2], bench_ops.len())];
        let mut args: Vec<String> = match sel(selector[0], 20) {
            0 => vec!["validate".into(), s(&stage.image)],
            1 => vec!["validate-canonical".into(), s(&stage.image)],
            2 => vec!["hash".into(), s(&stage.image)],
            3 => vec!["decode".into(), s(&stage.image)],
            4 => {
                let mut args = vec![
                    "encode".into(),
                    s(&stage.source),
                    "--name".into(),
                    name.into(),
                ];
                if selector[7].is_multiple_of(2) {
                    args.push("--output".into());
                    args.push(s(&stage.out));
                }
                args
            }
            5 => vec!["stream".into(), s(&stage.stream)],
            6 => {
                let mut args = vec![
                    "store".into(),
                    "put".into(),
                    s(&stage.image),
                    "--root".into(),
                    s(&stage.store),
                ];
                if selector[7].is_multiple_of(3) {
                    args.push("--sign-file".into());
                    args.push(s(&stage.seed));
                    args.push("--allow-insecure-seed".into());
                }
                args
            }
            7 => vec![
                "store".into(),
                "get".into(),
                hash.clone(),
                "--root".into(),
                s(&stage.store),
            ],
            8 => vec![
                "store".into(),
                "signature".into(),
                hash.clone(),
                "--root".into(),
                s(&stage.store),
            ],
            9 => {
                let mut args = vec![
                    "dict".into(),
                    "train".into(),
                    "--output".into(),
                    s(&stage.dict),
                    s(&stage.sample1),
                    s(&stage.sample2),
                ];
                if selector[1].is_multiple_of(2) {
                    let sizes = ["255", "256", "1024", "100000000"];
                    args.push("--size".into());
                    args.push(sizes[sel(selector[2], sizes.len())].into());
                }
                args
            }
            10 => {
                let mut args = vec![
                    "dict".into(),
                    "apply".into(),
                    "--dictionary".into(),
                    s(&stage.dict),
                    "--output".into(),
                    s(&stage.out),
                    s(&stage.image),
                ];
                if selector[1].is_multiple_of(2) {
                    args.push("--decompress".into());
                    args.push("--max-bytes".into());
                    args.push(max_byte.into());
                } else {
                    args.push("--level".into());
                    args.push(level.into());
                }
                args
            }
            11 => {
                let mut args = vec!["proof".into(), "issue".into(), s(&stage.image)];
                if selector[7].is_multiple_of(2) {
                    args.push("--schema".into());
                    args.push(s(&stage.schema));
                    args.push("--output".into());
                    args.push(s(&stage.out));
                }
                args
            }
            12 => {
                let mut args = vec![
                    "proof".into(),
                    "verify".into(),
                    s(&stage.image),
                    s(&stage.proof),
                ];
                if selector[7].is_multiple_of(2) {
                    args.push("--schema".into());
                    args.push(s(&stage.schema));
                }
                args
            }
            13 => vec![
                "bench".into(),
                bench_op.into(),
                s(&stage.image),
                "--iterations".into(),
                iteration.into(),
            ],
            14 => vec![
                "conformance".into(),
                "run".into(),
                "--manifest".into(),
                s(&stage.manifest),
            ],
            15 => vec!["help".into()],
            16 => vec!["version".into()],
            17 => vec!["doctor".into()],
            18 => vec!["frobnicate".into()],
            _ => vec![],
        };
        // Junk legs: an unknown flag, an extra positional, or an output
        // path that names the input (the `ensure_distinct` refusal).
        match selector[6] % 4 {
            0 if !args.is_empty() => {
                args.push("--nope".into());
                args.push("x".into());
            }
            1 => args.push("extra".into()),
            2 if sel(selector[0], 20) == 4 || sel(selector[0], 20) == 11 => {
                args.push("--output".into());
                args.push(s(&stage.image));
            }
            _ => {}
        }
        args
    };

    // The same argv in two fresh tempdirs must decide the same way: the
    // parser is deterministic, and any nondeterminism is a bug, not a
    // timing artifact (only the Ok/Err outcome is compared).
    let dir_a = tempdir();
    let stage_a = stage(&dir_a, payload, &selector);
    let first = active_infinity_cli::run(argv(&stage_a, &selector));
    let dir_b = tempdir();
    let stage_b = stage(&dir_b, payload, &selector);
    let second = active_infinity_cli::run(argv(&stage_b, &selector));
    assert_eq!(
        first.is_ok(),
        second.is_ok(),
        "the same argv decides the same way twice: {first:?} vs {second:?}"
    );
    let _ = fs::remove_dir_all(&dir_a);
    let _ = fs::remove_dir_all(&dir_b);
});
