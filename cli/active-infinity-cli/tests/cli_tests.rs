//! End-to-end tests for the CLI surface: exit codes, the dictionary helpers,
//! the microbench, the store and the conformance scorecard.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use active_infinity::interop::from_active_source;
use active_infinity::{decode, encode};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_active-infinity-cli"))
}

fn sandbox(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("active-infinity-cli-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("sandbox");
    dir
}

fn run(args: &[&str]) -> Output {
    cli().args(args).output().expect("spawn cli")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn image(seed: usize) -> Vec<u8> {
    let source = format!(
        "[app]\nname = \"service-{seed}\"\nhost = \"node-{seed}.internal\"\nport = {}\nratio = {}%\n",
        8000 + seed,
        seed + 5
    );
    let module = from_active_source(&source, "test.active").expect("parse");
    encode(&module).expect("encode")
}

fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write");
}

#[test]
fn help_lists_every_command_with_examples() {
    let output = run(&["help"]);
    assert!(output.status.success());
    let text = stdout(&output);
    for command in [
        "encode",
        "decode",
        "validate",
        "hash",
        "stream",
        "store",
        "dict",
        "bench",
        "conformance",
        "doctor",
    ] {
        assert!(text.contains(command), "help is missing {command}");
    }
    assert!(text.contains("Examples:"), "help must show examples");
    assert!(
        text.contains("Exit codes:"),
        "help must document exit codes"
    );
}

#[test]
fn unknown_command_exits_with_the_usage_code() {
    let output = run(&["nonsense"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("usage:"));
}

#[test]
fn validate_hash_and_decode_agree() {
    let dir = sandbox("validate");
    let path = dir.join("image.ainf");
    let bytes = image(1);
    write(&path, &bytes);
    let path = path.to_str().expect("utf8");

    let validated = run(&["validate", path]);
    assert!(validated.status.success(), "{}", stderr(&validated));
    assert!(stdout(&validated).contains("ok nodes="));

    let hash = run(&["hash", path]);
    assert!(hash.status.success());
    let printed = stdout(&hash).trim().to_string();
    assert_eq!(printed.len(), 64);
    assert_eq!(
        printed,
        active_infinity::content_hash_hex(&bytes).expect("hash")
    );

    let decoded = run(&["decode", path]);
    assert!(decoded.status.success(), "{}", stderr(&decoded));
    let json: serde_json::Value = serde_json::from_str(&stdout(&decoded)).expect("json");
    assert!(json.is_object());
    assert!(!stdout(&decoded).contains("CANARY_SECRET_"));
}

#[test]
fn invalid_image_fails_closed_with_exit_one() {
    let dir = sandbox("invalid");
    let path = dir.join("broken.ainf");
    write(&path, b"not an image");
    let output = run(&["validate", path.to_str().expect("utf8")]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("infinity/"));
}

#[test]
fn dict_train_and_apply_round_trip() {
    let dir = sandbox("dict");
    let mut samples = Vec::new();
    for seed in 0..12 {
        let path = dir.join(format!("sample-{seed}.ainf"));
        write(&path, &image(seed));
        samples.push(path.to_string_lossy().into_owned());
    }
    let dictionary = dir.join("corpus.dict");
    let mut args = vec![
        "dict".to_string(),
        "train".to_string(),
        "--output".to_string(),
        dictionary.to_string_lossy().into_owned(),
        "--size".to_string(),
        "512".to_string(),
    ];
    args.extend(samples.iter().cloned());
    let reference: Vec<&str> = args.iter().map(String::as_str).collect();
    let trained = run(&reference);
    assert!(trained.status.success(), "{}", stderr(&trained));
    let dictionary_bytes = fs::read(&dictionary).expect("dictionary");
    assert_eq!(dictionary_bytes.len(), 512);

    let input = dir.join("sample-0.ainf");
    let compressed = dir.join("sample-0.zst");
    let restored = dir.join("sample-0.back");
    let applied = run(&[
        "dict",
        "apply",
        "--dictionary",
        dictionary.to_str().expect("utf8"),
        "--output",
        compressed.to_str().expect("utf8"),
        input.to_str().expect("utf8"),
    ]);
    assert!(applied.status.success(), "{}", stderr(&applied));
    assert!(
        fs::metadata(&compressed).expect("compressed").len()
            < fs::metadata(&input).expect("input").len(),
        "compression should shrink a small image with a matching dictionary"
    );

    let restored_output = run(&[
        "dict",
        "apply",
        "--decompress",
        "--dictionary",
        dictionary.to_str().expect("utf8"),
        "--output",
        restored.to_str().expect("utf8"),
        compressed.to_str().expect("utf8"),
    ]);
    assert!(
        restored_output.status.success(),
        "{}",
        stderr(&restored_output)
    );
    assert_eq!(
        fs::read(&restored).expect("restored"),
        fs::read(&input).expect("input")
    );
}

#[test]
fn dict_train_refuses_a_dictionary_larger_than_the_corpus() {
    let dir = sandbox("dict-small");
    let mut samples = Vec::new();
    for seed in 0..2 {
        let path = dir.join(format!("sample-{seed}.ainf"));
        write(&path, &image(seed));
        samples.push(path.to_string_lossy().into_owned());
    }
    let mut args = vec![
        "dict".to_string(),
        "train".to_string(),
        "--output".to_string(),
        dir.join("too-big.dict").to_string_lossy().into_owned(),
        "--size".to_string(),
        "1048576".to_string(),
    ];
    args.extend(samples);
    let reference: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(&reference);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("too large"));
}

#[test]
fn bench_prints_ordered_percentiles() {
    let dir = sandbox("bench");
    let path = dir.join("image.ainf");
    write(&path, &image(2));
    for op in ["validate", "hash", "encode", "decode"] {
        let output = run(&[
            "bench",
            op,
            path.to_str().expect("utf8"),
            "--iterations",
            "5",
        ]);
        assert!(output.status.success(), "{op}: {}", stderr(&output));
        let text = stdout(&output);
        let numbers: Vec<u64> = ["p50_ns=", "p95_ns=", "p99_ns="]
            .iter()
            .map(|key| {
                let start = text.find(key).unwrap_or_else(|| panic!("{key} in {text}")) + key.len();
                text[start..]
                    .split_whitespace()
                    .next()
                    .expect("value")
                    .parse()
                    .expect("number")
            })
            .collect();
        assert!(
            numbers[0] <= numbers[1] && numbers[1] <= numbers[2],
            "{op}: {numbers:?}"
        );
    }
}

#[test]
fn store_put_and_get_round_trip() {
    let dir = sandbox("store");
    let path = dir.join("image.ainf");
    let bytes = image(3);
    write(&path, &bytes);
    let root = dir.join("store");
    let put = run(&[
        "store",
        "put",
        path.to_str().expect("utf8"),
        "--root",
        root.to_str().expect("utf8"),
    ]);
    assert!(put.status.success(), "{}", stderr(&put));
    let hash = stdout(&put).trim().to_string();
    assert_eq!(hash.len(), 64);

    let out = dir.join("restored.ainf");
    let get = run(&[
        "store",
        "get",
        &hash,
        "--root",
        root.to_str().expect("utf8"),
        "--output",
        out.to_str().expect("utf8"),
    ]);
    assert!(get.status.success(), "{}", stderr(&get));
    assert_eq!(fs::read(&out).expect("restored"), bytes);
    // The stored image still decodes.
    decode(&bytes).expect("decode");
}

#[test]
fn proof_issue_and_verify_round_trip() {
    let dir = sandbox("proof");
    let image = dir.join("image.ainf");
    write(&image, &image_bytes_for_proof());
    let proof = dir.join("proof.json");
    let issued = run(&[
        "proof",
        "issue",
        image.to_str().expect("utf8"),
        "--output",
        proof.to_str().expect("utf8"),
    ]);
    assert!(issued.status.success(), "{}", stderr(&issued));
    let text = fs::read_to_string(&proof).expect("sidecar");
    assert!(text.contains("active-infinity/proof/1"), "{text}");

    let verified = run(&[
        "proof",
        "verify",
        image.to_str().expect("utf8"),
        proof.to_str().expect("utf8"),
    ]);
    assert!(verified.status.success(), "{}", stderr(&verified));
    assert!(stdout(&verified).contains("ok hash="));

    // A sidecar whose hash was edited must be refused.
    let mut value: serde_json::Value = serde_json::from_str(&text).expect("json");
    value["content_hash"] = serde_json::Value::String("00".repeat(32));
    fs::write(&proof, value.to_string()).expect("tamper");
    let refused = run(&[
        "proof",
        "verify",
        image.to_str().expect("utf8"),
        proof.to_str().expect("utf8"),
    ]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        stderr(&refused).contains("infinity/proof"),
        "{}",
        stderr(&refused)
    );
}

fn image_bytes_for_proof() -> Vec<u8> {
    image(9)
}

#[test]
fn proof_verify_without_a_sidecar_is_a_usage_error() {
    let output = run(&["proof", "verify"]);
    assert_eq!(output.status.code(), Some(2));
}
