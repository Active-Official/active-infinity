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

/// Grant Everyone read on a seed file (Windows only). Uses the SID form
/// (`*S-1-1-0`), which is locale-independent — the account name
/// "Everyone" is localized (e.g. "Todos" on a Spanish install).
#[cfg(windows)]
fn grant_everyone_read(path: &Path) {
    let output = Command::new("icacls")
        .arg(path)
        .arg("/grant")
        .arg("*S-1-1-0:R")
        .output()
        .expect("spawn icacls");
    assert!(
        output.status.success(),
        "icacls grant failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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

#[test]
fn version_prints_the_cli_and_library() {
    for flag in ["version", "--version", "-V"] {
        let output = run(&[flag]);
        assert!(output.status.success(), "{flag}: {}", stderr(&output));
        let text = stdout(&output);
        assert!(
            text.contains(concat!("active-infinity-cli ", env!("CARGO_PKG_VERSION"))),
            "{text}"
        );
        assert!(text.contains("(active-infinity "), "{text}");
    }
}

/// The store's authenticity path end to end: sign on put, verify on get, pin
/// the key, and every refusal exits non-zero with `infinity/signature`.
#[test]
fn store_signs_and_refuses_unsigned_or_foreign_objects() {
    let dir = sandbox("signed-store");
    let image_path = dir.join("image.ainf");
    let bytes = image(70);
    write(&image_path, &bytes);
    let store = dir.join("store");
    let store_arg = store.to_str().expect("store path");
    let seed = "01".repeat(32);

    let output = run(&[
        "store",
        "put",
        image_path.to_str().expect("image path"),
        "--root",
        store_arg,
        "--sign",
        &seed,
        "--i-accept-argv-key-leak",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let hash = stdout(&output).trim().to_string();
    assert_eq!(hash.len(), 64);

    let verified = run(&["store", "get", &hash, "--root", store_arg, "--verify"]);
    assert!(verified.status.success(), "{}", stderr(&verified));
    assert_eq!(verified.stdout.as_slice(), bytes.as_slice());

    let signature = run(&["store", "signature", &hash, "--root", store_arg]);
    assert!(signature.status.success(), "{}", stderr(&signature));
    let text = stdout(&signature);
    assert!(text.contains("key "), "{text}");
    assert!(text.contains(&hash), "{text}");
    let key = text
        .lines()
        .find_map(|line| line.strip_prefix("key "))
        .expect("key line")
        .to_string();

    // The same key on the explicit path verifies.
    let pinned = run(&[
        "store", "get", &hash, "--root", store_arg, "--verify", "--key", &key,
    ]);
    assert!(pinned.status.success(), "{}", stderr(&pinned));

    // An unsigned object is refused on the authenticity path and reports the
    // signature class.
    let plain_path = dir.join("plain.ainf");
    write(&plain_path, &image(71));
    let plain = run(&[
        "store",
        "put",
        plain_path.to_str().expect("plain path"),
        "--root",
        store_arg,
    ]);
    assert!(plain.status.success(), "{}", stderr(&plain));
    let plain_hash = stdout(&plain).trim().to_string();
    let refused = run(&["store", "get", &plain_hash, "--root", store_arg, "--verify"]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        stderr(&refused).contains("infinity/signature"),
        "{}",
        stderr(&refused)
    );

    // A different key does not verify the first object.
    let other_path = dir.join("other.ainf");
    write(&other_path, &image(72));
    let other = run(&[
        "store",
        "put",
        other_path.to_str().expect("other path"),
        "--root",
        store_arg,
        "--sign",
        &"02".repeat(32),
        "--i-accept-argv-key-leak",
    ]);
    assert!(other.status.success(), "{}", stderr(&other));
    let other_hash = stdout(&other).trim().to_string();
    let other_signature = run(&["store", "signature", &other_hash, "--root", store_arg]);
    let other_key = stdout(&other_signature)
        .lines()
        .find_map(|line| line.strip_prefix("key "))
        .expect("other key")
        .to_string();
    assert_ne!(key, other_key);
    let wrong = run(&[
        "store", "get", &hash, "--root", store_arg, "--verify", "--key", &other_key,
    ]);
    assert_eq!(wrong.status.code(), Some(1));
    assert!(stderr(&wrong).contains("another key"), "{}", stderr(&wrong));

    // --key without --verify is a usage error.
    let usage = run(&["store", "get", &hash, "--root", store_arg, "--key", &key]);
    assert_eq!(usage.status.code(), Some(2));

    // A tampered envelope is refused rather than accepted.
    let sig_path = store.join(format!("{hash}.sig"));
    let mut envelope = fs::read(&sig_path).expect("read envelope");
    envelope[40] ^= 0x01;
    fs::write(&sig_path, &envelope).expect("tamper envelope");
    let tampered = run(&["store", "get", &hash, "--root", store_arg, "--verify"]);
    assert_eq!(tampered.status.code(), Some(1));
    assert!(
        stderr(&tampered).contains("infinity/signature"),
        "{}",
        stderr(&tampered)
    );
}

#[test]
fn dict_train_refuses_a_size_whose_bound_would_wrap() {
    let dir = sandbox("dict-overflow");
    let mut samples = Vec::new();
    for seed in 0..2 {
        let path = dir.join(format!("sample-{seed}.ainf"));
        write(&path, &image(seed));
        samples.push(path.to_string_lossy().into_owned());
    }
    // 4 * this value is zero modulo 2^64, so an unchecked multiply lets the
    // corpus guard pass and hands zstd an impossible allocation.
    let mut args = vec![
        "dict".to_string(),
        "train".to_string(),
        "--output".to_string(),
        dir.join("overflow.dict").to_string_lossy().into_owned(),
        "--size".to_string(),
        "4611686018427387904".to_string(),
    ];
    args.extend(samples);
    let reference: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(&reference);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("usage:"), "{}", stderr(&output));
}

#[test]
fn dict_apply_refuses_an_impossible_level_and_ceiling() {
    let dir = sandbox("dict-flags");
    let input = dir.join("input.bin");
    write(&input, b"payload bytes");
    let dictionary = dir.join("corpus.dict");
    write(&dictionary, &image(0));

    // 2^40 truncates to 0 as an i32; a silent truncation would accept it.
    let output = run(&[
        "dict",
        "apply",
        "--dictionary",
        dictionary.to_str().expect("utf8"),
        "--level",
        "1099511627776",
        input.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("usage:"), "{}", stderr(&output));

    // A decode ceiling above the codec ceiling asks zstd for an allocation no
    // valid image could justify.
    let output = run(&[
        "dict",
        "apply",
        "--decompress",
        "--dictionary",
        dictionary.to_str().expect("utf8"),
        "--max-bytes",
        "18446744073709551615",
        input.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("usage:"), "{}", stderr(&output));
}

#[test]
fn an_input_above_the_ceiling_is_refused_before_it_is_read() {
    let dir = sandbox("input-ceiling");
    let huge = dir.join("huge.bin");
    let file = fs::File::create(&huge).expect("create");
    file.set_len((1u64 << 30) + 8192).expect("set len");
    drop(file);
    let dictionary = dir.join("corpus.dict");
    write(&dictionary, &image(0));

    let output = run(&[
        "dict",
        "apply",
        "--dictionary",
        dictionary.to_str().expect("utf8"),
        huge.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("input ceiling"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn stream_reassembles_a_valid_stream() {
    let dir = sandbox("stream");
    let image = image(0);
    let module = decode(&image).expect("decode");
    let mut bytes = Vec::new();
    for frame in active_infinity::stream::encode_stream(&module, 4096).expect("stream") {
        bytes.extend_from_slice(&frame.to_bytes());
    }
    let path = dir.join("s.ains");
    write(&path, &bytes);

    let output = run(&["stream", path.to_str().expect("utf8")]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("ok bytes="), "{}", stdout(&output));

    // A missing path is a usage error, not a panic or a silent success.
    let usage = run(&["stream"]);
    assert_eq!(usage.status.code(), Some(2), "{}", stderr(&usage));
}

#[test]
fn a_signing_seed_can_come_from_a_file() {
    let dir = sandbox("sign-file");
    let store = dir.join("store");
    let image_path = dir.join("image.ainf");
    write(&image_path, &image(0));
    let seed_path = dir.join("seed.txt");
    write(&seed_path, &"09".repeat(32).into_bytes());
    // The CLI refuses a seed file that group or other can read, and a file
    // created under a 022 umask is 0644 (audit AI-02).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).expect("mode");
    }

    // On Windows the CLI cannot verify a seed file's permissions, so
    // signing from a file needs the explicit --allow-insecure-seed flag
    // (INF-CLI-02). The refusal itself is covered by
    // `a_world_readable_seed_file_is_refused_on_windows`.
    let mut argv: Vec<&str> = vec![
        "store",
        "put",
        image_path.to_str().expect("utf8"),
        "--root",
        store.to_str().expect("utf8"),
        "--sign-file",
        seed_path.to_str().expect("utf8"),
    ];
    #[cfg(windows)]
    argv.push("--allow-insecure-seed");
    let put = run(&argv);
    assert!(put.status.success(), "{}", stderr(&put));
    let hash = stdout(&put).trim().to_string();

    let get = run(&[
        "store",
        "get",
        &hash,
        "--root",
        store.to_str().expect("utf8"),
        "--verify",
    ]);
    assert!(get.status.success(), "{}", stderr(&get));

    // Two seed sources at once are ambiguous.
    let both = run(&[
        "store",
        "put",
        image_path.to_str().expect("utf8"),
        "--root",
        store.to_str().expect("utf8"),
        "--sign",
        &"09".repeat(32),
        "--sign-file",
        seed_path.to_str().expect("utf8"),
    ]);
    assert_eq!(both.status.code(), Some(2), "{}", stderr(&both));
}

#[test]
fn a_signed_object_is_flagged_when_verification_is_not_requested() {
    let dir = sandbox("signed-note");
    let store = dir.join("store");
    let image_path = dir.join("image.ainf");
    write(&image_path, &image(0));
    let put = run(&[
        "store",
        "put",
        image_path.to_str().expect("utf8"),
        "--root",
        store.to_str().expect("utf8"),
        "--sign",
        &"09".repeat(32),
        "--i-accept-argv-key-leak",
    ]);
    assert!(put.status.success(), "{}", stderr(&put));
    let hash = stdout(&put).trim().to_string();

    let plain = run(&[
        "store",
        "get",
        &hash,
        "--root",
        store.to_str().expect("utf8"),
    ]);
    assert!(plain.status.success(), "{}", stderr(&plain));
    assert!(
        stderr(&plain).contains("pass --verify"),
        "the integrity-only path must point at --verify: {}",
        stderr(&plain)
    );
}

#[test]
fn strict_arguments_are_usage_errors() {
    let dir = sandbox("strict");
    let image_path = dir.join("image.ainf");
    write(&image_path, &image(0));
    let path = image_path.to_str().expect("utf8");

    for args in [
        vec!["validate", path, "extra"],
        vec!["hash", path, "extra"],
        vec!["validate", path, "--nope"],
        vec!["encode", path, "--name"],
        vec!["bench", "validate", path, "--iterations", "0"],
        vec!["bench", "validate", path, "--iterations", "999999999999"],
    ] {
        let reference: Vec<&str> = args.clone();
        let output = run(&reference);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn an_output_that_names_the_input_is_refused() {
    let dir = sandbox("same-path");
    let source = dir.join("source.active");
    write(&source, b"port = 8080\n");
    let output = run(&[
        "encode",
        source.to_str().expect("utf8"),
        "--output",
        source.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

#[test]
fn conformance_uses_the_manifest_directory_as_its_base() {
    let dir = sandbox("conformance-base");
    write(&dir.join("case.ainf"), &image(0));
    let manifest = dir.join("manifest.json");
    write(
        &manifest,
        br#"{"format":"active-conformance/1","version":"test","cases":[{"name":"case","kind":"valid","path":"case.ainf","content_hash":""}]}"#,
    );
    let output = run(&[
        "conformance",
        "run",
        "--manifest",
        manifest.to_str().expect("utf8"),
    ]);
    // The case fails on the deliberately empty hash, but it is *found*: the
    // base is the manifest's own directory.
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let scorecard: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("scorecard");
    let detail = scorecard["cases"][0]["detail"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        !detail.contains("cannot read") && !detail.contains("No such file"),
        "the case was not found: {detail}"
    );
}

#[test]
fn a_conformance_case_cannot_escape_the_manifest_directory() {
    let dir = sandbox("conformance-escape");
    let manifest = dir.join("manifest.json");
    write(
        &manifest,
        br#"{"format":"active-conformance/1","version":"test","cases":[{"name":"escape","kind":"valid","path":"../../etc/passwd"}]}"#,
    );
    let output = run(&[
        "conformance",
        "run",
        "--manifest",
        manifest.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("escapes the manifest directory"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn the_man_page_matches_the_command_surface() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let man = fs::read_to_string(root.join("docs/man/active-infinity-cli.1")).expect("man page");
    for command in [
        "encode",
        "decode",
        "validate",
        "hash",
        "stream",
        "store",
        "dict",
        "proof",
        "bench",
        "conformance",
        "doctor",
        "help",
    ] {
        assert!(man.contains(command), "the man page omits {command}");
    }
    assert!(
        man.contains(env!("CARGO_PKG_VERSION")),
        "the man page must carry the CLI version {}",
        env!("CARGO_PKG_VERSION")
    );
    assert!(
        man.contains("--verify"),
        "the man page must document --verify"
    );
    assert!(
        man.contains("--sign-file"),
        "the man page must document --sign-file"
    );
}

#[test]
fn dict_apply_accepts_a_negative_level_and_refuses_one_below_the_range() {
    let dir = sandbox("dict-negative-level");
    let input = dir.join("input.bin");
    write(&input, b"payload bytes that compress at a negative level");
    let dictionary = dir.join("corpus.dict");
    write(&dictionary, &image(0));
    let output_path = dir.join("out.zst");

    // zstd's fast levels are negative; parsing the flag as an unsigned number
    // made half the advertised range unreachable from the CLI.
    let output = run(&[
        "dict",
        "apply",
        "--dictionary",
        dictionary.to_str().expect("utf8"),
        "--level",
        "-1",
        "--output",
        output_path.to_str().expect("utf8"),
        input.to_str().expect("utf8"),
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let compressed = fs::read(&output_path).expect("read output");
    assert!(!compressed.is_empty());

    let output = run(&[
        "dict",
        "apply",
        "--dictionary",
        dictionary.to_str().expect("utf8"),
        "--level",
        "-1000000",
        input.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("--level must be between"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn dict_train_refuses_samples_over_the_input_ceiling_before_reading_them() {
    let dir = sandbox("dict-sample-total");
    let mut samples = Vec::new();
    // Sparse files: the declared length is over the ceiling while the disk cost
    // is one cluster. A per-file read would commit 600 MiB each.
    for seed in 0..2 {
        let path = dir.join(format!("sparse-{seed}.ainf"));
        let file = fs::File::create(&path).expect("create");
        file.set_len(600u64 << 20).expect("set len");
        drop(file);
        samples.push(path.to_string_lossy().into_owned());
    }
    let mut args = vec![
        "dict".to_string(),
        "train".to_string(),
        "--output".to_string(),
        dir.join("over.dict").to_string_lossy().into_owned(),
    ];
    args.extend(samples);
    let reference: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(&reference);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("input ceiling"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn dict_apply_refuses_a_flag_that_the_mode_cannot_use() {
    let dir = sandbox("dict-mode-flags");
    let input = dir.join("input.bin");
    write(&input, b"payload bytes");
    let dictionary = dir.join("corpus.dict");
    write(&dictionary, &image(0));
    let dictionary = dictionary.to_str().expect("utf8");
    let input = input.to_str().expect("utf8");

    // A level on a decode is accepted nowhere; a ceiling on a compress is
    // accepted nowhere either. Both used to be ignored silently.
    let output = run(&[
        "dict",
        "apply",
        "--decompress",
        "--dictionary",
        dictionary,
        "--level",
        "3",
        input,
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("--level applies to compression only"),
        "{}",
        stderr(&output)
    );

    let output = run(&[
        "dict",
        "apply",
        "--dictionary",
        dictionary,
        "--max-bytes",
        "1024",
        input,
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("--max-bytes applies to --decompress only"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn dict_apply_refuses_output_equal_to_the_dictionary() {
    let dir = sandbox("dict-output-clash");
    let input = dir.join("input.bin");
    write(&input, b"payload bytes");
    let dictionary = dir.join("corpus.dict");
    write(&dictionary, &image(0));
    let before = fs::read(&dictionary).expect("read dictionary");

    // Overwriting the dictionary would silently replace it with data output;
    // every later run would compress under a "dictionary" that is not one.
    let output = run(&[
        "dict",
        "apply",
        "--dictionary",
        dictionary.to_str().expect("utf8"),
        "--output",
        dictionary.to_str().expect("utf8"),
        input.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("usage:"), "{}", stderr(&output));
    assert_eq!(fs::read(&dictionary).expect("read dictionary"), before);
}

#[test]
fn dict_train_needs_an_output_path() {
    let dir = sandbox("dict-no-output");
    let mut samples = Vec::new();
    for seed in 0..2 {
        let path = dir.join(format!("sample-{seed}.ainf"));
        write(&path, &image(seed));
        samples.push(path.to_string_lossy().into_owned());
    }
    let mut args = vec!["dict".to_string(), "train".to_string()];
    args.extend(samples);
    let reference: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(&reference);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("needs --output"),
        "{}",
        stderr(&output)
    );
    assert!(output.stdout.is_empty(), "no dictionary on stdout");
}

#[test]
fn dict_apply_refuses_an_empty_dictionary() {
    let dir = sandbox("dict-empty");
    let input = dir.join("input.bin");
    write(&input, b"payload bytes");
    let dictionary = dir.join("empty.dict");
    write(&dictionary, b"");

    // An empty dictionary is not a dictionary; zstd would silently compress
    // without one while the command claims otherwise.
    let output = run(&[
        "dict",
        "apply",
        "--dictionary",
        dictionary.to_str().expect("utf8"),
        input.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("must not be empty"),
        "{}",
        stderr(&output)
    );
}

/// A set-but-empty `--key` is a variable that did not expand; treating it as
/// absent would drop the pinned signer and accept any self-consistent envelope.
#[test]
fn store_get_refuses_an_empty_key_and_root() {
    let dir = sandbox("store-empty-flags");
    let path = dir.join("image.ainf");
    write(&path, &image(4));
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

    let get = run(&[
        "store",
        "get",
        &hash,
        "--root",
        root.to_str().expect("utf8"),
        "--verify",
        "--key",
        "",
    ]);
    assert_eq!(get.status.code(), Some(2), "{}", stderr(&get));
    assert!(stderr(&get).contains("usage:"), "{}", stderr(&get));

    let get = run(&[
        "store",
        "get",
        &hash,
        "--root",
        root.to_str().expect("utf8"),
        "--key",
        "",
    ]);
    assert_eq!(get.status.code(), Some(2), "{}", stderr(&get));

    let get = run(&["store", "get", &hash, "--root", ""]);
    assert_eq!(get.status.code(), Some(2), "{}", stderr(&get));
}

/// A usage error must not create a store directory: `.active-store` in a repo
/// root can be committed later.
#[test]
fn a_usage_error_does_not_create_the_store() {
    let dir = sandbox("store-not-created");
    let root = dir.join("never");
    let output = run(&["store", "bogus", "--root", root.to_str().expect("utf8")]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        !root.exists(),
        "the store root was created by a usage error"
    );
}

/// An empty `--schema` would silently disable schema validation.
#[test]
fn proof_refuses_an_empty_schema() {
    let dir = sandbox("proof-empty-schema");
    let image = dir.join("image.ainf");
    write(&image, &image_bytes_for_proof());
    let proof = dir.join("proof.json");
    let issued = run(&[
        "proof",
        "issue",
        image.to_str().expect("utf8"),
        "--schema",
        "",
        "--output",
        proof.to_str().expect("utf8"),
    ]);
    assert_eq!(issued.status.code(), Some(2), "{}", stderr(&issued));
    assert!(stderr(&issued).contains("--schema"), "{}", stderr(&issued));
}

/// An empty `--name` is not a request for the default name.
#[test]
fn encode_refuses_an_empty_name() {
    let dir = sandbox("encode-empty-name");
    let source = dir.join("input.active");
    write(&source, b"port = 8080\n");
    let output = run(&[
        "encode",
        source.to_str().expect("utf8"),
        "--name",
        "",
        "--output",
        dir.join("out.ainf").to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

/// `Path::push` replaces the base for a rooted or prefixed path, so containment
/// must be proved on the canonical result, not on the spelling.
#[test]
fn a_conformance_case_outside_the_base_is_refused() {
    let dir = sandbox("conformance-escape");
    let manifest = dir.join("manifest.json");
    // A rooted path without a prefix is not `is_absolute` on Windows.
    let escape = if cfg!(windows) {
        "\\Windows\\win.ini"
    } else {
        "/etc/passwd"
    };
    write(
        &manifest,
        format!(
            "{{\"format\":\"active-conformance/1\",\"version\":\"test\",\"cases\":[{{\"kind\":\"valid\",\"name\":\"escape\",\"path\":\"{}\",\"expected_code\":\"\",\"sha256\":\"\",\"size\":0}}]}}",
            escape.replace('\\', "\\\\")
        )
        .as_bytes(),
    );
    let output = run(&[
        "conformance",
        "run",
        "--manifest",
        manifest.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let scorecard = stdout(&output);
    assert!(
        scorecard.contains("escapes the manifest directory"),
        "{scorecard}"
    );
}

/// A megabyte manifest can name millions of cases; the run is bounded.
#[test]
fn a_conformance_manifest_over_the_case_cap_is_refused() {
    let dir = sandbox("conformance-cases");
    let manifest = dir.join("manifest.json");
    let cases: Vec<String> = (0..4097)
        .map(|index| {
            format!(
                "{{\"kind\":\"valid\",\"name\":\"c{index}\",\"path\":\"c{index}.ainf\",\"expected_code\":\"\",\"sha256\":\"\",\"size\":0}}"
            )
        })
        .collect();
    write(
        &manifest,
        format!(
            "{{\"format\":\"active-conformance/1\",\"version\":\"test\",\"cases\":[{}]}}",
            cases.join(",")
        )
        .as_bytes(),
    );
    let output = run(&[
        "conformance",
        "run",
        "--manifest",
        manifest.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("at most"), "{}", stderr(&output));
}

/// A bench invocation is bounded by the bytes it processes.
#[test]
fn bench_refuses_more_work_than_the_budget() {
    let dir = sandbox("bench-budget");
    let input = dir.join("input.bin");
    // A 1 MiB image: the iteration count stays under the iteration cap while
    // the product clears the 8 GiB work budget.
    let source = format!("name = \"{}\"\n", "x".repeat(1 << 20));
    let module = from_active_source(&source, "bench.active").expect("parse");
    let bytes = encode(&module).expect("encode");
    write(&input, &bytes);
    let bytes = bytes.len() as u64;
    // Pick an iteration count whose product clears 8 GiB.
    let iterations = (8u64 << 30) / bytes + 2;
    let output = run(&[
        "bench",
        "validate",
        input.to_str().expect("utf8"),
        "--iterations",
        &iterations.to_string(),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("exceed"), "{}", stderr(&output));
}

/// The base is a second root: an absolute base would discard the manifest's
/// own directory.
#[test]
fn a_conformance_manifest_with_an_absolute_base_is_refused() {
    let dir = sandbox("conformance-abs-base");
    let manifest = dir.join("manifest.json");
    let base = if cfg!(windows) {
        "C:\\\\Windows"
    } else {
        "/etc"
    };
    write(
        &manifest,
        format!(
            "{{\"format\":\"active-conformance/1\",\"version\":\"t\",\"base\":\"{}\",\"cases\":[{{\"name\":\"x\",\"kind\":\"invalid\",\"path\":\"passwd\"}}]}}",
            base.replace('\\', "\\\\")
        )
        .as_bytes(),
    );
    let output = run(&[
        "conformance",
        "run",
        "--manifest",
        manifest.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("base"), "{}", stderr(&output));
}

/// An emptied case list must not pass a release gate having verified nothing.
#[test]
fn a_conformance_manifest_with_no_cases_is_refused() {
    let dir = sandbox("conformance-empty");
    let manifest = dir.join("manifest.json");
    write(
        &manifest,
        br#"{"format":"active-conformance/1","version":"t","cases":[]}"#,
    );
    let output = run(&[
        "conformance",
        "run",
        "--manifest",
        manifest.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("no cases"), "{}", stderr(&output));
}

/// Every case is pinned by size and sha256: a substituted vector that still
/// yields the declared error code must fail.
#[test]
fn a_conformance_case_must_match_its_pin() {
    let dir = sandbox("conformance-pin");
    write(&dir.join("case.ainf"), b"not the pinned bytes");
    let manifest = dir.join("manifest.json");
    write(
        &manifest,
        br#"{"format":"active-conformance/1","version":"t","cases":[{"name":"pin","kind":"invalid","path":"case.ainf","expected_code":"infinity/magic","sha256":"0000000000000000000000000000000000000000000000000000000000000000","size":20}]}"#,
    );
    let output = run(&[
        "conformance",
        "run",
        "--manifest",
        manifest.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let scorecard = stdout(&output);
    assert!(scorecard.contains("declared sha256"), "{scorecard}");
    assert!(
        !scorecard.contains(dir.to_str().expect("utf8")),
        "the scorecard leaked the runner's path: {scorecard}"
    );
}

/// A bad seed and an empty sign-file path are usage errors and must not create
/// the store directory.
#[test]
fn store_put_validates_the_seed_before_opening_the_store() {
    let dir = sandbox("store-seed-order");
    let path = dir.join("image.ainf");
    write(&path, &image(6));
    let root = dir.join("never");
    let output = run(&[
        "store",
        "put",
        path.to_str().expect("utf8"),
        "--root",
        root.to_str().expect("utf8"),
        "--sign",
        "zz",
        "--i-accept-argv-key-leak",
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(!root.exists(), "a bad seed created the store root");

    let output = run(&[
        "store",
        "put",
        path.to_str().expect("utf8"),
        "--root",
        root.to_str().expect("utf8"),
        "--sign-file",
        "",
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(!root.exists(), "an empty sign-file created the store root");
}

/// A seed on argv is refused unless the leak is acknowledged, and the refusal
/// happens before the store exists (audit AI-02).
#[test]
fn a_seed_on_argv_needs_the_leak_acknowledgement() {
    let dir = sandbox("argv-seed-gate");
    let path = dir.join("image.ainf");
    write(&path, &image(9));
    let root = dir.join("never");
    let output = run(&[
        "store",
        "put",
        path.to_str().expect("utf8"),
        "--root",
        root.to_str().expect("utf8"),
        "--sign",
        &"01".repeat(32),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("--sign-file"),
        "the refusal must point at --sign-file: {}",
        stderr(&output)
    );
    assert!(!root.exists(), "the refusal created the store root");
}

/// A signing seed file readable by other users is refused (audit AI-02).
#[cfg(unix)]
#[test]
fn a_world_readable_seed_file_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let dir = sandbox("seed-mode");
    let path = dir.join("image.ainf");
    write(&path, &image(10));
    let seed_path = dir.join("seed.txt");
    write(&seed_path, &("02".repeat(32).into_bytes()));
    fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o644)).expect("mode");
    let root = dir.join("store");
    let output = run(&[
        "store",
        "put",
        path.to_str().expect("utf8"),
        "--root",
        root.to_str().expect("utf8"),
        "--sign-file",
        seed_path.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("readable"), "{}", stderr(&output));
    assert!(!root.exists(), "the refusal created the store root");

    fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).expect("mode");
    let output = run(&[
        "store",
        "put",
        path.to_str().expect("utf8"),
        "--root",
        root.to_str().expect("utf8"),
        "--sign-file",
        seed_path.to_str().expect("utf8"),
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
}

/// A signing seed file readable by other users is refused on Windows too
/// (INF-CLI-02 / XPL-INF-04). The Unix mode check has no Windows
/// equivalent — Rust's std exposes no ACL API and this codebase forbids
/// unsafe code — so the CLI refuses `--sign-file` unless
/// `--allow-insecure-seed` is passed.
#[cfg(windows)]
#[test]
fn a_world_readable_seed_file_is_refused_on_windows() {
    let dir = sandbox("seed-acl");
    let path = dir.join("image.ainf");
    write(&path, &image(10));
    let seed_path = dir.join("seed.txt");
    write(&seed_path, &("02".repeat(32).into_bytes()));
    grant_everyone_read(&seed_path);
    let root = dir.join("store");
    let output = run(&[
        "store",
        "put",
        path.to_str().expect("utf8"),
        "--root",
        root.to_str().expect("utf8"),
        "--sign-file",
        seed_path.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("readable"), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("--allow-insecure-seed"),
        "the refusal must name the escape hatch: {}",
        stderr(&output)
    );
    assert!(!root.exists(), "the refusal created the store root");
}

/// `--allow-insecure-seed` is the explicit escape hatch: a world-readable
/// seed file signs when the caller accepts the exposure (INF-CLI-02).
#[test]
fn an_insecure_seed_flag_allows_a_world_readable_seed() {
    let dir = sandbox("seed-flag");
    let path = dir.join("image.ainf");
    write(&path, &image(11));
    let seed_path = dir.join("seed.txt");
    write(&seed_path, &("03".repeat(32).into_bytes()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o644)).expect("mode");
    }
    #[cfg(windows)]
    grant_everyone_read(&seed_path);
    let root = dir.join("store");
    let output = run(&[
        "store",
        "put",
        path.to_str().expect("utf8"),
        "--root",
        root.to_str().expect("utf8"),
        "--sign-file",
        seed_path.to_str().expect("utf8"),
        "--allow-insecure-seed",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("allow-insecure-seed"),
        "the escape hatch must be announced on stderr: {}",
        stderr(&output)
    );
}

/// A hash is hex only: `from_str_radix` accepts a leading `+`.
#[test]
fn a_hash_with_a_sign_is_refused() {
    let dir = sandbox("hash-sign");
    let root = dir.join("store");
    let mut hash = "+0".repeat(32);
    hash.truncate(64);
    let output = run(&[
        "store",
        "get",
        &hash,
        "--root",
        root.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

/// A manifest with another format string is not a conformance pack.
#[test]
fn a_conformance_manifest_with_another_format_is_refused() {
    let dir = sandbox("conformance-format");
    let manifest = dir.join("manifest.json");
    write(
        &manifest,
        br#"{"format":"not-conformance","version":"t","cases":[{"name":"x","kind":"valid","path":"x.ainf"}]}"#,
    );
    let output = run(&[
        "conformance",
        "run",
        "--manifest",
        manifest.to_str().expect("utf8"),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}
