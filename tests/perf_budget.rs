//! Performance and availability budgets.
//!
//! These are deliberately generous: the point is to catch a super-linear
//! regression or an unbounded allocation, not to benchmark a specific machine.
//! Numbers and methodology live in `docs/spec/performance.md`.

use std::time::{Duration, Instant};

use active_infinity::{encode, validate, InfinityModule, Inode};

fn wide(fields: u32) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut table = Vec::with_capacity(fields as usize);
    for index in 0..fields {
        let node = module.push(Inode::Int(index as i64));
        table.push((format!("f{index:05}"), node));
    }
    let root = module.push(Inode::Table { fields: table });
    module.set_root(Some(root));
    module
}

fn measure(bytes: &[u8], runs: u32) -> Duration {
    let start = Instant::now();
    for _ in 0..runs {
        validate(bytes).expect("valid image");
    }
    start.elapsed() / runs
}

#[test]
fn validation_scales_linearly() {
    let small = encode(&wide(1_000)).expect("small");
    let large = encode(&wide(20_000)).expect("large");
    assert!(validate(&small).is_ok());
    assert!(validate(&large).is_ok());
    let t_small = measure(&small, 5);
    let t_large = measure(&large, 3);
    // 20x the nodes must not cost 60x the time. The generous factor tolerates a
    // noisy CI runner while still catching quadratic traversal.
    let budget = t_small * 60 + Duration::from_millis(100);
    assert!(
        t_large <= budget,
        "validation scaled worse than linear: 1k={t_small:?} 20k={t_large:?}"
    );
}

#[test]
fn hostile_rejection_is_bounded() {
    let bomb = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/invalid/count_bomb.ainf"),
    )
    .expect("vector");
    let start = Instant::now();
    for _ in 0..1_000 {
        assert!(validate(&bomb).is_err());
    }
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "1000 count-bomb rejections took {:?}",
        start.elapsed()
    );
}

/// Resident set size of this process, in KiB. XPL-INF-07: the test exists
/// on every platform — Linux reads /proc, Windows reads the Working Set,
/// macOS reads `ps`. A helper that cannot measure must fail closed, not
/// return a number that would pass vacuously.
#[cfg(target_os = "linux")]
fn rss_kib() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").expect("statm");
    let pages: u64 = statm.split_whitespace().nth(1).unwrap().parse().unwrap();
    pages * 4
}

/// Working Set — the Windows RSS equivalent — of this process, in KiB.
#[cfg(target_os = "windows")]
fn rss_kib() -> u64 {
    let script = format!("(Get-Process -Id {}).WorkingSet64", std::process::id());
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .expect("spawn powershell");
    assert!(
        output.status.success(),
        "Get-Process failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes: u64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("WorkingSet64 is a number");
    bytes / 1024
}

/// Resident set size of this process, in KiB (`ps` reports KiB already).
#[cfg(target_os = "macos")]
fn rss_kib() -> u64 {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .expect("spawn ps");
    assert!(
        output.status.success(),
        "ps failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("rss is a number")
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn rss_kib() -> u64 {
    // No memory query exists for this platform; fail closed with the
    // documented reason rather than returning a number that would pass.
    panic!(
        "XPL-INF-07: no RSS measurement exists for this target; the growth budget is untested here"
    );
}

#[test]
fn repeated_validation_does_not_grow_rss() {
    let image = encode(&wide(2_000)).expect("image");
    for _ in 0..1_000 {
        validate(&image).expect("warmup");
    }
    let before = rss_kib();
    for _ in 0..20_000 {
        validate(&image).expect("cycle");
    }
    let after = rss_kib();
    assert!(
        after < before + 65_536,
        "RSS grew from {before} KiB to {after} KiB over 20k validations"
    );
}

#[test]
fn projection_budget_fails_fast_on_a_shared_dag() {
    let mut module = InfinityModule::new();
    let mut current = module.push(Inode::Int(1));
    for _ in 0..24 {
        let left = module.push(Inode::Ref(current));
        let right = module.push(Inode::Ref(current));
        current = module.push(Inode::Table {
            fields: vec![("l".into(), left), ("r".into(), right)],
        });
    }
    module.set_root(Some(current));
    let start = Instant::now();
    let error = active_infinity::to_protobuf(&module).expect_err("budget must fire");
    // A budget is a limit, like the byte and redaction ceilings beside it; only
    // the depth refusal is an encoding fault (`docs/spec/projection.md` §5).
    assert_eq!(error.code(), "infinity/limit");
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "the budget fired after {:?}",
        start.elapsed()
    );
}

#[test]
fn stream_reassembly_rejects_truncation_in_bounded_time() {
    use active_infinity::stream::{decode_stream, StreamEncoder};

    let module = wide(2_000);
    let stream = StreamEncoder::new(&module, 256).expect("stream").to_bytes();
    let truncated = &stream[..stream.len() / 2];
    let start = Instant::now();
    for _ in 0..200 {
        assert!(decode_stream(truncated).is_err());
    }
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "200 truncated stream decodes took {:?}",
        start.elapsed()
    );
}
