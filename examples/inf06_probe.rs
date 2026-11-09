//! INF-06 probe child: validate one image file and report peak RSS.
//!
//! The parent test (`tests/working_budget_tests.rs`) builds a max-shape image,
//! writes it to a temp file, and runs this binary as a subprocess so the peak
//! RSS it reports covers *only* the validate call — the test process itself
//! holds the image bytes and other tests' allocations, so an in-process peak
//! would be meaningless.
//!
//! Usage: `inf06_probe <image-path> [--structural | --canonical]`
//!
//! * `--structural` (default): `validate_with` with `verify_canonical: false`
//!   — the structural validator only. This is the leg the INF-06 fix changes
//!   (`check_edges` streaming + the `max_working_bytes` budget); the
//!   canonical proof is a separate decode+encode allocation story (its decode
//!   side is bounded by INF-01's `max_decoded_bytes`, its encode side builds
//!   a second full image) and is measured only as an informational `--canonical`
//!   run, not asserted here.
//! * `--canonical`: default `validate()` (proof on).
//!
//! Output (stdout, one `key=value` per line):
//! ```text
//! result=ok
//! result=err:infinity/edge-set
//! input_bytes=637534208
//! baseline_kib=12345
//! peak_kib=789012
//! validate_ms=1234
//! ```
//!
//! Peak RSS is the process high-water mark, so it catches a transient that is
//! freed before exit: Windows reads `PeakWorkingSet64`, Linux reads `VmHWM`
//! from `/proc/self/status`. Any other platform fails closed with a clear
//! message (the repo's own `tests/perf_budget.rs` precedent: a helper that
//! cannot measure must fail, not return a number that would pass vacuously).

use std::io::Write;
use std::time::Instant;

use active_infinity::{validate, validate_with, DecodeOpts};

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| {
        eprintln!("usage: inf06_probe <image-path> [--structural | --canonical]");
        std::process::exit(2);
    });
    let mut canonical = false;
    for arg in args {
        match arg.as_str() {
            "--structural" => canonical = false,
            "--canonical" => canonical = true,
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let bytes = std::fs::read(&path).unwrap_or_else(|err| {
        eprintln!("cannot read {path}: {err}");
        std::process::exit(2);
    });
    let input_bytes = bytes.len();

    let baseline_kib = rss_current_kib();
    let start = Instant::now();
    let result = if canonical {
        validate(&bytes)
    } else {
        validate_with(
            &bytes,
            DecodeOpts {
                verify_canonical: false,
                ..DecodeOpts::default()
            },
        )
    };
    let validate_ms = start.elapsed().as_millis();
    // Peak *after* the call: the high-water mark covers the transient even
    // though every Vec the validator built is already freed.
    let peak_kib = rss_peak_kib();

    let mut out = std::io::stdout().lock();
    match &result {
        Ok(_) => writeln!(out, "result=ok").unwrap(),
        Err(err) => writeln!(out, "result=err:{}", err.code()).unwrap(),
    }
    writeln!(out, "input_bytes={input_bytes}").unwrap();
    writeln!(out, "baseline_kib={baseline_kib}").unwrap();
    writeln!(out, "peak_kib={peak_kib}").unwrap();
    writeln!(out, "validate_ms={validate_ms}").unwrap();
}

/// Current RSS of this process, in KiB.
fn rss_current_kib() -> u64 {
    #[cfg(target_os = "windows")]
    {
        let script = format!("(Get-Process -Id {}).WorkingSet64", std::process::id());
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .expect("spawn powershell for WorkingSet64");
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
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("VmRSS:") {
                return value
                    .trim()
                    .strip_suffix(" kB")
                    .expect("VmRSS unit")
                    .trim()
                    .parse()
                    .expect("VmRSS is a number");
            }
        }
        panic!("/proc/self/status has no VmRSS line");
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        panic!(
            "INF-06: no RSS measurement exists for this target; the probe refuses to report a number it cannot measure"
        );
    }
}

/// Peak (high-water) RSS of this process, in KiB.
fn rss_peak_kib() -> u64 {
    #[cfg(target_os = "windows")]
    {
        let script = format!("(Get-Process -Id {}).PeakWorkingSet64", std::process::id());
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .expect("spawn powershell for PeakWorkingSet64");
        assert!(
            output.status.success(),
            "Get-Process failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes: u64 = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .expect("PeakWorkingSet64 is a number");
        bytes / 1024
    }
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("VmHWM:") {
                return value
                    .trim()
                    .strip_suffix(" kB")
                    .expect("VmHWM unit")
                    .trim()
                    .parse()
                    .expect("VmHWM is a number");
            }
        }
        panic!("/proc/self/status has no VmHWM line");
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        panic!(
            "INF-06: no peak-RSS measurement exists for this target; the probe refuses to report a number it cannot measure"
        );
    }
}
