//! Machine-portable performance matrix for the regression gate.
//!
//! Prints JSON with p50/p95/p99 latency for the shipped codec on two module
//! shapes. `scripts/perf_gate.py` turns the numbers into machine-independent
//! checks: tail stability (p95, which tolerates one scheduler hiccup), linear
//! scaling between the shapes, and an optional absolute baseline.
//!
//! ```text
//! cargo run --release --example perf_matrix --all-features
//! ```

use std::hint::black_box;
use std::time::Instant;

use active_infinity::{content_hash, decode, encode, validate, InfinityModule, Inode};

fn fixture(fields: usize) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut table = Vec::with_capacity(fields + 1);
    for index in 0..fields {
        let value = module.push(Inode::Int(index as i64));
        table.push((format!("field-{index}"), value));
    }
    let name = module.push(Inode::Str("perf-matrix".into()));
    table.push(("name".into(), name));
    let root = module.push(Inode::Table { fields: table });
    module.set_root(Some(root));
    module
}

/// (p50, p95, p99) in nanoseconds.
fn measure(mut op: impl FnMut(), iterations: usize) -> (u64, u64, u64) {
    for _ in 0..20 {
        op();
    }
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        op();
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let percentile = |fraction: f64| -> u64 {
        let index = ((samples.len() as f64 - 1.0) * fraction).round() as usize;
        samples[index].as_nanos() as u64
    };
    (percentile(0.50), percentile(0.95), percentile(0.99))
}

fn main() {
    let small = fixture(1_000);
    let large = fixture(10_000);
    let small_image = encode(&small).expect("encode");
    let large_image = encode(&large).expect("encode");

    let mut entries = Vec::new();
    let mut record = |name: &str, op: &mut dyn FnMut(), iterations: usize| {
        let (p50, p95, p99) = measure(op, iterations);
        entries.push(format!(
            "\"{name}\":{{\"p50_ns\":{p50},\"p95_ns\":{p95},\"p99_ns\":{p99}}}"
        ));
    };

    record(
        "encode_1k",
        &mut || {
            black_box(encode(&small).expect("encode"));
        },
        300,
    );
    record(
        "encode_10k",
        &mut || {
            black_box(encode(&large).expect("encode"));
        },
        120,
    );
    record(
        "validate_1k",
        &mut || {
            black_box(validate(&small_image).expect("validate"));
        },
        500,
    );
    record(
        "validate_10k",
        &mut || {
            black_box(validate(&large_image).expect("validate"));
        },
        200,
    );
    record(
        "decode_1k",
        &mut || {
            black_box(decode(&small_image).expect("decode"));
        },
        300,
    );
    record(
        "decode_10k",
        &mut || {
            black_box(decode(&large_image).expect("decode"));
        },
        120,
    );
    record(
        "hash_10k",
        &mut || {
            black_box(content_hash(&large_image).expect("hash"));
        },
        300,
    );

    println!(
        "{{\"schema\":\"active-infinity/perf-matrix/1\",\"host\":{{\"os\":\"{}\",\"arch\":\"{}\"}},\"sizes\":{{\"small_bytes\":{},\"large_bytes\":{}}},\"ops\":{{{}}}}}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        small_image.len(),
        large_image.len(),
        entries.join(",")
    );
}
