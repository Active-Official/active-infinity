//! Criterion benchmarks for the canonical codec.
//!
//! Run with `cargo bench`. Baselines are recorded in `docs/spec/performance.md`.
//! The matrix covers wide modules (many sibling tables) and deep modules (a
//! chain of tables), because the two shapes stress different bounds: table
//! sorting and string dedup on the wide side, depth accounting and DFS on the
//! deep side. Each fixture carries a secret, annotations and provenance so the
//! redaction path is exercised in the same image that is measured.

use std::hint::black_box;

use active_infinity::{
    encode, validate, AnnotationKind, DecodeOpts, InfinityModule, InfinityView, Inode, Limits,
    NodeId, ProvEntry, ProvValue, Provenance, UnitTag,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn finish(module: &mut InfinityModule, root: NodeId) {
    module.set_root(Some(root));
    module.bind("root", root);
    let secret = module.push(Inode::Secret(active_infinity::SecretBytes::from(
        "super-secret-token",
    )));
    module.annotate(root, AnnotationKind::Intent("benchmark fixture".into()));
    module.annotate(secret, AnnotationKind::AiImmutable(true));
    module.set_provenance(Some(Provenance {
        producer: Some("criterion".into()),
        timestamp_ms: 1_700_000_000_000,
        model: Some("none".into()),
        tool: Some("active-infinity/bench".into()),
        parent: None,
        entries: vec![ProvEntry {
            key: "run".into(),
            value: ProvValue::Text("baseline".into()),
        }],
    }));
}

fn wide_module(fields: usize) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut table_fields = Vec::new();
    for index in 0..fields {
        let name = module.push(Inode::Str(format!("service-{index:04}")));
        let port = module.push(Inode::Int(8000 + index as i64));
        let number = module.push(Inode::Int(index as i64));
        let budget = module.push(Inode::Quantity {
            value: number,
            unit: UnitTag::Milliseconds,
        });
        let flags = {
            let mut elements = Vec::new();
            for flag in 0..4 {
                let literal = module.push(Inode::Str(format!("flag-{flag}")));
                elements.push(literal);
            }
            module.push(Inode::Array { elements })
        };
        let entry = module.push(Inode::Table {
            fields: vec![
                ("name".into(), name),
                ("port".into(), port),
                ("budget".into(), budget),
                ("flags".into(), flags),
            ],
        });
        table_fields.push((format!("service_{index:04}"), entry));
    }
    let root = module.push(Inode::Table {
        fields: table_fields,
    });
    finish(&mut module, root);
    module
}

fn deep_module(depth: usize) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut child = module.push(Inode::Int(1));
    for index in 0..depth {
        let label = module.push(Inode::Str(format!("level-{index:04}")));
        child = module.push(Inode::Table {
            fields: vec![("label".into(), label), ("next".into(), child)],
        });
    }
    finish(&mut module, child);
    module
}

fn bench_module(criterion: &mut Criterion, shape: &str, module: InfinityModule, bytes: Vec<u8>) {
    let mut group = criterion.benchmark_group(format!("codec/{shape}"));
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    let nodes = module.node_count();

    group.bench_function(BenchmarkId::new("encode", nodes), |bencher| {
        bencher.iter(|| black_box(encode(black_box(&module)).expect("encode")));
    });
    group.bench_function(BenchmarkId::new("decode", nodes), |bencher| {
        bencher.iter(|| black_box(active_infinity::decode(black_box(&bytes)).expect("decode")));
    });
    group.bench_function(BenchmarkId::new("validate", nodes), |bencher| {
        bencher.iter(|| black_box(validate(black_box(&bytes)).expect("validate")));
    });
    group.bench_function(BenchmarkId::new("view", nodes), |bencher| {
        bencher.iter(|| {
            let view = InfinityView::with_opts(
                black_box(&bytes),
                DecodeOpts {
                    limits: Limits::default(),
                    verify_hash: true,
                    verify_canonical: false,
                },
            )
            .expect("view");
            black_box((view.node_count(), view.content_hash()))
        });
    });
    group.finish();
}

fn benchmarks(criterion: &mut Criterion) {
    for fields in [64usize, 256, 1024] {
        let module = wide_module(fields);
        let bytes = encode(&module).expect("encode");
        eprintln!(
            "wide/{fields}: {} nodes, {} bytes",
            module.node_count(),
            bytes.len()
        );
        bench_module(criterion, &format!("wide-{fields}"), module, bytes);
    }
    for depth in [32usize, 128, 512] {
        let module = deep_module(depth);
        let bytes = encode(&module).expect("encode");
        eprintln!(
            "deep/{depth}: {} nodes, {} bytes",
            module.node_count(),
            bytes.len()
        );
        bench_module(criterion, &format!("deep-{depth}"), module, bytes);
    }
}

/// Hash formatting sits on every content address, receipt and log head.
///
/// The formatter used to call `format!` once per byte (32 allocations per
/// hash); this group keeps the one-allocation version honest.
fn bench_hash_text(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("hash_text");
    let hash =
        active_infinity::content_hash(&encode(&wide_module(64)).expect("encode")).expect("hash");
    group.bench_function("hash_hex", |bencher| {
        bencher.iter(|| black_box(active_infinity::ir::hash_hex(black_box(&hash))));
    });
    let text = active_infinity::ir::hash_hex(&hash);
    group.bench_function("parse_hash_hex", |bencher| {
        bencher.iter(|| black_box(active_infinity::ir::parse_hash_hex(black_box(&text))));
    });
    group.finish();
}

criterion_group!(benches, benchmarks, bench_hash_text);
criterion_main!(benches);
