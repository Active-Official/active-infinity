//! Criterion benchmarks for the canonical codec.
//!
//! Run with `cargo bench`. Baselines are recorded in `docs/spec/performance.md`.
//! The benchmark builds a representative module (nested tables, arrays,
//! quantities, strings, a secret, annotations and provenance) once, then
//! measures encode, decode, validate-only and zero-copy view construction.

use std::hint::black_box;

use active_infinity::{
    encode, validate, AnnotationKind, DecodeOpts, InfinityModule, InfinityView, Inode, Limits,
    ProvEntry, ProvValue, Provenance, UnitTag,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn sample_module(fields: usize) -> InfinityModule {
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
    module
}

fn benchmarks(criterion: &mut Criterion) {
    let module = sample_module(256);
    let bytes = encode(&module).expect("encode");
    eprintln!(
        "fixture: {} nodes, {} bytes",
        module.node_count(),
        bytes.len()
    );

    let mut group = criterion.benchmark_group("codec");
    group.throughput(Throughput::Bytes(bytes.len() as u64));

    group.bench_function(BenchmarkId::new("encode", module.node_count()), |bencher| {
        bencher.iter(|| black_box(encode(black_box(&module)).expect("encode")));
    });
    group.bench_function(BenchmarkId::new("decode", module.node_count()), |bencher| {
        bencher.iter(|| black_box(active_infinity::decode(black_box(&bytes)).expect("decode")));
    });
    group.bench_function(
        BenchmarkId::new("validate", module.node_count()),
        |bencher| {
            bencher.iter(|| black_box(validate(black_box(&bytes)).expect("validate")));
        },
    );
    group.bench_function(BenchmarkId::new("view", module.node_count()), |bencher| {
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

criterion_group!(benches, benchmarks);
criterion_main!(benches);
