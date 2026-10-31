//! Public bakeoff skeleton for Active Infinity.
//!
//! Measures the shipped codec on identical module shapes. Competitor adapters
//! are filled in C-7.3; until then they are explicit placeholders so no
//! invented number can be published.

use active_infinity::stream::{apply_delta_in_place, DeltaOp};
use active_infinity::{content_hash, decode, encode, validate, InfinityModule, Inode};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};

fn fixture(fields: usize) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut table = Vec::with_capacity(fields.max(3));
    for index in 0..fields.max(3) {
        let value = module.push(Inode::Int(index as i64));
        table.push((format!("field-{index}"), value));
    }
    let name = module.push(Inode::Str("bakeoff".into()));
    table.push(("name".into(), name));
    let root = module.push(Inode::Table { fields: table });
    module.set_root(Some(root));
    module
}

fn bench_infinity(c: &mut Criterion) {
    let mut group = c.benchmark_group("infinity_bakeoff");
    for (name, fields) in [("small", 8usize), ("medium", 1_000), ("large", 10_000)] {
        let module = fixture(fields);
        let image = encode(&module).expect("encode");
        group.bench_with_input(BenchmarkId::new("encode", name), &module, |b, module| {
            b.iter(|| black_box(encode(module).expect("encode")));
        });
        group.bench_with_input(BenchmarkId::new("validate", name), &image, |b, image| {
            b.iter(|| black_box(validate(image).expect("validate")));
        });
        group.bench_with_input(BenchmarkId::new("decode", name), &image, |b, image| {
            b.iter(|| black_box(decode(image).expect("decode")));
        });
        group.bench_with_input(BenchmarkId::new("hash", name), &image, |b, image| {
            b.iter(|| black_box(content_hash(image).expect("hash")));
        });
    }
    group.finish();
}

fn bench_delta(c: &mut Criterion) {
    let mut module = InfinityModule::new();
    let mut fields = Vec::new();
    for index in 0..10_000 {
        let value = module.push(Inode::Int(index));
        fields.push((format!("field-{index}"), value));
    }
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));
    let target = active_infinity::ir::NodeId(9_999);
    let mut fragment = InfinityModule::new();
    let new_value = fragment.push(Inode::Int(-1));
    fragment.set_root(Some(new_value));
    let ops = [DeltaOp::PutNode {
        target,
        fragment: Box::new(fragment),
    }];
    c.bench_function("delta_patch_large_10k", |b| {
        b.iter_batched(
            || module.clone(),
            |mut patched| {
                apply_delta_in_place(&mut patched, &ops).expect("delta");
                black_box(encode(&patched).expect("encode"))
            },
            BatchSize::SmallInput,
        );
    });
}

#[allow(dead_code)]
mod competitors {
    //! Adapters land in C-7.3 with the same logical module shape.
    //! TODO(CHECKLIST C-7.3): serde_json, prost, flatbuffers and rkyv adapters.

    pub fn serde_json_encode() -> Option<Vec<u8>> {
        None
    }

    pub fn prost_encode() -> Option<Vec<u8>> {
        None
    }

    pub fn flatbuffers_encode() -> Option<Vec<u8>> {
        None
    }

    pub fn rkyv_encode() -> Option<Vec<u8>> {
        None
    }
}

criterion_group!(benches, bench_infinity, bench_delta);
criterion_main!(benches);
