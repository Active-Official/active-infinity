//! Public bakeoff skeleton for Active Infinity.
//!
//! Measures the shipped codec on identical module shapes. Competitor adapters
//! are filled in C-7.3; until then they are explicit placeholders so no
//! invented number can be published.

use active_infinity::stream::{apply_delta_in_place, DeltaOp};
use active_infinity::{content_hash, decode, encode, encode_many, validate, InfinityModule, Inode};
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

fn bench_batch(c: &mut Criterion) {
    let modules: Vec<InfinityModule> = (0..32).map(|_| fixture(1_000)).collect();
    let mut group = c.benchmark_group("infinity_batch");
    group.bench_function("encode_loop_32x1k", |b| {
        b.iter(|| {
            let out: Vec<Vec<u8>> = modules
                .iter()
                .map(|module| encode(module).expect("encode"))
                .collect();
            black_box(out.len())
        });
    });
    let mut reused: Vec<Vec<u8>> = Vec::new();
    group.bench_function("encode_many_32x1k", |b| {
        b.iter(|| {
            encode_many(modules.iter(), &mut reused).expect("batch");
            black_box(reused.len())
        });
    });
    group.finish();
}

mod competitors {
    //! Real competitor encoders on the same logical shape: a table of
    //! `fields` string-to-integer entries plus a name.
    //!
    //! FlatBuffers is excluded from the encoded-size and encode-time matrix: a
    //! fair comparison needs schema-generated code, and a hand-written builder
    //! would measure our glue instead of the format. The interop story for
    //! FlatBuffers/Protobuf lives in `docs/spec/performance.md`.
    use std::collections::{BTreeMap, HashMap};

    use prost::Message;

    pub fn pairs(fields: usize) -> BTreeMap<String, i64> {
        (0..fields)
            .map(|index| (format!("field-{index}"), index as i64))
            .collect()
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ProstTable {
        #[prost(map = "string, int64", tag = "1")]
        pub fields: HashMap<String, i64>,
        #[prost(string, tag = "2")]
        pub name: String,
    }

    #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    pub struct RkyvTable {
        pub fields: BTreeMap<String, i64>,
        pub name: String,
    }

    pub fn serde_json_bytes(fields: usize) -> Vec<u8> {
        // Same logical shape as the other adapters: every field plus the name.
        let mut map = serde_json::Map::new();
        for (key, value) in pairs(fields) {
            map.insert(key, serde_json::Value::from(value));
        }
        map.insert("name".to_string(), serde_json::Value::from("bakeoff"));
        serde_json::to_vec(&map).expect("json")
    }

    pub fn prost_bytes(fields: usize) -> Vec<u8> {
        ProstTable {
            fields: pairs(fields).into_iter().collect(),
            name: "bakeoff".to_string(),
        }
        .encode_to_vec()
    }

    pub fn rkyv_bytes(fields: usize) -> Vec<u8> {
        let table = RkyvTable {
            fields: pairs(fields),
            name: "bakeoff".to_string(),
        };
        rkyv::to_bytes::<rkyv::rancor::Error>(&table).expect("rkyv").to_vec()
    }
}

fn bench_competitors(c: &mut Criterion) {
    let mut group = c.benchmark_group("competitors_encode");
    for (name, fields) in [("small", 8usize), ("medium", 1_000), ("large", 10_000)] {
        group.bench_with_input(
            BenchmarkId::new("active-infinity", name),
            &fields,
            |b, fields| {
                b.iter(|| black_box(encode(&fixture(*fields)).expect("encode")));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("serde_json", name),
            &fields,
            |b, fields| b.iter(|| black_box(competitors::serde_json_bytes(*fields))),
        );
        group.bench_with_input(BenchmarkId::new("prost", name), &fields, |b, fields| {
            b.iter(|| black_box(competitors::prost_bytes(*fields)))
        });
        group.bench_with_input(BenchmarkId::new("rkyv", name), &fields, |b, fields| {
            b.iter(|| black_box(competitors::rkyv_bytes(*fields)))
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_infinity,
    bench_delta,
    bench_batch,
    bench_competitors
);
criterion_main!(benches);
