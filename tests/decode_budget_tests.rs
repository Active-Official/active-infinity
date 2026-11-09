//! Regression tests for the decoded-output budget (INF-01, R2-INF-DEC-01).
//!
//! `decode_validated` refuses an image whose materialised form would exceed
//! `Limits::max_decoded_bytes` (default 256 MiB), charging every cloned byte
//! per use — a string referenced by N nodes is charged N times, and a
//! type-enum member is charged once per `SchemaField` that names the type.
//! `validate()` (no materialisation) is unaffected: every image refused
//! here still validates.
//!
//! The discriminating tests use a tight budget between the naive
//! per-string charge and the true materialised size, so they fail if the
//! accounting ever regresses to counting direct references only.

use active_infinity::{
    decode, decode_with, encode, validate, DecodeOpts, InfinityModule, Inode, Limits, ProvEntry,
    ProvValue, Provenance, SchemaFieldSpec, SecretBytes, TypeSpec, UnitTag,
};

/// `DecodeOpts` identical to the default except for the decoded-bytes budget.
fn with_budget(max_decoded_bytes: u64) -> DecodeOpts {
    DecodeOpts {
        limits: Limits {
            max_decoded_bytes,
            ..Limits::default()
        },
        verify_hash: true,
        verify_canonical: false,
    }
}

fn assert_limit(err: &active_infinity::Error) {
    assert_eq!(
        err.code(),
        "infinity/limit",
        "expected infinity/limit, got {err}"
    );
}

/// One 64 KiB string referenced by `n` `Str` nodes under one array root.
/// The encoder interns the string once, so the image stays small while the
/// decoded form is `n * 64 KiB`.
fn shared_string_image(n: u32) -> Vec<u8> {
    let shared = "s".repeat(64 * 1024);
    let mut module = InfinityModule::new();
    let mut elems = Vec::with_capacity(n as usize);
    for _ in 0..n {
        elems.push(module.push(Inode::Str(shared.clone())));
    }
    let root = module.push(Inode::Array { elements: elems });
    module.set_root(Some(root));
    encode(&module).expect("encode shared-string module")
}

#[test]
fn inf01_shared_string_refused_at_default_budget() {
    // W4's 1091x point, scaled past the boundary: 5000 x 64 KiB =
    // 327,680,000 decoded bytes from a ~246 KiB image, over the 256 MiB
    // default budget. The audit's own 852x point (2000 x 64 KiB = 131 MB)
    // is under the absolute default budget and still decodes — the budget
    // bounds absolute output, not the ratio (see the tight-budget test).
    let image = shared_string_image(5000);
    assert!(
        image.len() < 400_000,
        "image must stay small: {}",
        image.len()
    );
    validate(&image).expect("the bomb image is structurally valid");
    assert_limit(&decode(&image).expect_err("default decode must refuse"));
}

#[test]
fn inf01_shared_string_allowed_when_budget_raised() {
    let image = shared_string_image(5000);
    let decoded = decode_with(&image, with_budget(512 << 20)).expect("raised budget decodes");
    let mut decoded_bytes = 0usize;
    for node in decoded.nodes() {
        if let Inode::Str(s) = node {
            decoded_bytes += s.len();
        }
    }
    assert_eq!(decoded_bytes, 5000 * 64 * 1024);
}

#[test]
fn inf01_tight_budget_refuses_modest_amplification() {
    // The audit's 852x point: 2000 x 64 KiB = 131,072,000 decoded bytes.
    // A 1 MiB budget refuses it; the gate trips long before any cloning.
    let image = shared_string_image(2000);
    validate(&image).expect("the image is structurally valid");
    assert_limit(
        &decode_with(&image, with_budget(1 << 20))
            .expect_err("a 1 MiB budget must refuse 131 MB of strings"),
    );
    // ... and the same image still decodes under the default budget.
    assert!(decode(&image).is_ok());
}

#[test]
fn r2_dec01_type_enum_fanout_charged_per_schema_field() {
    // R2-INF-DEC-01, second leg (r2_dec_01b): one interned enum type whose
    // single member is 64 KiB, referenced by 2000 `SchemaField` nodes. The
    // member string is directly referenced exactly once in the whole image
    // (one aux entry of one interned type), so a per-string budget would
    // charge 64 KiB — while decode clones it 2000 times (131 MB). The
    // 1 MiB budget sits between those two numbers: it trips only if the
    // type fan-out is charged per referencing node.
    const N: usize = 2000;
    const BIG_LEN: usize = 64 * 1024;
    let big = "x".repeat(BIG_LEN);
    let mut module = InfinityModule::new();
    let mut fields: Vec<(String, active_infinity::NodeId)> = Vec::with_capacity(N);
    for i in 0..N {
        let id = module.push(Inode::SchemaField(SchemaFieldSpec::bare(TypeSpec::Enum(
            vec![big.clone(), "b".to_string()],
        ))));
        fields.push((format!("f{i:04}"), id));
    }
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode schema-field module");
    let meta = validate(&image).expect("validate schema-field image");
    assert_eq!(meta.types, 1, "the enum type must be interned to one entry");
    assert!(image.len() < 400_000, "image stays small: {}", image.len());
    assert_limit(
        &decode_with(&image, with_budget(1 << 20))
            .expect_err("a 1 MiB budget must refuse 131 MB of per-field enum clones"),
    );
}

#[test]
fn r2_dec01_type_enum_allowed_when_budget_raised() {
    const N: usize = 2000;
    const BIG_LEN: usize = 64 * 1024;
    let big = "x".repeat(BIG_LEN);
    let mut module = InfinityModule::new();
    let mut fields: Vec<(String, active_infinity::NodeId)> = Vec::with_capacity(N);
    for i in 0..N {
        let id = module.push(Inode::SchemaField(SchemaFieldSpec::bare(TypeSpec::Enum(
            vec![big.clone(), "b".to_string()],
        ))));
        fields.push((format!("f{i:04}"), id));
    }
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode schema-field module");
    let decoded = decode_with(&image, with_budget(256 << 20)).expect("raised budget decodes");
    let mut materialised: u64 = 0;
    for node in decoded.nodes() {
        if let Inode::SchemaField(spec) = node {
            if let TypeSpec::Enum(members) = &spec.typ {
                materialised += members.iter().map(|s| s.len() as u64).sum::<u64>();
            }
        }
    }
    assert_eq!(materialised, (N as u64) * (BIG_LEN as u64 + 1));
}

#[test]
fn inf01_blob_payload_charged_per_blob_node() {
    // One 64 KiB payload shared by 100 `Blob` nodes: 6,553,600 decoded
    // payload bytes (plus media types) from one heap entry.
    let payload = vec![0xABu8; 64 * 1024];
    // The encoder verifies the declared hash against the payload.
    let hash = *blake3::hash(&payload).as_bytes();
    let mut module = InfinityModule::new();
    let mut elems = Vec::new();
    for _ in 0..100u32 {
        elems.push(module.push(Inode::Blob {
            hash,
            size: payload.len() as u64,
            tainted: false,
            media_type: "application/octet-stream".to_string(),
            payload: Some(payload.clone()),
        }));
    }
    let root = module.push(Inode::Array { elements: elems });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode shared-blob module");
    validate(&image).expect("the image is structurally valid");
    assert_limit(
        &decode_with(&image, with_budget(1 << 20))
            .expect_err("a 1 MiB budget must refuse 6.5 MB of blob payloads"),
    );
    assert!(decode(&image).is_ok());
}

#[test]
fn inf01_unit_name_charged_per_quantity_node() {
    // One 32 KiB named unit shared by 1000 `Quantity` nodes: 32,768,000
    // decoded name bytes (round-1 text: "a 64 KiB unit name x 100k
    // Quantity nodes").
    let name = "u".repeat(32 * 1024);
    let mut module = InfinityModule::new();
    let mut elems = Vec::new();
    for i in 0..1000u32 {
        let v = module.push(Inode::Int(i as i64));
        elems.push(module.push(Inode::Quantity {
            value: v,
            unit: UnitTag::Named(name.clone()),
        }));
    }
    let root = module.push(Inode::Array { elements: elems });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode shared-unit module");
    validate(&image).expect("the image is structurally valid");
    assert_limit(
        &decode_with(&image, with_budget(1 << 20))
            .expect_err("a 1 MiB budget must refuse 32 MB of unit names"),
    );
    assert!(decode(&image).is_ok());
}

#[test]
fn inf01_table_field_name_charged_per_field() {
    // One 16 KiB field name shared by 500 one-field tables: 8,388,608
    // decoded name bytes.
    let name = "f".repeat(16 * 1024);
    let mut module = InfinityModule::new();
    let mut tables = Vec::new();
    for i in 0..500u32 {
        let v = module.push(Inode::Int(i as i64));
        tables.push(module.push(Inode::Table {
            fields: vec![(name.clone(), v)],
        }));
    }
    let root = module.push(Inode::Array { elements: tables });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode shared-field-name module");
    validate(&image).expect("the image is structurally valid");
    assert_limit(
        &decode_with(&image, with_budget(1 << 20))
            .expect_err("a 1 MiB budget must refuse 8 MB of field names"),
    );
    assert!(decode(&image).is_ok());
}

#[test]
fn inf01_annotation_string_charged_per_annotation() {
    // One 16 KiB intent string on 500 nodes: 8,388,608 decoded bytes.
    let text = "a".repeat(16 * 1024);
    let mut module = InfinityModule::new();
    let mut ids = Vec::new();
    for _ in 0..500 {
        ids.push(module.push(Inode::Null));
    }
    for &id in &ids {
        module.annotate(id, active_infinity::AnnotationKind::Intent(text.clone()));
    }
    module.set_root(Some(ids[0]));
    let image = encode(&module).expect("encode shared-annotation module");
    validate(&image).expect("the image is structurally valid");
    assert_limit(
        &decode_with(&image, with_budget(1 << 20))
            .expect_err("a 1 MiB budget must refuse 8 MB of annotation strings"),
    );
    assert!(decode(&image).is_ok());
}

#[test]
fn inf01_secret_payload_charged_per_secret_node() {
    // 100 distinct 64 KiB secrets: 6,553,600 decoded bytes. Secrets are
    // not shared between nodes (each node has its own table entry), so this
    // pins the per-node secret charge rather than fan-out.
    let mut module = InfinityModule::new();
    let mut elems = Vec::new();
    for i in 0..100u32 {
        let mut payload = vec![0u8; 64 * 1024];
        payload[0] = i as u8;
        elems.push(module.push(Inode::Secret(SecretBytes::new(payload))));
    }
    let root = module.push(Inode::Array { elements: elems });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode secret module");
    validate(&image).expect("the image is structurally valid");
    assert_limit(
        &decode_with(&image, with_budget(1 << 20))
            .expect_err("a 1 MiB budget must refuse 6.5 MB of secrets"),
    );
    assert!(decode(&image).is_ok());
}

#[test]
fn inf01_provenance_strings_charged_per_entry() {
    // 100 provenance entries sharing one 64 KiB `Text` value: 6,553,600
    // decoded bytes from one heap entry.
    let shared = "p".repeat(64 * 1024);
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Null);
    module.set_root(Some(root));
    module.set_provenance(Some(Provenance {
        producer: Some("budget-test".to_string()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: None,
        entries: (0..100)
            .map(|i| ProvEntry {
                key: format!("k{i:03}"),
                value: ProvValue::Text(shared.clone()),
            })
            .collect(),
    }));
    let image = encode(&module).expect("encode provenance module");
    validate(&image).expect("the image is structurally valid");
    assert_limit(
        &decode_with(&image, with_budget(1 << 20))
            .expect_err("a 1 MiB budget must refuse 6.5 MB of provenance text"),
    );
    assert!(decode(&image).is_ok());
}

#[test]
fn inf01_small_shared_strings_still_decode() {
    // The budget must not refuse ordinary sharing: 100 x 1 KiB = 100 KiB
    // decoded, far under every profile including `Limits::strict()`.
    let shared = "s".repeat(1024);
    let mut module = InfinityModule::new();
    let mut elems = Vec::new();
    for _ in 0..100u32 {
        elems.push(module.push(Inode::Str(shared.clone())));
    }
    let root = module.push(Inode::Array { elements: elems });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode small shared-string module");
    let strict = DecodeOpts {
        limits: Limits::strict(),
        verify_hash: true,
        verify_canonical: false,
    };
    assert!(decode(&image).is_ok());
    assert!(decode_with(&image, strict).is_ok());
}
