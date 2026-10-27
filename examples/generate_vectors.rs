//! Generate the checked-in conformance vector set.
//!
//! Run with `cargo run --example generate_vectors`. The output is committed:
//! `tests/vectors/valid/*.ainf` (canonical images) and
//! `tests/vectors/invalid/*.ainf` (one declared fault each), with an
//! `index.txt` per directory giving the expected hash or error code.
//!
//! Vectors are generated from the shipped encoder, so a change in canonical
//! form shows up as a diff in this directory — the intent of a conformance set.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use active_infinity::{
    encode, hash_image, AnnotationKind, InfinityModule, Inode, ProvEntry, ProvValue, Provenance,
    Section, TypeSpec, UnitTag,
};

fn valid_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("conformance".into()));
    let port = module.push(Inode::Int(8080));
    let rate = {
        let number = module.push(Inode::Float(2.5));
        module.push(Inode::Quantity {
            value: number,
            unit: UnitTag::RequestsPerSecond,
        })
    };
    let custom = {
        let number = module.push(Inode::Int(7));
        module.push(Inode::Quantity {
            value: number,
            unit: UnitTag::Named("widgets".into()),
        })
    };
    let secret = module.push(Inode::Secret(active_infinity::SecretBytes::from(
        "vector-secret",
    )));
    let flags = {
        let a = module.push(Inode::Bool(true));
        let b = module.push(Inode::Null);
        module.push(Inode::Array {
            elements: vec![a, b],
        })
    };
    let schema = module.push(Inode::SchemaField(active_infinity::SchemaFieldSpec {
        typ: TypeSpec::Table { closed: true },
        ..active_infinity::SchemaFieldSpec::bare(TypeSpec::Table { closed: true })
    }));
    let root = module.push(Inode::Table {
        fields: vec![
            ("name".into(), name),
            ("port".into(), port),
            ("rate".into(), rate),
            ("custom".into(), custom),
            ("secret".into(), secret),
            ("flags".into(), flags),
            ("schema".into(), schema),
        ],
    });
    module.set_root(Some(root));
    module.bind("root", root);
    module.annotate(root, AnnotationKind::Intent("conformance fixture".into()));
    module.annotate(root, AnnotationKind::AiImmutable(true));
    module.set_provenance(Some(Provenance {
        producer: Some("generate_vectors".into()),
        timestamp_ms: 1_700_000_000_000,
        model: None,
        tool: Some("active-infinity".into()),
        parent: Some([4u8; 32]),
        entries: vec![ProvEntry {
            key: "kind".into(),
            value: ProvValue::Text("conformance".into()),
        }],
    }));
    module
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    let valid_dir = root.join("valid");
    let invalid_dir = root.join("invalid");
    fs::create_dir_all(&valid_dir).expect("valid dir");
    fs::create_dir_all(&invalid_dir).expect("invalid dir");

    // ---- valid --------------------------------------------------------
    let empty = InfinityModule::new();
    let simple = {
        let mut module = InfinityModule::new();
        let text = module.push(Inode::Str("hello".into()));
        let number = module.push(Inode::Int(42));
        let root = module.push(Inode::Table {
            fields: vec![("greeting".into(), text), ("answer".into(), number)],
        });
        module.set_root(Some(root));
        module
    };
    let fixtures: BTreeMap<&str, InfinityModule> = [
        ("empty", empty),
        ("simple", simple),
        ("full", valid_module()),
    ]
    .into_iter()
    .collect();
    let mut index = String::from("# name total_size content_hash nodes strings blobs\n");
    for (name, module) in &fixtures {
        let bytes = encode(module).expect("encode");
        fs::write(valid_dir.join(format!("{name}.ainf")), &bytes).expect("write");
        let meta = active_infinity::validate(&bytes).expect("validate");
        index.push_str(&format!(
            "{name} {} {} {} {} {}\n",
            meta.total_size,
            active_infinity::ir::hash_hex(&meta.content_hash),
            meta.nodes,
            meta.strings,
            meta.blobs
        ));
    }
    fs::write(valid_dir.join("index.txt"), index).expect("index");

    // ---- invalid ------------------------------------------------------
    // Each vector has exactly one declared fault; where the fault is not a
    // hash fault, the stored hash is recomputed so the intended check fires.
    let base = encode(&valid_module()).expect("encode");
    let mut vectors: Vec<(&str, &str, Vec<u8>)> = Vec::new();

    let mut bad_magic = base.clone();
    bad_magic[0] = b'X';
    vectors.push(("bad_magic", "infinity/magic", bad_magic));

    let mut bad_major = base.clone();
    bad_major[4] = 9;
    vectors.push(("bad_major", "infinity/version-major", bad_major));

    let mut bad_minor = base.clone();
    bad_minor[7] = 9;
    vectors.push(("bad_minor", "infinity/version-minor", bad_minor));

    let mut bad_header_size = base.clone();
    bad_header_size[10] = 8;
    vectors.push(("bad_header_size", "infinity/header-size", bad_header_size));

    let mut bad_flags = base.clone();
    bad_flags[8] = 0x80;
    vectors.push(("bad_flags", "infinity/flags", bad_flags));

    let mut truncated = base.clone();
    truncated.truncate(base.len() - 8);
    vectors.push(("truncated", "infinity/truncated", truncated));

    let mut trailing = base.clone();
    trailing.extend_from_slice(&[0u8; 8]);
    vectors.push(("trailing", "infinity/trailing-bytes", trailing));

    let mut bad_hash = base.clone();
    bad_hash[16] ^= 0xff;
    vectors.push(("bad_hash", "infinity/hash-mismatch", bad_hash));

    // Node count bomb: claim 1M nodes in a small buffer.
    let mut count_bomb = base.clone();
    count_bomb[68..72].copy_from_slice(&1_000_000u32.to_le_bytes());
    vectors.push(("count_bomb", "infinity/count", count_bomb));

    // Count within limits but unsatisfiable by the buffer.
    let mut short_count = base.clone();
    short_count[68..72].copy_from_slice(&100u32.to_le_bytes());
    vectors.push(("short_count", "infinity/count", short_count));

    // Offset to a non-aligned position.
    let mut bad_offset = base.clone();
    let nodes_off = u32::from_le_bytes(base[64..68].try_into().unwrap());
    bad_offset[64..68].copy_from_slice(&(nodes_off + 4).to_le_bytes());
    vectors.push(("bad_offset", "infinity/offset", bad_offset));

    // Unknown unit discriminant (with the hash fixed up).
    let mut bad_unit = base.clone();
    let header = active_infinity::layout::Header::parse(&base).expect("header");
    let units = header.span(Section::Units).offset as usize;
    bad_unit[units..units + 4].copy_from_slice(&999u32.to_le_bytes());
    fix_hash(&mut bad_unit);
    vectors.push(("bad_unit", "infinity/unknown-unit", bad_unit));

    // Non-canonical string order: swap two entries in the string offset table.
    let mut bad_strings = base.clone();
    let strings = header.span(Section::Strings).offset as usize;
    if header.span(Section::Strings).count >= 2 {
        let first = u32::from_le_bytes(base[strings..strings + 4].try_into().unwrap());
        let second = u32::from_le_bytes(base[strings + 4..strings + 8].try_into().unwrap());
        bad_strings[strings..strings + 4].copy_from_slice(&second.to_le_bytes());
        bad_strings[strings + 4..strings + 8].copy_from_slice(&first.to_le_bytes());
        fix_hash(&mut bad_strings);
        // String ordering, heap offsets and alignment all report the same
        // structural class.
        vectors.push(("bad_string_order", "infinity/offset", bad_strings));
    }

    // Non-zero padding between sections (recomputed from the string section).
    let mut bad_padding = base.clone();
    let string_count = header.span(Section::Strings).count as usize;
    let string_body = 4 * (string_count + 1)
        + u32::from_le_bytes(
            base[strings + string_count * 4..strings + string_count * 4 + 4]
                .try_into()
                .unwrap(),
        ) as usize;
    let padding_at = strings + string_body;
    if padding_at < base.len() {
        bad_padding[padding_at] = 0xff;
        fix_hash(&mut bad_padding);
        vectors.push(("bad_padding", "infinity/padding", bad_padding));
    }

    // Edge table forgery: point an edge at an out-of-range node.
    let mut bad_edge = base.clone();
    let edges = header.span(Section::Edges).offset as usize;
    if header.span(Section::Edges).count > 0 {
        bad_edge[edges..edges + 4].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        fix_hash(&mut bad_edge);
        vectors.push(("bad_edge", "infinity/edge", bad_edge));
    }

    let mut invalid_index = String::from("# name expected_code\n");
    for (name, code, bytes) in &vectors {
        fs::write(invalid_dir.join(format!("{name}.ainf")), bytes).expect("write");
        invalid_index.push_str(&format!("{name} {code}\n"));
    }
    fs::write(invalid_dir.join("index.txt"), invalid_index).expect("index");
    println!(
        "wrote {} valid and {} invalid vectors to {}",
        fixtures.len(),
        vectors.len(),
        root.display()
    );
}

fn fix_hash(bytes: &mut [u8]) {
    let hash = hash_image(bytes).expect("hash");
    bytes[16..48].copy_from_slice(&hash);
}
