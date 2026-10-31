//! Marathon section I-02 regressions: layout validation of untrusted bytes.
//!
//! Findings from `docs/hardening/COPILOT-MARATHON.md`; each test failed against
//! the code as it stood before the fix.

use active_infinity::layout::{Header, Limits, Section};
use active_infinity::{encode, validate, validate_with, DecodeOpts, InfinityModule, Inode};

fn image() -> Vec<u8> {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("gateway".to_string()));
    let port = module.push(Inode::Int(8080));
    let root = module.push(Inode::Table {
        fields: vec![("name".to_string(), name), ("port".to_string(), port)],
    });
    module.set_root(Some(root));
    module.bind("gateway", root);
    encode(&module).expect("encode")
}

fn span_offset(section: Section) -> usize {
    64 + section as usize * 8
}

#[test]
fn a_count_bomb_in_a_variable_section_is_a_count_error() {
    // A count that fits the configured ceiling but cannot be satisfied by the
    // buffer is a count fault (`infinity/count`), not a truncation: agents branch
    // on the code, and the same fault used to be reported as `truncated` for
    // strings, blobs, secrets and extensions because the table read failed first.
    let cases = [
        (Section::Strings, 1_000_000u32),
        (Section::Blobs, 100_000),
        (Section::Secrets, 100_000),
        (Section::Extensions, 60_000),
    ];
    for (section, count) in cases {
        let mut bytes = image();
        let base = span_offset(section) + 4;
        bytes[base..base + 4].copy_from_slice(&count.to_le_bytes());
        let error = validate(&bytes).expect_err("a count bomb is refused");
        assert_eq!(
            error.code(),
            "infinity/count",
            "{section:?} count {count}: {error:?}"
        );
    }
}

#[test]
fn the_header_total_size_is_bounded() {
    // `total_size` is a header field: it can never be smaller than the header and
    // every section starts 8-aligned. The failure is an offset fault at parse
    // time, not `trailing-bytes` after a full layout walk.
    for bad in [0u64, 1, 100, 225] {
        let mut bytes = image();
        bytes[56..64].copy_from_slice(&bad.to_le_bytes());
        let error = Header::parse(&bytes).expect_err("an impossible total size is refused");
        assert_eq!(error.code(), "infinity/offset", "{bad}: {error:?}");
        assert!(format!("{error}").contains("total-size"), "{error}");
    }
    // A well-formed size still parses.
    Header::parse(&image()).expect("the fixture parses");
}

#[test]
fn a_section_offset_past_the_buffer_is_refused_before_any_read() {
    let mut bytes = image();
    let base = span_offset(Section::Nodes);
    bytes[base..base + 4].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
    let error = validate(&bytes).expect_err("an offset past the buffer is refused");
    assert!(
        matches!(error.code(), "infinity/offset" | "infinity/count"),
        "{error:?}"
    );
}

fn rewrite_hash(bytes: &mut [u8]) {
    let hash = active_infinity::encode::hash_image(bytes).expect("hash");
    bytes[16..48].copy_from_slice(&hash);
}

/// A module with two sibling tables, so the fields table has two ranges.
fn two_tables() -> Vec<u8> {
    let mut module = InfinityModule::new();
    let a_name = module.push(Inode::Str("a".to_string()));
    let a_value = module.push(Inode::Int(1));
    let first = module.push(Inode::Table {
        fields: vec![("x".to_string(), a_name), ("y".to_string(), a_value)],
    });
    let b_name = module.push(Inode::Str("b".to_string()));
    let b_value = module.push(Inode::Int(2));
    let second = module.push(Inode::Table {
        fields: vec![("x".to_string(), b_name), ("y".to_string(), b_value)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("first".to_string(), first), ("second".to_string(), second)],
    });
    module.set_root(Some(root));
    encode(&module).expect("encode")
}

fn node_offset(bytes: &[u8], index: usize) -> usize {
    Header::parse(bytes)
        .expect("header")
        .span(Section::Nodes)
        .offset as usize
        + index * active_infinity::layout::NODE_RECORD_SIZE
}

#[test]
fn a_non_zero_node_reserved_byte_is_refused() {
    // Bytes 2..4 of every 32-byte node record are reserved. They are hashed, so
    // an image carrying them validates while re-encoding to different bytes:
    // two bytes per node of data hidden inside the module identity.
    for index in 0..3 {
        let mut bytes = image();
        let at = node_offset(&bytes, index);
        bytes[at + 2] = 0xFF;
        rewrite_hash(&mut bytes);
        let error = validate(&bytes).expect_err("reserved byte is refused");
        assert_eq!(error.code(), "infinity/node", "node {index}: {error:?}");
    }
}

#[test]
fn a_table_field_range_out_of_order_is_refused() {
    // The fields table is packed in node order: the first table claims [0,2) and
    // the second [2,4). Swapping the two starts keeps both ranges in bounds but
    // breaks the packing, which is how unused or overlapping entries hide.
    let mut bytes = two_tables();
    let nodes = Header::parse(&bytes).expect("header").span(Section::Nodes);
    let mut tables = Vec::new();
    for index in 0..nodes.count as usize {
        let at = nodes.offset as usize + index * active_infinity::layout::NODE_RECORD_SIZE;
        let kind = bytes[at];
        let len = u64::from_le_bytes(bytes[at + 16..at + 24].try_into().expect("len"));
        if kind == 8 && len == 2 {
            tables.push(at);
        }
    }
    assert!(tables.len() >= 2, "the fixture has two two-field tables");
    let first = tables[0];
    let second = tables[1];
    bytes[first + 8..first + 16].copy_from_slice(&2u64.to_le_bytes());
    bytes[second + 8..second + 16].copy_from_slice(&0u64.to_le_bytes());
    rewrite_hash(&mut bytes);
    let error = validate(&bytes).expect_err("a non-packed field range is refused");
    assert_eq!(error.code(), "infinity/count", "{error:?}");
}

#[test]
fn a_duplicate_constraint_bound_is_refused() {
    // `min` and `max` are separate aux tags; the same tag twice decodes to one
    // value and re-encodes to one entry, so two hashes would name one module.
    let mut module = InfinityModule::new();
    let inner = module.push(Inode::Int(5));
    let constrained = module.push(Inode::Constrained {
        target: inner,
        constraint: active_infinity::ir::Constraint::MinMax {
            min: Some(1),
            max: Some(9),
        },
    });
    module.set_root(Some(constrained));
    let mut bytes = encode(&module).expect("encode");
    let header = Header::parse(&bytes).expect("header");
    let aux = header.span(Section::Aux).offset as usize;
    // The second aux entry's tag (max = 1) becomes min (0).
    bytes[aux + 8..aux + 12].copy_from_slice(&0u32.to_le_bytes());
    rewrite_hash(&mut bytes);
    let error = validate(&bytes).expect_err("duplicate constraint tags are refused");
    assert_eq!(error.code(), "infinity/node", "{error:?}");
}

#[test]
fn a_self_loop_is_a_cycle() {
    let mut bytes = two_tables();
    let edges = Header::parse(&bytes).expect("header").span(Section::Edges);
    assert!(edges.count > 0);
    let at = edges.offset as usize;
    let to = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().expect("to"));
    bytes[at..at + 4].copy_from_slice(&to.to_le_bytes());
    rewrite_hash(&mut bytes);
    let error = validate(&bytes).expect_err("a self-loop is a cycle");
    assert_eq!(error.code(), "infinity/cycle", "{error:?}");
}

#[test]
fn a_detached_blob_size_is_held_to_the_ceiling() {
    // A blob that travels without bytes still declares its size. That claim is
    // part of the module, so it cannot exceed the blob ceiling.
    let mut module = InfinityModule::new();
    let media = module.push(Inode::Str("application/octet-stream".to_string()));
    let blob = module.push(Inode::Blob {
        hash: [7u8; 32],
        size: u64::MAX,
        tainted: false,
        media_type: "application/octet-stream".to_string(),
        payload: None,
    });
    let root = module.push(Inode::Table {
        fields: vec![("media".to_string(), media), ("blob".to_string(), blob)],
    });
    module.set_root(Some(root));
    let bytes = encode(&module).expect("encode");
    let error = validate(&bytes).expect_err("an impossible detached size is refused");
    assert_eq!(error.code(), "infinity/limit", "{error:?}");
}

#[test]
fn a_canonical_image_still_validates_under_strict_limits() {
    let opts = DecodeOpts {
        limits: Limits::strict(),
        verify_hash: true,
        verify_canonical: true,
    };
    validate_with(&image(), opts).expect("the fixture is canonical under strict limits");
}

#[test]
fn the_provenance_ceiling_is_checked_before_the_block_is_walked() {
    // The provenance section count is a byte length; `max_prov_entries` bounds the
    // entries. A block claiming more entries than the ceiling is refused, and the
    // number in the error is the ceiling, not the byte length.
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(1));
    module.set_root(Some(root));
    module.set_provenance(Some(active_infinity::Provenance {
        producer: Some("marathon".to_string()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: None,
        entries: Vec::new(),
    }));
    let mut bytes = encode(&module).expect("encode");
    let provenance = Section::Provenance as usize;
    let span = 64 + provenance * 8;
    let offset = u32::from_le_bytes(bytes[span..span + 4].try_into().expect("offset")) as usize;
    assert_ne!(offset, 0, "the fixture carries a provenance block");
    // The entry count lives at byte 4 of the provenance header.
    bytes[offset + 4..offset + 8].copy_from_slice(&1000u32.to_le_bytes());
    let opts = DecodeOpts {
        limits: Limits {
            max_prov_entries: 8,
            ..Limits::default()
        },
        verify_hash: false,
        verify_canonical: false,
    };
    let error = validate_with(&bytes, opts).expect_err("too many entries");
    assert_eq!(error.code(), "infinity/limit", "{error:?}");
    assert!(
        format!("{error}").contains('8'),
        "the reported ceiling is the entry cap, got {error}"
    );
}
