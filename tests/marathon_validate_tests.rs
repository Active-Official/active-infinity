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
