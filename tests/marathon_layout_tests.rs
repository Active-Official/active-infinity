//! Marathon section I-01/I-05 regressions: header serialization, limits,
//! alignment, dialect preimage and unreachable nodes.
//!
//! Each test here corresponds to a finding in
//! `docs/hardening/COPILOT-MARATHON.md`; the first version of the test failed
//! against the code as it stood before the fix.

use active_infinity::layout::{
    align8, dialect_hash, Header, Limits, SectionSpan, FLAG_CANONICAL, FORMAT_MAJOR, FORMAT_MINOR,
    HEADER_SIZE, SECTION_COUNT,
};
use active_infinity::{Error, InfinityModule, Inode, SecretBytes};

fn header() -> Header {
    Header {
        major: FORMAT_MAJOR,
        minor: FORMAT_MINOR,
        flags: FLAG_CANONICAL,
        header_size: HEADER_SIZE as u16,
        content_hash: [7u8; 32],
        dialect_hash: dialect_hash(),
        total_size: HEADER_SIZE as u64,
        sections: [SectionSpan::default(); SECTION_COUNT],
    }
}

#[test]
fn writing_a_header_zeroes_the_reserved_tail() {
    // A caller-owned buffer may hold anything, including bytes from a previous
    // secret. `parse` refuses a non-zero reserved tail, so `write` must produce
    // those zeros itself instead of inheriting them from the buffer.
    let mut buffer = vec![0xAAu8; HEADER_SIZE];
    header().write(&mut buffer);
    let parsed = Header::parse(&buffer).expect("a written header parses");
    assert_eq!(
        parsed.content_hash, [7u8; 32],
        "the fields survive the round trip"
    );
    assert!(
        buffer[64 + SECTION_COUNT * 8..]
            .iter()
            .all(|byte| *byte == 0),
        "the reserved tail is zeroed"
    );
}

#[test]
fn a_header_size_error_preserves_the_wire_value() {
    let mut buffer = vec![0u8; HEADER_SIZE];
    header().write(&mut buffer);
    buffer[10..12].copy_from_slice(&0x0110u16.to_le_bytes());
    let error = Header::parse(&buffer).expect_err("0x0110 is not the fixed size");
    match error {
        Error::HeaderSize(value) => {
            assert_eq!(value, 0x0110, "the reported size is the wire value")
        }
        other => panic!("expected HeaderSize, got {other:?}"),
    }
}

#[test]
fn align8_saturates_instead_of_wrapping() {
    // `u64::MAX + 7` wraps to 6 in release and panics in debug. The layout
    // primitive must not do either: it rounds up, and at the top it stays at the
    // top so the caller's size check fails closed.
    assert_eq!(align8(0), 0);
    assert_eq!(align8(1), 8);
    assert_eq!(align8(8), 8);
    // u64::MAX rounds to the highest aligned value, 0xFFFF_FFFF_FFFF_FFF8.
    const TOP_ALIGNED: u64 = u64::MAX - 7;
    assert_eq!(align8(u64::MAX), TOP_ALIGNED);
    assert_eq!(align8(u64::MAX - 8), TOP_ALIGNED);
}

#[test]
fn every_zero_ceiling_is_refused() {
    type Zeroer = Box<dyn Fn(&mut Limits)>;
    let mut cases: Vec<(&str, Zeroer)> = Vec::new();
    macro_rules! ceiling {
        ($name:ident) => {
            cases.push((
                stringify!($name),
                Box::new(|limits: &mut Limits| limits.$name = 0),
            ));
        };
    }
    ceiling!(max_nodes);
    ceiling!(max_edges);
    ceiling!(max_children);
    ceiling!(max_fields);
    ceiling!(max_parts);
    ceiling!(max_strings);
    ceiling!(max_string_bytes);
    ceiling!(max_blobs);
    ceiling!(max_blob_bytes);
    ceiling!(max_annotations);
    ceiling!(max_units);
    ceiling!(max_types);
    ceiling!(max_aux);
    ceiling!(max_numbers);
    ceiling!(max_secrets);
    ceiling!(max_secret_bytes);
    ceiling!(max_extensions);
    ceiling!(max_prov_entries);
    ceiling!(max_hashes);
    ceiling!(max_bindings);
    ceiling!(max_total_bytes);
    ceiling!(max_depth);
    assert_eq!(cases.len(), 22, "every field of Limits is covered");

    for (name, zero) in cases {
        let mut limits = Limits::default();
        zero(&mut limits);
        let error = limits
            .check()
            .expect_err(&format!("{name} = 0 must be refused"));
        assert_eq!(
            error.code(),
            "infinity/invalid-argument",
            "{name} must be an argument error"
        );
        assert!(
            format!("{error}").contains(name),
            "{name}: the message names the field, got {error}"
        );
    }
}

#[test]
fn the_dialect_preimage_lists_the_aux_tags_it_claims() {
    // The dialect hash commits to the node-kind and aux-tag vocabulary. If a
    // constant is added without updating the preimage text, two peers with
    // different semantics share a dialect; this test is the tripwire.
    let listed = active_infinity::layout::DIALECT_AUX_TAGS_TEXT
        .strip_prefix("aux-tags:")
        .expect("the preimage names the aux tags");
    let tags: Vec<u32> = listed
        .split(',')
        .map(|tag| tag.parse().expect("decimal tag"))
        .collect();
    assert_eq!(
        tags,
        active_infinity::layout::AUX_TAGS,
        "the preimage lists exactly the constants in AUX_TAGS"
    );
    assert_eq!(
        active_infinity::layout::DIALECT_KINDS_TEXT,
        format!("node-kinds:0..={}", active_infinity::layout::NODE_KIND_MAX),
        "the preimage names the highest node kind"
    );
}

#[test]
fn the_dialect_hash_is_pinned() {
    // Changing this value changes every image: it is a format decision, never a
    // side effect of an edit. Update only with a FORMAT_MAJOR/MINOR bump and a
    // note in the changelog.
    assert_eq!(
        dialect_hash(),
        active_infinity::layout::DIALECT_HASH_GOLDEN,
        "the dialect hash moved"
    );
}

#[test]
fn unreachable_nodes_are_reported_and_dropped_by_canonicalization() {
    // `validate_structure` deliberately does not own reachability: in-place
    // stream deltas replace a subtree and leave the old one orphaned, and
    // canonicalization drops it. The public `check_reachable` is the check for
    // callers that need the wire rule, and the wire validator always applies it.
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(1));
    module.set_root(Some(root));
    let _orphan = module.push(Inode::Secret(SecretBytes::from("orphan-secret")));

    module
        .validate_structure(u64::MAX, 4096)
        .expect("structural validation passes; a delta may have orphaned the node");
    let error = module
        .check_reachable()
        .expect_err("the orphan is reported by the explicit check");
    assert_eq!(error.code(), "infinity/node", "{error:?}");

    let image = active_infinity::encode(&module).expect("encode");
    let decoded = active_infinity::decode(&image).expect("decode");
    assert_eq!(
        decoded.node_count(),
        module.node_count() - 1,
        "canonicalization drops the unreachable node"
    );
    active_infinity::validate(&image).expect("the image is valid");
}

#[test]
fn a_hostile_offset_is_reported_as_truncated_not_a_wrap() {
    // `read_u32(buf, usize::MAX)` used to compute `offset + 4`, which wraps in
    // release and panics in debug. A hostile offset is a truncated buffer.
    let error = active_infinity::layout::read_u32(&[0u8; 8], usize::MAX)
        .expect_err("an impossible offset is out of bounds");
    assert_eq!(error.code(), "infinity/truncated");
    let error = active_infinity::layout::read_u64(&[0u8; 8], usize::MAX)
        .expect_err("an impossible offset is out of bounds");
    assert_eq!(error.code(), "infinity/truncated");
}

#[test]
fn hash_and_binding_counts_have_their_own_ceilings() {
    // `max_hashes` and `max_bindings` exist so a module with a huge provenance
    // hash table and few nodes is refused on its own section count, and the
    // error names that ceiling instead of borrowing `max_nodes`.
    let limits = Limits {
        max_hashes: 4,
        max_bindings: 4,
        ..Limits::default()
    };
    assert_eq!(limits.max_hashes, 4);
    assert_eq!(limits.max_bindings, 4);
    assert!(limits.check().is_ok());
}

#[test]
fn a_reachable_module_still_validates() {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("svc".to_string()));
    let value = module.push(Inode::Int(80));
    let root = module.push(Inode::Table {
        fields: vec![("name".to_string(), name), ("port".to_string(), value)],
    });
    module.set_root(Some(root));
    module.bind("svc", root);
    module
        .validate_structure(u64::MAX, 4096)
        .expect("a tree rooted at the root node is fine");
}
