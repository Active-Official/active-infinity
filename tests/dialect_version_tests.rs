//! Regression tests for the dialect-version family: INF-03 + BND-F1 + R2-VER-03.
//!
//! The root cause (round 1 INF-03, confirmed by W4; boundary BND-F1, confirmed
//! by W6; round 2 R2-VER-03, confirmed by W16 on Linux + Windows with a
//! cross-platform fixture exchange): `dialect_hash()` baked `FORMAT_MINOR`
//! into the Blake3 preimage, so the minor-acceptance branch in `Header::parse`
//! (and in the stream Begin handler) could never succeed — every image with an
//! older minor necessarily carried an older dialect hash, and `validate`
//! refused it with `DialectMismatch`. The first `FORMAT_MINOR` bump would
//! have bricked every stored 1.0 image, including every object in a `Store`,
//! which had no migration path. At the same time the dialect covered no
//! canonical-form rule, so the three hash-affecting canonical-form changes in
//! 2.4.0/2.4.1/2.4.2 (same day, format still 1.0) silently re-addressed every
//! module with no version signal at all.
//!
//! The fix (format 1.1): the dialect hash covers `FORMAT_MAJOR` plus an
//! explicit `DIALECT_VERSION` (currently 1) plus the canonical-form rules
//! (`DIALECT_CANONICAL_TEXT`) — and no longer covers `FORMAT_MINOR`. The
//! 1.0 dialect (`0x7782_d0ea_5e28_b75d`, the old golden) stays accepted in
//! `validate` and in the stream Begin handler, so stored 1.0 images pass the
//! dialect gate under a 1.1 decoder. They are structurally valid but not
//! canonical under 1.1 (a re-encode writes the 1.1 header), so the migration
//! path is: lenient decode (`verify_canonical: false`) → `encode` → store
//! the 1.1 image. Plain `validate()`/`decode()` still refuse the 1.0 bytes
//! as not-canonical (INF-02: the default proves canonical form) — the
//! refusal now comes from the canonical proof, with a re-encode migration,
//! instead of from a dead dialect gate with no recovery path.
//!
//! The 1.0 fixture is `tests/fixtures/dialect-1_0.ainf`: a 440-byte image
//! produced by the pre-fix encoder (format 1.0, dialect
//! `0x7782_d0ea_5e28_b75d`, content hash
//! `41806302c4828a40906faa93843b3608acbf4028a005b5b0ad9fb1b14c827e56`),
//! a table `{greeting: "hello", answer: 42}` with a separator-containing
//! annotation (`Intent("a|b:c")`, the 2.4.2 tie-break shape).

use active_infinity::layout::{
    is_accepted_dialect, Header, DIALECT_CANONICAL_TEXT, DIALECT_HASH_GOLDEN,
    DIALECT_HASH_GOLDEN_1_0, DIALECT_VERSION, FORMAT_MAJOR, FORMAT_MINOR,
};
use active_infinity::stream::{encode_stream, Frame, FrameKind, StreamDecoder};
use active_infinity::{
    decode_with, encode, validate, validate_canonical, validate_with, DecodeOpts, InfinityModule,
    Inode,
};

/// The format-1.0 fixture, produced by the pre-fix encoder.
const LEGACY_FIXTURE: &[u8] = include_bytes!("fixtures/dialect-1_0.ainf");

/// The lenient options: the migration path that accepts a valid image whose
/// bytes are not the current canonical encoding.
fn lenient() -> DecodeOpts {
    DecodeOpts {
        verify_canonical: false,
        ..DecodeOpts::default()
    }
}

fn fixture_module() -> InfinityModule {
    decode_with(LEGACY_FIXTURE, lenient()).expect("the 1.0 fixture decodes leniently")
}

#[test]
fn the_dialect_hash_covers_the_dialect_version_not_the_format_minor() {
    // The dialect is versioned explicitly now; the wire minor is a header
    // field, not a hash input — a future minor bump must not re-address
    // every stored image the way R2-VER-03 proved a 1.1 decoder would.
    assert_eq!(FORMAT_MAJOR, 1);
    assert_eq!(FORMAT_MINOR, 1, "this fix ships format 1.1");
    assert_eq!(DIALECT_VERSION, 1, "the first versioned dialect");
    assert_eq!(
        active_infinity::layout::dialect_hash(),
        DIALECT_HASH_GOLDEN,
        "the current dialect hash is pinned"
    );
    assert_eq!(
        active_infinity::layout::dialect_hash_1_0(),
        DIALECT_HASH_GOLDEN_1_0,
        "the legacy 1.0 dialect recomputes exactly (the old preimage, frozen)"
    );
    assert_ne!(
        DIALECT_HASH_GOLDEN, DIALECT_HASH_GOLDEN_1_0,
        "the 1.1 dialect differs from the 1.0 dialect: the hash changed once, \
         deliberately, with the version bump — never silently in a patch"
    );
    assert!(
        DIALECT_CANONICAL_TEXT.contains("canonical:1"),
        "the dialect preimage names the canonical-form rule set it covers"
    );
    assert!(
        is_accepted_dialect(DIALECT_HASH_GOLDEN),
        "current dialect accepted"
    );
    assert!(
        is_accepted_dialect(DIALECT_HASH_GOLDEN_1_0),
        "legacy 1.0 dialect accepted: the migration story"
    );
    assert!(!is_accepted_dialect(0), "a zero dialect is refused");
    assert!(
        !is_accepted_dialect(u64::MAX),
        "an unknown dialect is refused"
    );
    assert!(
        !is_accepted_dialect(0x6274_7b54_a51b_638b),
        "the dialect a naive minor-only bump would have produced (W16 probe_dialect_minor11) \
         is refused: it is neither the current nor the legacy dialect"
    );
}

#[test]
fn a_format_1_0_image_is_valid_but_not_canonical_under_1_1() {
    let header = Header::parse(LEGACY_FIXTURE).expect("the 1.0 header parses");
    assert_eq!(
        (header.major, header.minor),
        (1, 0),
        "the fixture is format 1.0"
    );
    assert_eq!(
        header.dialect_hash, DIALECT_HASH_GOLDEN_1_0,
        "the fixture carries the legacy 1.0 dialect"
    );
    // The image path accepts the legacy dialect: structural validation passes
    // under the lenient options. Plain `validate()` proves canonical form by
    // default (INF-02), so it refuses the 1.0 bytes as not-canonical — the
    // dialect gate itself is no longer the refusal.
    validate_with(LEGACY_FIXTURE, lenient())
        .expect("a stored 1.0 image still validates structurally");
    let error =
        validate(LEGACY_FIXTURE).expect_err("plain validate() proves canonical form by default");
    assert_eq!(error.code(), "infinity/not-canonical", "{error:?}");
    // The migration path: lenient decode, then re-encode to the 1.1 form.
    let module = fixture_module();
    let reencoded = encode(&module).expect("re-encode the migrated module");
    let new_header = Header::parse(&reencoded).expect("the re-encoded header parses");
    assert_eq!((new_header.major, new_header.minor), (1, 1));
    assert_eq!(new_header.dialect_hash, DIALECT_HASH_GOLDEN);
    assert_ne!(
        reencoded, LEGACY_FIXTURE,
        "re-encoding re-addresses the module once, deliberately: the header carries the new dialect"
    );
    validate_canonical(&reencoded, Default::default())
        .expect("the re-encoded image is canonical under 1.1");
    // But the 1.0 bytes themselves are not the 1.1 canonical encoding, so the
    // canonical proof refuses them — with the explicit re-encode migration,
    // not a dead dialect gate.
    let error = validate_canonical(LEGACY_FIXTURE, Default::default())
        .expect_err("a 1.0 image is not canonical under 1.1");
    assert_eq!(error.code(), "infinity/not-canonical", "{error:?}");
    let error = decode_with(LEGACY_FIXTURE, DecodeOpts::default())
        .expect_err("default decode proves canonical form, so it refuses the 1.0 bytes");
    assert_eq!(error.code(), "infinity/not-canonical", "{error:?}");
}

#[test]
fn a_format_1_1_image_round_trips() {
    let mut module = InfinityModule::new();
    let greeting = module.push(Inode::Str("hello".into()));
    let answer = module.push(Inode::Int(42));
    let table = module.push(Inode::Table {
        fields: vec![("greeting".into(), greeting), ("answer".into(), answer)],
    });
    module.set_root(Some(table));
    let image = encode(&module).expect("encode");
    let header = Header::parse(&image).expect("parse");
    assert_eq!((header.major, header.minor), (1, 1));
    assert_eq!(header.dialect_hash, DIALECT_HASH_GOLDEN);
    validate(&image).expect("a 1.1 image validates");
    validate_canonical(&image, Default::default()).expect("a 1.1 image is canonical");
    let decoded = active_infinity::decode(&image).expect("a 1.1 image decodes by default");
    assert_eq!(decoded, module);
    assert_eq!(encode(&decoded).expect("re-encode"), image);
}

#[test]
fn a_stream_begin_with_the_legacy_dialect_is_accepted() {
    // The W16 proof shape, inverted: a 1.0 Begin over 1.1 section bodies must
    // now be accepted by the 1.1 decoder, and the image and stream paths must
    // agree (both accept). The reassembled image is regenerated with the
    // current header, so the generation is a 1.1 image.
    let module = fixture_module();
    let mut frames = encode_stream(&module, 4096).expect("stream frames");
    assert_eq!(frames[0].kind, FrameKind::Begin);
    assert_eq!(frames[0].payload.len(), 24);
    // Rewrite the Begin to the 1.0 producer's values: minor 0, legacy dialect.
    frames[0].payload[2..4].copy_from_slice(&0u16.to_le_bytes());
    frames[0].payload[8..16].copy_from_slice(&DIALECT_HASH_GOLDEN_1_0.to_le_bytes());
    let mut decoder = StreamDecoder::new();
    decoder
        .push(&frames[0])
        .expect("Begin with minor 0 + legacy dialect");
    for frame in &frames[1..] {
        decoder.push(frame).expect("the rest of the generation");
    }
    let streamed = decoder.finish().expect("the generation completes");
    let header = Header::parse(&streamed.image).expect("the reassembled header parses");
    assert_eq!((header.major, header.minor), (1, 1));
    assert_eq!(header.dialect_hash, DIALECT_HASH_GOLDEN);
    validate_canonical(&streamed.image, Default::default())
        .expect("the reassembled image is canonical under 1.1");
}

#[test]
fn a_stream_begin_with_an_unknown_dialect_or_future_minor_is_refused() {
    let module = fixture_module();
    let frames = encode_stream(&module, 4096).expect("stream frames");
    // Unknown dialect, current minor: the dialect gate still refuses.
    let mut bad_dialect = frames[0].clone();
    bad_dialect.payload[8..16].copy_from_slice(&0xdead_beef_cafe_f00du64.to_le_bytes());
    let mut decoder = StreamDecoder::new();
    let error = decoder
        .push(&bad_dialect)
        .expect_err("an unknown dialect is refused at Begin");
    assert_eq!(error.code(), "infinity/dialect", "{error:?}");
    // Future minor, current dialect: the minor gate still refuses.
    let mut future_minor = frames[0].clone();
    future_minor.payload[2..4].copy_from_slice(&(FORMAT_MINOR + 1).to_le_bytes());
    let mut decoder = StreamDecoder::new();
    let error = decoder
        .push(&future_minor)
        .expect_err("a future minor is refused at Begin");
    assert_eq!(error.code(), "infinity/version-minor", "{error:?}");
    // The Begin frame's dialect word is read through the same acceptance set
    // as the image path: a raw frame carrying the legacy dialect is accepted.
    let mut legacy = frames[0].clone();
    legacy.payload[2..4].copy_from_slice(&0u16.to_le_bytes());
    legacy.payload[8..16].copy_from_slice(&DIALECT_HASH_GOLDEN_1_0.to_le_bytes());
    let mut decoder = StreamDecoder::new();
    decoder
        .push(&legacy)
        .expect("a legacy-dialect Begin is accepted on its own");
}
