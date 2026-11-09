//! Regression tests for the canonical-by-default decode (INF-02).
//!
//! `DecodeOpts::default()` proves canonicality: `decode`, `validate`,
//! `decode_provenance`, `decode_annotations` and `content_hash` refuse a
//! structurally valid image that is not exactly the canonical encoding of
//! its own content (`infinity/not-canonical`). Trusted or migration paths
//! that must accept slack opt out explicitly with
//! `DecodeOpts { verify_canonical: false, .. }`.
//!
//! The slack fixture is the audit's P-A image: one extra unreferenced string
//! ("zzz-unref"), correct offsets, recomputed hash, 288 bytes vs 280 for the
//! canonical re-encode. The flag-cleared fixture is the W5 CLI-01 shape: the
//! canonical encoding of a module with `FLAG_CANONICAL` cleared (and the hash
//! recomputed) — the re-encode proof is unconditional, so an unflagged image
//! fails even though its bytes are otherwise canonical.

use active_infinity::encode::hash_image;
use active_infinity::layout::{Header, Section, FLAG_CANONICAL};
use active_infinity::{
    content_hash, decode, decode_with, encode, validate, validate_canonical, validate_with,
    DecodeOpts, InfinityModule, Inode,
};

/// The lenient options: the pre-INF-02 default, for paths that must accept slack.
fn lenient() -> DecodeOpts {
    DecodeOpts {
        verify_canonical: false,
        ..DecodeOpts::default()
    }
}

/// P-A image: one `Str("a")` module plus an unreferenced "zzz-unref" string.
fn slack_image() -> Vec<u8> {
    let mut m = InfinityModule::new();
    let s = m.push(Inode::Str("a".into()));
    m.set_root(Some(s));
    let orig = encode(&m).unwrap();
    let header = Header::parse(&orig).unwrap();
    let str_span = header.span(Section::Strings);
    let str_off = str_span.offset as usize;
    let str_count = str_span.count as usize;
    // Old strings body: (count+1)*4 table words + heap. New: +1 word + 9 heap bytes.
    let old_body = (str_count + 1) * 4 + 1; // heap "a" is 1 byte
    let new_body = (str_count + 2) * 4 + 10; // heap "a"+"zzz-unref"
    let old_padded = (old_body + 7) & !7;
    let new_padded = (new_body + 7) & !7;
    let shift = (new_padded - old_padded) as u64;
    assert_eq!(shift, 8);
    let mut img = Vec::with_capacity(orig.len() + shift as usize);
    // Header placeholder (will patch offsets + hash at the end).
    img.extend_from_slice(&orig[..str_off]);
    // New strings section: offsets [0,1,10], heap_len 10, heap "azzz-unref".
    img.extend_from_slice(&0u32.to_le_bytes());
    img.extend_from_slice(&1u32.to_le_bytes());
    img.extend_from_slice(&10u32.to_le_bytes());
    img.extend_from_slice(b"azzz-unref");
    img.extend(std::iter::repeat_n(0u8, new_padded - new_body));
    // Rest of the image (sections after Strings), unchanged bytes.
    let rest_start = str_off + old_padded;
    img.extend_from_slice(&orig[rest_start..]);
    // Patch header: sections after Strings shift by 8; total_size += 8.
    let mut hdr = header;
    for sec in Section::ALL {
        if (sec as usize) > (Section::Strings as usize) {
            let sp = hdr.span_mut(sec);
            sp.offset += shift as u32;
        }
    }
    hdr.span_mut(Section::Strings).count += 1;
    hdr.total_size += shift;
    hdr.write(&mut img);
    // Recompute content hash (hash field zeroed for hashing).
    let hash = hash_image(&img).unwrap();
    img[16..48].copy_from_slice(&hash);
    assert_eq!(img.len(), 288, "slack image must be 288 bytes");
    img
}

/// Canonical image of a small module with `FLAG_CANONICAL` cleared.
fn flag_cleared_image() -> Vec<u8> {
    let mut m = InfinityModule::new();
    let hello = m.push(Inode::Str("hello".into()));
    let number = m.push(Inode::Int(42));
    let table = m.push(Inode::Table {
        fields: vec![("greeting".into(), hello), ("answer".into(), number)],
    });
    m.set_root(Some(table));
    let mut img = encode(&m).unwrap();
    let mut hdr = Header::parse(&img).unwrap();
    assert_ne!(hdr.flags & FLAG_CANONICAL, 0, "encoder marks canonical");
    hdr.flags &= !FLAG_CANONICAL;
    hdr.write(&mut img);
    let hash = hash_image(&img).unwrap();
    img[16..48].copy_from_slice(&hash);
    img
}

fn assert_not_canonical(err: &active_infinity::Error) {
    assert_eq!(
        err.code(),
        "infinity/not-canonical",
        "expected infinity/not-canonical, got {err}"
    );
}

#[test]
fn inf02_default_decode_refuses_slack_image() {
    let img = slack_image();
    assert_not_canonical(&decode(&img).expect_err("default decode must refuse slack"));
    assert_not_canonical(&validate(&img).expect_err("default validate must refuse slack"));
    assert_not_canonical(&content_hash(&img).expect_err("content_hash must refuse slack"));
    assert_not_canonical(
        &validate_canonical(&img, active_infinity::Limits::default())
            .expect_err("validate_canonical must refuse slack"),
    );
}

#[test]
fn inf02_explicit_opt_out_accepts_slack_image() {
    let img = slack_image();
    // The lenient path still accepts it — and the re-encode drops the slack,
    // which is exactly why the default refuses: bytes and hash change.
    let decoded = decode_with(&img, lenient()).expect("lenient decode accepts slack");
    let reenc = encode(&decoded).unwrap();
    assert_eq!(reenc.len(), 280, "re-encode drops the slack string");
    assert_ne!(reenc, img);
    assert!(validate_with(&img, lenient()).is_ok());
}

#[test]
fn inf02_paranoid_still_refuses_slack_image() {
    let img = slack_image();
    assert_not_canonical(
        &decode_with(&img, DecodeOpts::paranoid()).expect_err("paranoid decode must refuse slack"),
    );
}

#[test]
fn inf02_flag_cleared_image_refused_by_default() {
    // The re-encode proof is unconditional: an unflagged image fails even
    // though its bytes are otherwise the canonical encoding of its content.
    // This is the W5 CLI-01 / NF-W5-01 fixture shape (flag-cleared).
    let img = flag_cleared_image();
    assert_not_canonical(&decode(&img).expect_err("default decode must refuse unflagged"));
    assert_not_canonical(&validate(&img).expect_err("default validate must refuse unflagged"));
    // ... while the lenient path accepts it.
    assert!(decode_with(&img, lenient()).is_ok());
}

#[test]
fn inf02_canonical_images_still_decode_by_default() {
    // Encoder output is canonical: the default path accepts it, the
    // round trip is byte-identical, and the hash is stable — the format's
    // guarantee #1 now holds for accepted input, not just encoder output.
    let mut m = InfinityModule::new();
    let hello = m.push(Inode::Str("hello".into()));
    let number = m.push(Inode::Int(42));
    let table = m.push(Inode::Table {
        fields: vec![("greeting".into(), hello), ("answer".into(), number)],
    });
    m.set_root(Some(table));
    let bytes = encode(&m).unwrap();
    let decoded = decode(&bytes).expect("canonical image decodes by default");
    assert_eq!(decoded, m);
    assert_eq!(encode(&decoded).unwrap(), bytes);
    assert_eq!(
        content_hash(&bytes).unwrap(),
        content_hash(&encode(&decoded).unwrap()).unwrap()
    );
    assert!(validate(&bytes).is_ok());
    assert!(validate_canonical(&bytes, active_infinity::Limits::default()).is_ok());
}
