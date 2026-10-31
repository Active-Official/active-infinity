//! Marathon section I-03: canonical form.
//!
//! `tests/marathon_layout_tests.rs` and `tests/marathon_validate_tests.rs` cover
//! the wire rules; this file covers identity: the same logical module must encode
//! to the same bytes whatever order its arena was built in.

use active_infinity::{encode, InfinityModule, Inode};

/// The same logical module: a table `{a: 1}` plus two values reachable only
/// through bindings (`y` → 8, `z` → 9), with those values pushed in opposite
/// orders. Only the binding roots can order them, so this is where the arena's
/// construction order used to leak into the canonical bytes.
fn module(values_reversed: bool) -> InfinityModule {
    let mut module = InfinityModule::new();
    let one = module.push(Inode::Int(1));
    let (y_value, z_value) = if values_reversed {
        let z = module.push(Inode::Int(9));
        let y = module.push(Inode::Int(8));
        (y, z)
    } else {
        let y = module.push(Inode::Int(8));
        let z = module.push(Inode::Int(9));
        (y, z)
    };
    let root = module.push(Inode::Table {
        fields: vec![("a".to_string(), one)],
    });
    module.set_root(Some(root));
    module.bind("y", y_value);
    module.bind("z", z_value);
    module
}

#[test]
fn annotation_order_does_not_change_the_canonical_bytes() {
    // Two annotation-only subjects, annotated in opposite orders. The annotation
    // set is the same, so the image must be too: numbering has to be defined by
    // content, not by the order the caller called `annotate`.
    let build = |first_on_two: bool| {
        let mut module = InfinityModule::new();
        let root = module.push(Inode::Int(1));
        let two = module.push(Inode::Int(2));
        let three = module.push(Inode::Int(3));
        module.set_root(Some(root));
        if first_on_two {
            module.annotate(two, active_infinity::AnnotationKind::Intent("a".into()));
            module.annotate(three, active_infinity::AnnotationKind::Intent("b".into()));
        } else {
            module.annotate(three, active_infinity::AnnotationKind::Intent("b".into()));
            module.annotate(two, active_infinity::AnnotationKind::Intent("a".into()));
        }
        module
    };
    assert_eq!(
        encode(&build(true)).expect("forward"),
        encode(&build(false)).expect("reversed"),
        "annotation insertion order must not reach the image"
    );
}

#[test]
fn every_nan_normalizes_to_the_canonical_bit_pattern() {
    // A signaling NaN used to be refused by structural validation before
    // canonicalization could normalize it, so the module could not be encoded at
    // all. Every NaN becomes the one permitted quiet NaN instead.
    let mut module = InfinityModule::new();
    let signaling = module.push(Inode::Float(f64::from_bits(0x7ff0_0000_0000_0001)));
    let negative = module.push(Inode::Float(f64::from_bits(0xfff8_0000_0000_0000)));
    let root = module.push(Inode::Array {
        elements: vec![signaling, negative],
    });
    module.set_root(Some(root));

    let image = encode(&module).expect("every NaN is canonicalized");
    active_infinity::validate_canonical(&image, active_infinity::Limits::default())
        .expect("the image is canonical");
    let decoded = active_infinity::decode(&image).expect("decode");
    for node in decoded.nodes() {
        if let Inode::Float(value) = node {
            assert_eq!(
                value.to_bits(),
                active_infinity::layout::CANONICAL_NAN_BITS,
                "a NaN survived with a foreign bit pattern"
            );
        }
    }
    assert_eq!(encode(&decoded).expect("re-encode"), image);
}

#[test]
fn an_inconsistent_blob_is_refused_at_encode() {
    // The encoder used to write the fields it was given, so a blob whose size or
    // hash disagreed with its payload produced an image the crate then refused to
    // read. The failure belongs on the way out.
    let payload = vec![7u8; 32];
    let good_hash = *blake3::hash(&payload).as_bytes();
    let build = |hash: [u8; 32], size: u64| {
        let mut module = InfinityModule::new();
        let media = module.push(Inode::Str("application/octet-stream".to_string()));
        let blob = module.push(Inode::Blob {
            hash,
            size,
            tainted: false,
            media_type: "application/octet-stream".to_string(),
            payload: Some(payload.clone()),
        });
        let root = module.push(Inode::Table {
            fields: vec![("media".to_string(), media), ("blob".to_string(), blob)],
        });
        module.set_root(Some(root));
        module
    };

    let error = encode(&build(good_hash, payload.len() as u64 + 1))
        .expect_err("a size that disagrees with the payload is refused");
    assert_eq!(error.code(), "infinity/encode", "{error:?}");

    let error = encode(&build([0u8; 32], payload.len() as u64))
        .expect_err("a hash that disagrees with the payload is refused");
    assert_eq!(error.code(), "infinity/encode", "{error:?}");
    assert!(format!("{error}").contains("hash"), "{error}");

    let image = encode(&build(good_hash, payload.len() as u64)).expect("a consistent blob encodes");
    active_infinity::validate_canonical(&image, active_infinity::Limits::default())
        .expect("the image is canonical");
}

#[test]
fn arena_order_does_not_change_the_canonical_bytes() {
    // Canonical numbering used to order the binding roots by numeric node id, so
    // the arena's construction order leaked into the image: two modules with the
    // same content had two hashes.
    let forward = encode(&module(false)).expect("encode forward");
    let reversed = encode(&module(true)).expect("encode reversed");
    assert_eq!(
        forward, reversed,
        "the same module must have one canonical encoding"
    );
}

#[test]
fn arena_order_does_not_change_module_equality() {
    assert_eq!(
        module(false),
        module(true),
        "structural equality is over the canonical form"
    );
}

#[test]
fn the_canonical_encoding_is_stable_across_repetition() {
    let image = encode(&module(false)).expect("encode");
    let decoded = active_infinity::decode(&image).expect("decode");
    let again = encode(&decoded).expect("re-encode");
    assert_eq!(
        image, again,
        "decode then encode is the identity on an image"
    );
    active_infinity::validate_canonical(&image, active_infinity::Limits::default())
        .expect("the encoding is canonical");
}
