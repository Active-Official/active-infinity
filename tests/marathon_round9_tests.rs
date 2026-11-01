//! I-12 round 9: canonical identity under colliding keys, ident locators, blob
//! payloads, binding paths and debug redaction.

use active_infinity::interop::{secret_tainted_paths, value_paths};
use active_infinity::{
    encode, validate_canonical, AnnotationKind, InfinityModule, Inode, Limits, SecretBytes,
};

/// An `Ident` inside a secret locator is secret text, not a symbol.
#[test]
fn an_ident_locator_leaves_the_public_heap() {
    let literal = "ident-canary-1234";
    let mut module = InfinityModule::new();
    let ident = module.push(Inode::Ident(literal.into()));
    let secret = module.push(Inode::SecretRef { locator: ident });
    let root = module.push(Inode::Table {
        fields: vec![("password".into(), secret)],
    });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode");
    let decoded = active_infinity::decode(&image).expect("decode");
    for node in decoded.nodes() {
        match node {
            Inode::Str(text) | Inode::Ident(text) => assert_ne!(text, literal),
            _ => {}
        }
    }
}

/// The primary ordering key is not injective; equal keys must be broken by
/// content, not by arena id, or equal modules get different Blake3 addresses.
#[test]
fn a_colliding_primary_key_is_ordered_by_content() {
    let build = |reversed: bool| {
        let mut module = InfinityModule::new();
        let root = module.push(Inode::Int(0));
        module.set_root(Some(root));
        let one = module.push(Inode::Int(2));
        let two = module.push(Inode::Int(1));
        let three = module.push(Inode::Int(2));
        // Both render as `G1a=i1b=i2`; only the arena order differs.
        let (first, second) = if reversed {
            let second = module.push(Inode::SchemaTable {
                fields: vec![("a".into(), two), ("b".into(), three)],
                closed: true,
            });
            let first = module.push(Inode::SchemaTable {
                fields: vec![("a=i1b".into(), one)],
                closed: true,
            });
            (first, second)
        } else {
            let first = module.push(Inode::SchemaTable {
                fields: vec![("a=i1b".into(), one)],
                closed: true,
            });
            let second = module.push(Inode::SchemaTable {
                fields: vec![("a".into(), two), ("b".into(), three)],
                closed: true,
            });
            (first, second)
        };
        for subject in [first, second] {
            module.annotate(subject, AnnotationKind::Intent("note".into()));
        }
        module
    };
    let a = encode(&build(false)).expect("encode a");
    let b = encode(&build(true)).expect("encode b");
    assert_eq!(a, b, "arena order leaked into the canonical bytes");
}

/// A secret under a binding keeps a dotted path, so an agent that anonymises by
/// label can still name the leaf.
#[test]
fn a_binding_only_secret_keeps_its_dotted_path() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from("hidden")));
    let table = module.push(Inode::Table {
        fields: vec![("pw".into(), secret)],
    });
    module.bind("cfg", table);
    let root = module.push(Inode::Int(0));
    module.set_root(Some(root));
    let paths = value_paths(&module);
    assert_eq!(paths.get(&secret).map(String::as_str), Some("cfg.pw"));
    let tainted = secret_tainted_paths(&module);
    assert!(tainted.contains(&"cfg.pw".to_string()), "{tainted:?}");
}

/// A materialised blob payload is an opaque binary surface: a secret copy inside
/// it cannot be redacted, so the encoder refuses the module.
#[test]
fn a_blob_payload_copying_a_secret_is_refused() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from("blob-canary")));
    let payload = b"prefix blob-canary suffix".to_vec();
    let hash = *blake3::hash(&payload).as_bytes();
    let blob = module.push(Inode::Blob {
        hash,
        size: payload.len() as u64,
        tainted: false,
        media_type: "text/plain".into(),
        payload: Some(payload),
    });
    let root = module.push(Inode::Table {
        fields: vec![("secret".into(), secret), ("blob".into(), blob)],
    });
    module.set_root(Some(root));
    let error = encode(&module).expect_err("a blob payload with a secret is refused");
    assert_eq!(error.code(), "infinity/encode", "{error}");
    assert!(error.to_string().contains("blob"), "{error}");
}

/// `Debug` runs before encode (logging, panics): a 32-byte secret used as a hash
/// must not appear as hex.
#[test]
fn debug_never_prints_a_secret_hash() {
    let secret = [0xABu8; 32];
    let mut module = InfinityModule::new();
    let node = module.push(Inode::Secret(SecretBytes::new(secret.to_vec())));
    let blob = module.push(Inode::Blob {
        hash: secret,
        size: 3,
        tainted: false,
        media_type: "text/plain".into(),
        payload: None,
    });
    module.set_provenance(Some(active_infinity::Provenance {
        parent: Some(secret),
        ..active_infinity::Provenance::default()
    }));
    let root = module.push(Inode::Table {
        fields: vec![("secret".into(), node), ("blob".into(), blob)],
    });
    module.set_root(Some(root));
    let text = format!("{module:?}");
    let hex: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
    assert!(!text.contains(&hex), "{text}");
}

/// The canonical image is a fixed point. A fragment in stored metadata is
/// refused on the first pass; without one, re-encoding a decoded image is a
/// no-op.
#[test]
fn the_canonical_image_is_a_fixed_point() {
    let build = |metadata_mentions_fragment: bool| {
        let mut module = InfinityModule::new();
        let name = module.push(Inode::Str("svc".into()));
        let interp = module.push(Inode::Interpolate {
            parts: vec![
                active_infinity::InterpPart::Literal("hunter-".into()),
                active_infinity::InterpPart::Expr(name),
            ],
        });
        let secret = module.push(Inode::SecretRef { locator: interp });
        let root = module.push(Inode::Table {
            fields: vec![("password".into(), secret)],
        });
        module.set_root(Some(root));
        let note = if metadata_mentions_fragment {
            "hunter- note"
        } else {
            "a note"
        };
        module.annotate(root, AnnotationKind::Intent(note.into()));
        module
    };

    let image = encode(&build(false)).expect("encode");
    validate_canonical(&image, Limits::default()).expect("canonical");
    let decoded = active_infinity::decode(&image).expect("decode");
    assert_eq!(encode(&decoded).expect("re-encode"), image);

    // A fragment in stored metadata cannot be represented: refuse it, and the
    // refusal must not depend on a round trip.
    let error = encode(&build(true)).expect_err("a fragment in metadata is refused");
    assert_eq!(error.code(), "infinity/encode", "{error}");
}
