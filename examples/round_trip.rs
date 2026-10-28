//! Round-trip a module through the canonical binary form.
//!
//! Run with `cargo run --example round_trip`.

#[cfg(feature = "json")]
use active_infinity::interop::SECRET_MARKER;
use active_infinity::{
    decode, encode, validate, validate_canonical, InfinityModule, Inode, Limits, SecretBytes,
    UnitTag,
};

fn main() {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("checkout".into()));
    let port = module.push(Inode::Int(8080));
    let milliseconds = module.push(Inode::Int(1500));
    let timeout = module.push(Inode::Quantity {
        value: milliseconds,
        unit: UnitTag::Milliseconds,
    });
    let token = module.push(Inode::Secret(SecretBytes::from("example-token-123")));
    let root = module.push(Inode::Table {
        fields: vec![
            ("name".into(), name),
            ("port".into(), port),
            ("timeout".into(), timeout),
            ("token".into(), token),
        ],
    });
    module.set_root(Some(root));

    let image = encode(&module).expect("encode");
    let meta = validate(&image).expect("validate");
    assert!(validate_canonical(&image, Limits::default()).is_ok());
    let decoded = decode(&image).expect("decode");
    assert_eq!(encode(&decoded).expect("re-encode"), image);
    assert_eq!(
        meta.content_hash,
        active_infinity::hash_image(&image).expect("hash")
    );

    println!(
        "image={} bytes nodes={} hash={:02x?}",
        image.len(),
        meta.nodes,
        &meta.content_hash[..4]
    );
    #[cfg(feature = "json")]
    {
        let json = active_infinity::interop::to_redacted_json(&decoded).expect("json");
        assert!(!json.contains("example-token-123"));
        assert!(json.contains(SECRET_MARKER));
        println!("{json}");
    }
}
