#![no_main]

//! Redacted JSON and Protobuf projections must agree.
//!
//! Invariants under test (I-1, I-3, I-9):
//!
//! 1. Both projections of the same logical module contain the secret marker and
//!    neither contains the secret literal.
//! 2. Projection output is deterministic and depends on logical content, not on
//!    arena order: decode(encode(module)) projects identically.
//! 3. The protobuf projection advertises the same content hash as the canonical
//!    image and never copies a secret.
//!
//! Run with `cargo +nightly fuzz run fuzz_projection_agreement -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_infinity::interop::SECRET_MARKER;
use active_infinity::{
    decode, encode, hash_image, to_protobuf, validate, InfinityModule, Inode, SecretBytes,
};

#[path = "common.rs"]
mod common;

fn with_secret(literal: &str, reorder: bool) -> InfinityModule {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from(literal)));
    let number = module.push(Inode::Int(9));
    let mut fields = vec![
        ("s".into(), secret),
        ("n".into(), number),
        ("text".into(), { module.push(Inode::Str("plain".into())) }),
    ];
    if reorder {
        fields.reverse();
    }
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));
    module
}

fuzz_target!(|data: &[u8]| {
    let literal = common::canary(data);
    let module = with_secret(&literal, data.first().copied().unwrap_or(0) % 2 == 1);

    // 1. JSON and protobuf agree on redaction.
    let json = active_infinity::interop::to_redacted_json(&module).expect("JSON projection");
    let protobuf = to_protobuf(&module).expect("protobuf projection");
    assert!(!json.contains(&literal), "JSON leaked the secret");
    assert!(
        !String::from_utf8_lossy(&protobuf).contains(&literal),
        "protobuf leaked the secret"
    );
    assert!(json.contains(SECRET_MARKER), "JSON must carry the marker");
    assert!(
        protobuf
            .windows(SECRET_MARKER.len())
            .any(|window| window == SECRET_MARKER.as_bytes()),
        "protobuf must carry the marker"
    );

    // 2. Logical identity, not arena order.
    let image = encode(&module).expect("module encodes");
    let decoded = decode(&image).expect("canonical image decodes");
    let json_again = active_infinity::interop::to_redacted_json(&decoded).expect("JSON");
    let protobuf_again = to_protobuf(&decoded).expect("protobuf");
    assert_eq!(json, json_again, "JSON depends on arena order");
    assert_eq!(protobuf, protobuf_again, "protobuf depends on arena order");

    // 3. The advertised hash is the canonical image hash.
    let hash = hash_image(&image).expect("hash");
    assert!(
        protobuf.windows(hash.len()).any(|window| window == hash),
        "the protobuf projection must advertise the content hash"
    );
    assert!(validate(&image).is_ok(), "the source module must validate");

    // A cyclic hand-built module must be refused, not recurse.
    let mut cyclic = InfinityModule::new();
    let a = cyclic.push(Inode::Ref(active_infinity::NodeId(1)));
    let b = cyclic.push(Inode::Ref(a));
    cyclic.set_root(Some(b));
    let _ = active_infinity::interop::to_redacted_json(&cyclic);
    let _ = to_protobuf(&cyclic);
});
