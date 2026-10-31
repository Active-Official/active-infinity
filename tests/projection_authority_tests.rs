#![cfg(feature = "json")]

//! Projections are views, never the system of record: editing one cannot move
//! the content address, and neither projection is a valid AINF image.

use active_infinity::interop::{to_redacted_json, SECRET_MARKER};
use active_infinity::{
    content_hash, decode, encode, to_protobuf, validate, InfinityModule, Inode, SecretBytes,
};

fn module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::new(
        "CANARY_SECRET_PROJECTION_AUTHORITY",
    )));
    let count = module.push(Inode::Int(7));
    let name = module.push(Inode::Str("projection".to_string()));
    let root = module.push(Inode::Table {
        fields: vec![
            ("count".to_string(), count),
            ("name".to_string(), name),
            ("token".to_string(), secret),
        ],
    });
    module.set_root(Some(root));
    module
}

#[test]
fn editing_the_json_projection_cannot_change_the_address() {
    let module = module();
    let image = encode(&module).expect("encode");
    let address = content_hash(&image).expect("hash");
    let json = to_redacted_json(&decode(&image).expect("decode")).expect("json");
    // An "edit" to the view changes nothing about the bytes or the address.
    let edited = json.replace("\"count\":7", "\"count\":1000000");
    assert_ne!(edited, json);
    assert_eq!(content_hash(&image).expect("hash"), address);
    assert!(validate(&image).is_ok());
    // The projection is not an image: validation refuses it.
    assert!(validate(edited.as_bytes()).is_err());
    assert!(validate(json.as_bytes()).is_err());
}

#[test]
fn the_protobuf_projection_is_not_an_image() {
    let module = module();
    let image = encode(&module).expect("encode");
    let address = content_hash(&image).expect("hash");
    let projection = to_protobuf(&module).expect("protobuf");
    assert!(validate(&projection).is_err(), "protobuf is not AINF");
    // The projection carries the address so a consumer can check it, but the
    // address itself still comes from the AINF bytes.
    assert!(projection
        .windows(address.len())
        .any(|window| window == address));
    assert_eq!(content_hash(&image).expect("hash"), address);
}

#[test]
fn neither_projection_carries_secret_material() {
    let module = module();
    let image = encode(&module).expect("encode");
    let decoded = decode(&image).expect("decode");
    let json = to_redacted_json(&decoded).expect("json");
    let protobuf = to_protobuf(&module).expect("protobuf");
    for (name, bytes) in [("json", json.as_bytes()), ("protobuf", &protobuf[..])] {
        let leaked = bytes
            .windows("CANARY_SECRET_PROJECTION_AUTHORITY".len())
            .any(|window| window == b"CANARY_SECRET_PROJECTION_AUTHORITY");
        assert!(!leaked, "{name} carried secret material");
    }
    assert!(json.contains(SECRET_MARKER));
}

#[test]
fn a_redacted_projection_is_stable_for_the_same_image() {
    let image = encode(&module()).expect("encode");
    let first = to_redacted_json(&decode(&image).expect("decode")).expect("json");
    let second = to_redacted_json(&decode(&image).expect("decode")).expect("json");
    assert_eq!(first, second);
    // Re-encoding the decoded module reproduces the exact image (canonical).
    let module = decode(&image).expect("decode");
    assert_eq!(encode(&module).expect("encode"), image);
}
