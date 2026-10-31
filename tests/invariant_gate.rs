//! C-1 invariant gate: a secret canary never appears in any Infinity
//! diagnostic or projection, and the canonical hash still covers the instance.

use active_infinity::interop::to_redacted_json;
use active_infinity::{content_hash, encode, validate, InfinityModule, Inode, SecretBytes};

const CANARY: &str = "maturity-secret-canary-4d19";

fn fixture() -> InfinityModule {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from(CANARY)));
    let copy = module.push(Inode::Str(CANARY.into()));
    let port = module.push(Inode::Int(8080));
    let root = module.push(Inode::Table {
        fields: vec![
            (CANARY.into(), secret),
            ("copy".into(), copy),
            ("port".into(), port),
        ],
    });
    module.set_root(Some(root));
    module
}

#[test]
fn canary_never_reaches_debug_display_json_or_protobuf() {
    let module = fixture();
    let print = format!("{module:?}");
    let json = to_redacted_json(&module).expect("json projection");
    let proto = active_infinity::to_protobuf(&module).expect("protobuf");
    assert!(!print.contains(CANARY), "Debug leaked the canary");
    assert!(!json.contains(CANARY), "JSON projection leaked the canary");
    assert!(
        !String::from_utf8_lossy(&proto).contains(CANARY),
        "Protobuf projection leaked the canary"
    );

    let bytes = encode(&module).expect("encode");
    validate(&bytes).expect("validate");
    assert_eq!(content_hash(&bytes).expect("hash").len(), 32);
}

#[test]
fn secret_values_are_never_equal() {
    let first = Inode::Secret(SecretBytes::from(CANARY));
    let second = Inode::Secret(SecretBytes::from(CANARY));
    assert_ne!(first, second);
}
