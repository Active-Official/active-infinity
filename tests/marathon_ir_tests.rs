//! Marathon section I-05: the IR, secrets and units.

use active_infinity::{
    encode, AnnotationKind, InfinityModule, Inode, ProvKind, SchemaFieldSpec, SecretBytes, TypeSpec,
};

fn base_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(1));
    module.set_root(Some(root));
    module
}

#[test]
fn modules_with_different_extensions_are_not_equal() {
    // Extensions are sorted and hashed by canonicalization, so they are part of
    // the identity. Structural equality ignored them: two modules compared equal
    // while their bytes (and hashes) differed, which breaks dedup and signature
    // binding.
    let mut left = base_module();
    left.add_extension(1, b"payload-left".to_vec());
    let mut right = base_module();
    right.add_extension(1, b"payload-right".to_vec());
    assert!(left != right, "different extensions are different modules");
    assert_ne!(encode(&left).expect("left"), encode(&right).expect("right"));

    let mut same = base_module();
    same.add_extension(1, b"payload-left".to_vec());
    assert_eq!(left, same, "equal extensions stay equal");
}

#[test]
fn a_secret_ref_module_reports_having_a_secret() {
    // `has_secret` only matched a literal `Secret` node, so a module whose secret
    // is `secret(env.TOKEN)` answered false and any "no secret, log freely" gate
    // took the wrong branch.
    let mut module = InfinityModule::new();
    let env = module.push(Inode::Env {
        name: "TOKEN".to_string(),
        default: None,
    });
    let secret = module.push(Inode::SecretRef { locator: env });
    let root = module.push(Inode::Table {
        fields: vec![("token".to_string(), secret)],
    });
    module.set_root(Some(root));
    assert!(module.has_secret(), "a SecretRef is a secret");

    let mut plain = base_module();
    assert!(!plain.has_secret());
    let literal = plain.push(Inode::Secret(SecretBytes::from("literal-secret")));
    plain.bind("token", literal);
    assert!(plain.has_secret(), "a literal is a secret");
}

#[test]
fn a_type_name_does_not_echo_its_members() {
    // A schema type can carry a copy of a secret as an enum member; `name()` is a
    // diagnostics string and must not print it.
    let spec = TypeSpec::Enum(vec!["hunter2-canary".to_string(), "b".to_string()]);
    let name = spec.name();
    assert!(!name.contains("hunter2-canary"), "{name}");
    assert!(name.contains('2'), "the member count is kept: {name}");

    let field = SchemaFieldSpec {
        typ: spec,
        min: None,
        max: None,
        min_len: None,
        max_len: None,
        pattern: None,
        default: None,
        deprecated: None,
    };
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from("hunter2-canary")));
    let schema = module.push(Inode::SchemaField(field));
    let root = module.push(Inode::Array {
        elements: vec![secret, schema],
    });
    module.set_root(Some(root));
    module.annotate(root, AnnotationKind::Intent("schema".to_string()));
    let bytes = encode(&module).expect("encode");
    let printed = format!("{:?}", active_infinity::decode(&bytes).expect("decode"));
    assert!(!printed.contains("hunter2-canary"), "{printed}");
}

#[test]
fn the_reserved_provenance_kind_has_no_reader() {
    // Code 4 is reserved on the wire; `from_code` used to produce a kind nothing
    // can encode.
    assert!(ProvKind::from_code(4).is_none());
    for code in 0..=3 {
        let kind = ProvKind::from_code(code).expect("a defined kind");
        assert_eq!(kind.code(), code);
    }
}
