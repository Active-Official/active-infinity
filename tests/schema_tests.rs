//! C-3.2 schema accept/reject and hash-boundary tests.

use active_infinity::ir::TypeSpec;
use active_infinity::{content_hash, encode, validate, InfinityModule, Inode, Schema};

fn instance(extra: bool) -> InfinityModule {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("gateway".into()));
    let port = module.push(Inode::Int(8787));
    let mut fields = vec![("name".into(), name), ("port".into(), port)];
    if extra {
        let extra = module.push(Inode::Bool(true));
        fields.push(("extra".into(), extra));
    }
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));
    module
}

fn schema(closed: bool) -> Schema {
    Schema::from_fields(
        &[("name", TypeSpec::String), ("port", TypeSpec::Int)],
        closed,
    )
    .expect("schema")
}

#[test]
fn schema_accepts_the_declared_shape() {
    let instance = instance(false);
    schema(true).validate_instance(&instance).expect("valid");
}

#[test]
fn schema_rejects_missing_wrong_type_and_unknown_fields() {
    let empty = InfinityModule::new();
    let error = schema(true).validate_instance(&empty).expect_err("no root");
    assert_eq!(error.code(), "infinity/schema");

    let mut missing = InfinityModule::new();
    let name = missing.push(Inode::Str("gateway".into()));
    let root = missing.push(Inode::Table {
        fields: vec![("name".into(), name)],
    });
    missing.set_root(Some(root));
    let error = schema(true)
        .validate_instance(&missing)
        .expect_err("missing");
    assert_eq!(error.code(), "infinity/schema");

    let mut wrong = InfinityModule::new();
    let name = wrong.push(Inode::Bool(true));
    let port = wrong.push(Inode::Int(1));
    let root = wrong.push(Inode::Table {
        fields: vec![("name".into(), name), ("port".into(), port)],
    });
    wrong.set_root(Some(root));
    let error = schema(true)
        .validate_instance(&wrong)
        .expect_err("wrong type");
    assert_eq!(error.code(), "infinity/schema");

    let unknown = instance(true);
    let error = schema(true)
        .validate_instance(&unknown)
        .expect_err("closed");
    assert_eq!(error.code(), "infinity/schema");
    schema(false)
        .validate_instance(&unknown)
        .expect("open accepts");
}

#[test]
fn schema_round_trips_as_canonical_ainf() {
    let schema = schema(true);
    let bytes = schema.to_bytes().expect("schema encode");
    validate(&bytes).expect("schema validate");
    let decoded = Schema::from_bytes(&bytes).expect("schema decode");
    assert_eq!(decoded.field_names().expect("names"), vec!["name", "port"]);
    assert!(decoded.is_closed());
}

#[test]
fn schema_never_changes_the_instance_hash() {
    let instance = instance(false);
    let before = content_hash(&encode(&instance).expect("encode")).expect("hash");
    schema(true).validate_instance(&instance).expect("valid");
    let after = content_hash(&encode(&instance).expect("encode")).expect("hash");
    assert_eq!(before, after);
}

#[test]
fn schema_from_bytes_canonicalizes_non_canonical_input() {
    // INF-SCHEMA-05: a schema image that is not the canonical encoding of its
    // content still loads, and the stored module is the canonical form. The
    // unflagged variant below is the W5/INF-02 flag-cleared shape; the W4 probe
    // used a slack string (376 in vs 368 out) -- both go through the same
    // lenient-decode, re-encode, strict-decode path in `from_bytes`.
    let schema = schema(true);
    let canonical = schema.to_bytes().expect("schema encode");
    let unflagged = active_infinity::encode::encode_with(
        schema.module(),
        active_infinity::layout::EncodeOpts {
            write_hash: true,
            mark_canonical: false,
            streamed: false,
        },
    )
    .expect("encode without the canonical flag");
    assert_ne!(canonical, unflagged, "the unflagged variant must differ");
    let loaded = Schema::from_bytes(&unflagged).expect("non-canonical schema loads");
    assert_eq!(
        loaded.to_bytes().expect("schema encode"),
        canonical,
        "the stored schema re-encodes to the canonical bytes"
    );
    assert_eq!(
        encode(loaded.module()).expect("module encode"),
        canonical,
        "module() is the canonical form, not the input form"
    );
    assert!(loaded.is_closed());
    assert_eq!(loaded.field_names().expect("names"), vec!["name", "port"]);
}
