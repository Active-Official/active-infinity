//! Writes deterministic seeds for the targets whose parser has a positive
//! branch. A refused seed only ever exercises the error path, so the oracle on
//! a successful parse would never run.
//!
//! Regenerate with:
//!   cargo run --manifest-path fuzz/Cargo.toml --example gen_seeds

use std::fs;
use std::path::PathBuf;

use active_infinity::{
    encode, InfinityModule, Inode, Proof, Schema, SchemaFieldSpec, SignedImage, TypeSpec,
};

fn fixture() -> Vec<u8> {
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Str("seed-fixture".into()));
    let root = module.push(Inode::Table {
        fields: vec![("value".into(), value)],
    });
    module.set_root(Some(root));
    encode(&module).expect("fixture encodes")
}

fn schema_image() -> Vec<u8> {
    let mut module = InfinityModule::new();
    let field = module.push(Inode::SchemaField(SchemaFieldSpec {
        typ: TypeSpec::Int,
        min: None,
        max: None,
        min_len: None,
        max_len: None,
        pattern: None,
        default: None,
        deprecated: None,
    }));
    let table = module.push(Inode::SchemaTable {
        fields: vec![("value".into(), field)],
        closed: true,
    });
    module.set_root(Some(table));
    encode(&module).expect("schema encodes")
}

fn main() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let image = fixture();

    // A complete envelope under a fixed key.
    let signed = SignedImage::sign_with_seed(image.clone(), &[7u8; 32]).expect("sign");
    let bytes = signed.to_bytes();
    assert!(SignedImage::from_bytes(&bytes).is_ok(), "the seed must verify");
    write(&corpus.join("fuzz_signed_image/valid-envelope"), &bytes);

    // A sidecar that describes the fixture.
    let proof = Proof::issue(&image).expect("issue");
    let json = proof.to_json();
    assert!(Proof::from_json(&json).is_ok(), "the seed must parse");
    write(&corpus.join("fuzz_proof_sidecar/valid-proof.json"), json.as_bytes());

    // A schema-class image with a positive branch.
    let schema = schema_image();
    assert!(Schema::from_bytes(&schema).is_ok(), "the seed must parse");
    write(&corpus.join("fuzz_schema/schema.ainf"), &schema);

    println!("wrote deterministic seeds under {}", corpus.display());
}

fn write(path: &std::path::Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("corpus directory");
    }
    fs::write(path, bytes).expect("seed");
}
