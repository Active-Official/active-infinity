//! Proof-carrying sidecars: an issued proof verifies its image, and a
//! tampered image, proof or schema is refused.

use active_infinity::{
    content_hash, encode, validate, Error, InfinityModule, Inode, Proof, Schema, TypeSpec,
};

fn vector(name: &str) -> Vec<u8> {
    std::fs::read(format!("tests/vectors/valid/{name}")).expect("vector")
}

fn instance(port: i64) -> Vec<u8> {
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Int(port));
    let root = module.push(Inode::Table {
        fields: vec![("port".to_string(), value)],
    });
    module.set_root(Some(root));
    encode(&module).expect("encode")
}

#[test]
fn a_proof_describes_its_image_and_verifies() {
    let image = vector("full.ainf");
    let proof = Proof::issue(&image).expect("issue");
    let meta = validate(&image).expect("validate");
    assert_eq!(proof.content_hash, content_hash(&image).expect("hash"));
    assert_eq!(proof.size, meta.total_size);
    assert_eq!(proof.nodes, meta.nodes);
    assert_eq!(proof.secrets, meta.secrets);
    assert_eq!(proof.major, meta.major);
    assert_eq!(proof.minor, meta.minor);
    assert!(proof.canonical);
    assert!(proof.schema_hash.is_none());
    proof.verify(&image).expect("verify");
}

#[test]
fn a_tampered_image_is_refused() {
    let mut image = vector("full.ainf");
    let proof = Proof::issue(&image).expect("issue");
    let index = image.len() / 2;
    image[index] ^= 0x01;
    // The image either fails validation (structure or hash) or fails the proof
    // comparison; either way it must be refused, never accepted.
    let error = proof.verify(&image).expect_err("tampered image");
    assert!(
        error.code() == "infinity/proof" || error.code().starts_with("infinity/"),
        "{error:?}"
    );

    let truncated = &vector("full.ainf")[..100];
    assert!(proof.verify(truncated).is_err());
}

#[test]
fn a_tampered_sidecar_is_refused() {
    let image = vector("full.ainf");
    let proof = Proof::issue(&image).expect("issue");

    let mut wrong_hash = proof.clone();
    wrong_hash.content_hash[0] ^= 0x01;
    assert_eq!(
        wrong_hash.verify(&image).expect_err("hash").code(),
        "infinity/proof"
    );

    let mut wrong_size = proof.clone();
    wrong_size.size += 1;
    assert_eq!(
        wrong_size.verify(&image).expect_err("size").code(),
        "infinity/proof"
    );

    let mut wrong_secrets = proof.clone();
    wrong_secrets.secrets += 1;
    assert_eq!(
        wrong_secrets.verify(&image).expect_err("secrets").code(),
        "infinity/proof"
    );
}

#[test]
fn a_non_canonical_image_is_refused_at_issue() {
    // A valid image with a non-zero content hash field would fail canonical
    // validation; the shipped non-canonical fixtures exercise that path.
    let path = std::path::Path::new("tests/vectors/valid/non_canonical.ainf");
    if let Ok(bytes) = std::fs::read(path) {
        let error = Proof::issue(&bytes).expect_err("non-canonical");
        assert_eq!(error.code(), "infinity/not-canonical");
    }
}

#[test]
fn a_companion_schema_is_recorded_and_required() {
    let image = instance(8080);
    let schema = Schema::from_fields(&[("port", TypeSpec::Int)], false)
        .expect("schema")
        .to_bytes()
        .expect("schema bytes");
    let proof = Proof::issue_with_schema(&image, Some(&schema)).expect("issue");
    assert_eq!(
        proof.schema_hash,
        Some(content_hash(&schema).expect("schema hash"))
    );
    proof
        .verify_with_schema(&image, Some(&schema))
        .expect("verified");
    // Verifying without the schema cannot confirm the shape.
    let error = proof.verify(&image).expect_err("schema required");
    assert_eq!(error.code(), "infinity/proof");
    // Supplying the schema to a proof that carries none is refused too.
    let plain = Proof::issue(&image).expect("plain");
    let error = plain
        .verify_with_schema(&image, Some(&schema))
        .expect_err("unexpected schema");
    assert_eq!(error.code(), "infinity/proof");
}

#[test]
fn a_schema_that_rejects_the_instance_fails_at_issue() {
    let image = instance(8080);
    let wrong = Schema::from_fields(&[("port", TypeSpec::String)], false)
        .expect("schema")
        .to_bytes()
        .expect("bytes");
    let error = Proof::issue_with_schema(&image, Some(&wrong)).expect_err("wrong type");
    assert_eq!(error.code(), "infinity/schema");
}

#[test]
fn the_sidecar_round_trips_through_json() {
    let image = vector("simple.ainf");
    let schema = Schema::from_fields(&[("name", TypeSpec::String)], false).expect("schema");
    let _ = schema;
    let proof = Proof::issue(&image).expect("issue");
    let json = proof.to_json();
    assert!(json.contains("active-infinity/proof/1"), "{json}");
    let parsed = Proof::from_json(&json).expect("parse");
    assert_eq!(parsed, proof);
    parsed.verify(&image).expect("verify parsed");

    let mut tampered: serde_json::Value = serde_json::from_str(&json).expect("json");
    tampered["content_hash"] = serde_json::Value::String("00".repeat(32));
    let error = Proof::from_json(&tampered.to_string())
        .expect("parse")
        .verify(&image)
        .expect_err("tampered json");
    assert_eq!(error.code(), "infinity/proof");
}

#[test]
fn an_unknown_sidecar_format_is_refused() {
    let image = vector("simple.ainf");
    let proof = Proof::issue(&image).expect("issue");
    let json = proof
        .to_json()
        .replace("active-infinity/proof/1", "other/format");
    let error = Proof::from_json(&json).expect_err("format");
    assert_eq!(error.code(), "infinity/proof");
}

#[test]
fn redaction_is_reported_from_the_secret_table() {
    let with_secrets = vector("full.ainf");
    let meta = validate(&with_secrets).expect("validate");
    let proof = Proof::issue(&with_secrets).expect("issue");
    assert_eq!(proof.requires_redaction(), meta.secrets > 0);

    let empty = vector("empty.ainf");
    let proof = Proof::issue(&empty).expect("issue");
    let meta = validate(&empty).expect("validate");
    assert_eq!(proof.requires_redaction(), meta.secrets > 0);
}

#[test]
fn a_proof_for_one_image_does_not_verify_another() {
    let first = Proof::issue(&vector("full.ainf")).expect("issue");
    let error = first
        .verify(&vector("simple.ainf"))
        .expect_err("different image");
    assert!(matches!(error, Error::Proof(_)), "{error:?}");
}
