//! Writes deterministic seeds for the targets whose parser has a positive
//! branch. A refused seed only ever exercises the error path, so the oracle on
//! a successful parse would never run.
//!
//! Regenerate with:
//!   cargo run --manifest-path fuzz/Cargo.toml --example gen_seeds

use std::fs;
use std::path::PathBuf;

use active_infinity::compress::train_dictionary;
use active_infinity::interop::{from_active_source, redact_image};
use active_infinity::stream::encode_stream_with;
use active_infinity::{
    content_hash, decode, encode, validate_canonical, AnnotationKind, EncodeOpts, InfinityModule,
    Inode, Proof, Schema, SchemaFieldSpec, SecretBytes, SignedImage, TypeSpec, UnitTag,
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

/// The `common::fixture` shape (a secret-bearing module), so the redaction
/// seed exercises the secret path, not just the refusal path.
fn secret_fixture() -> Vec<u8> {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("svc".into()));
    let port = module.push(Inode::Int(8080));
    let number = module.push(Inode::Int(5));
    let quantity = module.push(Inode::Quantity {
        value: number,
        unit: UnitTag::Milliseconds,
    });
    let secret = module.push(Inode::Secret(SecretBytes::from("canary-0123456789")));
    let root = module.push(Inode::Table {
        fields: vec![
            ("name".into(), name),
            ("port".into(), port),
            ("q".into(), quantity),
            ("secret".into(), secret),
        ],
    });
    module.set_root(Some(root));
    module.annotate(root, AnnotationKind::Intent("service table".into()));
    encode(&module).expect("secret fixture encodes")
}

/// A larger valid image (a 2 KiB repetitive string), so the CLI seed's
/// `dict train` leg has enough sample bytes for its default size.
fn large_fixture() -> Vec<u8> {
    let mut module = InfinityModule::new();
    let text = module.push(Inode::Str("service config line\n".repeat(128)));
    let root = module.push(Inode::Table {
        fields: vec![("config".into(), text)],
    });
    module.set_root(Some(root));
    encode(&module).expect("large fixture encodes")
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

/// The schema the `fixture` really satisfies: one `value` string, closed.
fn fixture_schema() -> Vec<u8> {
    let schema =
        Schema::from_fields(&[("value", TypeSpec::String)], true).expect("fixture schema builds");
    schema.to_bytes().expect("fixture schema encodes")
}

fn main() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let image = fixture();

    // A complete envelope under a fixed key.
    let signed = SignedImage::sign_with_seed(image.clone(), &[7u8; 32]).expect("sign");
    let bytes = signed.to_bytes();
    assert!(
        SignedImage::from_bytes(&bytes).is_ok(),
        "the seed must verify"
    );
    write(&corpus.join("fuzz_signed_image/valid-envelope"), &bytes);

    // A sidecar that describes the fixture.
    let proof = Proof::issue(&image).expect("issue");
    let json = proof.to_json();
    assert!(Proof::from_json(&json).is_ok(), "the seed must parse");
    write(
        &corpus.join("fuzz_proof_sidecar/valid-proof.json"),
        json.as_bytes(),
    );

    // A schema-class image with a positive branch.
    let schema = schema_image();
    assert!(Schema::from_bytes(&schema).is_ok(), "the seed must parse");
    write(&corpus.join("fuzz_schema/schema.ainf"), &schema);

    // INF-POLY-05 seeds: one per new target, each asserting its positive
    // branch before it is written.

    // A valid Active source: the source target parses it, encodes it and
    // evaluates it.
    let source =
        "[app]\nname = \"service-0\"\nhost = \"node-0.internal\"\nport = 8000\nratio = 5%\n";
    assert!(
        from_active_source(source, "seed.active").is_ok(),
        "the source seed must parse"
    );
    write(
        &corpus.join("fuzz_from_active_source/seed"),
        source.as_bytes(),
    );

    // Eight repetitive samples and a training size of 4096: the dictionary
    // target trains and round-trips. (zstd's trainer needs at least seven
    // samples — fewer refuse with `infinity/compression`, which the target
    // also covers — so the seed uses eight, split exactly as the target
    // splits them: equal shares, the last taking the tail.)
    let sample = "name = \"service\"\nhost = \"node.internal\"\nport = 8000\n".repeat(512);
    let dictionary = {
        let mut samples: Vec<&[u8]> = Vec::new();
        let mut start = 0usize;
        for index in 0..8 {
            let end = if index + 1 == 8 {
                sample.len()
            } else {
                sample.len() * (index + 1) / 8
            };
            samples.push(&sample.as_bytes()[start..end]);
            start = end;
        }
        train_dictionary(&samples, 4096).expect("the seed trains")
    };
    assert!(!dictionary.is_empty(), "the seed dictionary is non-empty");
    let mut seed = vec![6u8, 0, 15];
    seed.extend_from_slice(sample.as_bytes());
    write(&corpus.join("fuzz_train_dictionary/seed"), &seed);

    // [image_len:u16][image][hash]: the store target puts the fixture and
    // the probe hash names it.
    let hash = content_hash(&image).expect("the seed image hashes");
    let mut seed = (image.len() as u16).to_le_bytes().to_vec();
    seed.extend_from_slice(&image);
    seed.extend_from_slice(&hash);
    assert!(
        validate_canonical(&image, active_infinity::Limits::default()).is_ok(),
        "the store seed must validate"
    );
    write(&corpus.join("fuzz_store/seed"), &seed);

    // [image_len:u16][schema_len:u16][image][schema][sidecar]: the proof
    // target issues over the fixture with its schema and verifies.
    let fixture_schema = fixture_schema();
    let schema_proof =
        Proof::issue_with_schema(&image, Some(&fixture_schema)).expect("the seed proof issues");
    assert!(
        schema_proof
            .verify_with_schema(&image, Some(&fixture_schema))
            .is_ok(),
        "the seed proof verifies"
    );
    let mut seed = (image.len() as u16).to_le_bytes().to_vec();
    seed.extend_from_slice(&(fixture_schema.len() as u16).to_le_bytes());
    seed.extend_from_slice(&image);
    seed.extend_from_slice(&fixture_schema);
    seed.extend_from_slice(schema_proof.to_json().as_bytes());
    write(&corpus.join("fuzz_proof_verify_schema/seed"), &seed);

    // An op script over the fixture: validate it, hash it, allocate and
    // stale-free a generational buffer, allocate and free a legacy one.
    // Ops read slices by (offset:u16, length:u16) into the whole seed.
    let mut script = Vec::new();
    // Op sizes: validate 5, content_hash 5, alloc_gen 2, free_gen 3,
    // alloc 2, free 2 — the image starts right after the script.
    let image_at = 5 + 5 + 2 + 3 + 2 + 2;
    let image_len = image.len() as u16;
    script.push(4);
    script.extend_from_slice(&(image_at as u16).to_le_bytes());
    script.extend_from_slice(&image_len.to_le_bytes());
    script.push(8);
    script.extend_from_slice(&(image_at as u16).to_le_bytes());
    script.extend_from_slice(&image_len.to_le_bytes());
    script.push(1);
    script.push(16);
    script.push(3);
    script.push(0);
    script.push(1);
    script.push(0);
    script.push(1);
    script.push(2);
    script.push(0);
    assert_eq!(
        script.len(),
        image_at,
        "the script length is the image offset"
    );
    assert!(
        active_infinity::validate(&image).is_ok(),
        "the FFI seed image must validate"
    );
    script.extend_from_slice(&image);
    write(&corpus.join("fuzz_ffi_boundary/seed"), &script);

    // Eight zero selector bytes (command 0: `validate`) over the large
    // fixture: the CLI target validates a real image, and the payload is
    // big enough for the `dict train` leg's default size.
    let large = large_fixture();
    assert!(
        active_infinity::validate(&large).is_ok(),
        "the CLI seed image must validate"
    );
    let mut seed = vec![0u8; 8];
    seed.extend_from_slice(&large);
    write(&corpus.join("fuzz_cli_args/seed"), &seed);

    // A secret-bearing image: the redaction target redacts it idempotently.
    let secret = secret_fixture();
    let once = redact_image(&secret).expect("the redaction seed must redact");
    assert_eq!(
        redact_image(&once).expect("the redaction seed must re-redact"),
        once,
        "the redaction seed must be idempotent"
    );
    write(&corpus.join("fuzz_redact_image/seed"), &secret);

    // [chunk index 4 (= 64)][flags 3 (write_hash + mark_canonical)][image]:
    // the stream target encodes the fixture with those options and
    // round-trips it (only a canonical stream round-trips).
    let module = decode(&image).expect("the fixture decodes");
    let stream_opts = EncodeOpts {
        write_hash: true,
        mark_canonical: true,
        streamed: false,
        drop_unreachable: false,
    };
    assert!(
        encode_stream_with(&module, 64, stream_opts).is_ok(),
        "the stream seed must encode"
    );
    let mut seed = vec![4u8, 3];
    seed.extend_from_slice(&image);
    write(&corpus.join("fuzz_stream_opts/seed"), &seed);

    println!("wrote deterministic seeds under {}", corpus.display());
}

fn write(path: &std::path::Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("corpus directory");
    }
    fs::write(path, bytes).expect("seed");
}
