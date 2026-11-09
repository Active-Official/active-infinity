#![no_main]
//! `Proof::verify_with_schema` is the one proof entry point no target drove:
//! the sidecar, the image AND the companion schema all come from fuzz bytes,
//! so a mismatch in any of the three must refuse — with `infinity/proof`,
//! or `infinity/limit` when the image itself breaches a ceiling — and a
//! proof issued over a real image must verify (INF-POLY-05).

use libfuzzer_sys::fuzz_target;

use active_infinity::{content_hash, decode, encode, Proof};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 || data.len() > 32_768 {
        return;
    }
    // Length-prefixed split, so a seed can name each part exactly:
    // [image_len:u16 LE][schema_len:u16 LE][image][schema][sidecar JSON].
    let image_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let schema_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    let mut rest = &data[4..];
    let (image, schema_bytes, sidecar) = if rest.len() < image_len {
        (rest, &[][..], &[][..])
    } else {
        let (image, tail) = rest.split_at(image_len);
        rest = tail;
        if rest.len() < schema_len {
            (image, rest, &[][..])
        } else {
            let (schema_bytes, sidecar) = rest.split_at(schema_len);
            (image, schema_bytes, sidecar)
        }
    };
    let Ok(text) = std::str::from_utf8(sidecar) else {
        return;
    };
    match Proof::from_json(text) {
        Ok(proof) => {
            for schema in [None, Some(schema_bytes)] {
                match proof.verify_with_schema(image, schema) {
                    Ok(()) => {
                        // A verified proof describes exactly this image.
                        assert_eq!(
                            proof.content_hash,
                            content_hash(image).expect("a verified image hashes"),
                            "a verified proof names the image hash"
                        );
                    }
                    // `verify_with_schema` maps every image/schema fault to
                    // the sidecar code and passes a resource ceiling through.
                    Err(error) => assert!(
                        matches!(error.code(), "infinity/proof" | "infinity/limit"),
                        "verify refusal without the sidecar code: {error}"
                    ),
                }
            }
        }
        Err(error) => assert_eq!(error.code(), "infinity/proof", "parse code"),
    }
    // Positive leg: issue over a real image, then verify with and without
    // the schema that was (or was not) supplied.
    if let Ok(module) = decode(image) {
        let image = encode(&module).expect("a decoded module encodes");
        match Proof::issue_with_schema(&image, Some(schema_bytes)) {
            Ok(proof) => {
                proof
                    .verify_with_schema(&image, Some(schema_bytes))
                    .expect("an issued proof verifies with its schema");
                // Without the schema the same proof must refuse: the schema
                // hash is part of what was issued.
                assert!(
                    proof.verify_with_schema(&image, None).is_err(),
                    "a schema-bound proof refuses without its schema"
                );
                // And a proof issued with no schema verifies with none
                // but refuses when one is supplied: the supplied schema
                // is not the one the proof was issued with (it has none).
                let plain = Proof::issue(&image).expect("a plain proof issues");
                plain
                    .verify_with_schema(&image, None)
                    .expect("a plain proof verifies");
                assert!(
                    plain
                        .verify_with_schema(&image, Some(schema_bytes))
                        .is_err(),
                    "a plain proof refuses a schema it does not carry"
                );
            }
            Err(error) => assert!(
                error.code().starts_with("infinity/"),
                "issue refusal without a codec code: {error}"
            ),
        }
    }
});
