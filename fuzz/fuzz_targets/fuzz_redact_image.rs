#![no_main]
//! Redaction is the secret boundary: `redact_image` and the redacted JSON
//! projections must never carry a secret literal, must stay total on
//! hostile images, and must be idempotent — a redacted image redacts to
//! itself (INF-POLY-05).

use libfuzzer_sys::fuzz_target;

use active_infinity::interop::{
    redact_image, redact_module, to_redacted_json, to_redacted_json_pretty, SECRET_MARKER,
};
use active_infinity::{decode, encode, validate};

#[path = "common.rs"]
mod common;

/// The fixture's canary secret, which no redacted output may carry.
const CANARY: &str = "canary-0123456789";

/// The compact and pretty projections of one module, as plain text.
fn projections(module: &active_infinity::InfinityModule) -> (String, String) {
    let compact = to_redacted_json(module).expect("a module projects");
    let pretty = to_redacted_json_pretty(module).expect("a module projects pretty");
    (compact, pretty)
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    // Canary leg, every iteration: the fixture carries a known secret, so
    // the redaction oracle is exact, not statistical.
    let fixture = common::fixture();
    let (compact, pretty) = projections(&fixture);
    assert!(
        !compact.contains(CANARY),
        "the compact projection leaks the canary"
    );
    assert!(
        !pretty.contains(CANARY),
        "the pretty projection leaks the canary"
    );
    assert!(
        pretty.contains(SECRET_MARKER),
        "the pretty projection marks the secret"
    );
    assert_eq!(
        pretty
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>(),
        compact
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>(),
        "the pretty projection is the compact one, spaced"
    );
    let redacted = redact_module(&fixture).expect("the fixture redacts");
    let (compact, pretty) = projections(&redacted);
    assert!(
        !compact.contains(CANARY),
        "a redacted module leaks the canary"
    );
    assert!(
        !pretty.contains(CANARY),
        "a redacted module leaks the canary (pretty)"
    );
    let image = encode(&fixture).expect("the fixture encodes");
    let once = redact_image(&image).expect("the fixture image redacts");
    assert!(validate(&once).is_ok(), "a redacted image validates");
    let twice = redact_image(&once).expect("a redacted image re-redacts");
    assert_eq!(once, twice, "redaction is idempotent");
    let decoded = decode(&once).expect("a redacted image decodes");
    assert_eq!(
        encode(&decoded).expect("a redacted image re-encodes"),
        once,
        "a redacted image is canonical"
    );

    // Fuzz leg: the input bytes as an image.
    match redact_image(data) {
        Ok(redacted) => {
            assert!(validate(&redacted).is_ok(), "a redacted image validates");
            let module = decode(&redacted).expect("a redacted image decodes");
            assert_eq!(
                encode(&module).expect("a redacted image re-encodes"),
                redacted,
                "a redacted image is canonical"
            );
            let again = redact_image(&redacted).expect("a redacted image re-redacts");
            assert_eq!(redacted, again, "redaction is idempotent on fuzz input");
            let (compact, pretty) = projections(&module);
            assert_eq!(
                pretty
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>(),
                compact
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>(),
                "the projections agree on fuzz input"
            );
        }
        Err(error) => assert!(
            error.code().starts_with("infinity/"),
            "redaction refusal without a codec code: {error}"
        ),
    }
});
