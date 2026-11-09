#![no_main]
//! Active text is the agent-facing input to the codec: `from_active_source`
//! parses it and `evaluate` runs it under a budget. Both must stay total:
//! hostile text parses or refuses with an `infinity/*` code, never panics,
//! and a parsed module encodes to a valid canonical image that evaluates
//! inside its budget (INF-POLY-05).
//!
//! One exception to "a parsed module encodes": the encoder fail-closes
//! (INF-04) on a module with an unreachable node — the bridge lowers the
//! whole active-core arena, so a source with a dead definition yields a
//! module no root reaches, and default `encode()` refuses it with
//! `infinity/node` rather than silently dropping data (which may include
//! secrets). That refusal is legitimate, so the target accepts it and
//! instead requires the dropping path to succeed and validate.

use libfuzzer_sys::fuzz_target;

use active_infinity::interop::{evaluate, from_active_source};
use active_infinity::{encode, encode_with, validate, EncodeOpts};

fuzz_target!(|data: &[u8]| {
    // The parser is the slow part; cap the input so one iteration stays fast.
    if data.len() > 8192 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match from_active_source(text, "fuzz.active") {
        Ok(module) => {
            match encode(&module) {
                Ok(image) => {
                    assert!(validate(&image).is_ok(), "a parsed module validates");
                }
                Err(error) => {
                    // Legitimate only for the fail-closed unreachable-node
                    // refusal (INF-04); anything else is a real defect.
                    assert_eq!(
                        error.code(),
                        "infinity/node",
                        "encode refusal without the node code: {error}"
                    );
                    let image = encode_with(
                        &module,
                        EncodeOpts {
                            drop_unreachable: true,
                            ..EncodeOpts::default()
                        },
                    )
                    .expect("a parsed module encodes with unreachable nodes dropped");
                    assert!(
                        validate(&image).is_ok(),
                        "a parsed module validates after dropping unreachable nodes"
                    );
                }
            }
            // A bounded budget: evaluation must stay total even for a hostile
            // module (the default wall clock is 100 ms, and every other
            // ceiling is a count, so no input can burn the iteration).
            if let Err(error) = evaluate(&module, active_core::Budget::default()) {
                assert!(
                    error.code().starts_with("infinity/"),
                    "evaluation refusal without a codec code: {error}"
                );
            }
        }
        Err(error) => assert!(
            error.code().starts_with("infinity/"),
            "source parse refusal without a codec code: {error}"
        ),
    }
});
