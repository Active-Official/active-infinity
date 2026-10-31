#![no_main]

//! Compressed frames are attacker-controlled: decompression must fail closed at
//! the caller's ceiling, with or without a dictionary, and must never panic.
//!
//! The oracles are fixed, not input-scaled: a 64-byte ceiling is a 64-byte
//! ceiling whatever the input, the committed expansion bomb must be refused at
//! that ceiling, and a round trip must be the identity.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

use active_infinity::compress::{compress, decompress, decompress_with_dictionary};

/// One MiB of zeros compresses to a few hundred bytes. Its expansion is the
/// classic decompression bomb.
fn bomb() -> &'static [u8] {
    static BOMB: OnceLock<Vec<u8>> = OnceLock::new();
    BOMB.get_or_init(|| compress(&[0u8; 1 << 20], 3).expect("compressing zeros"))
}

fuzz_target!(|data: &[u8]| {
    // A successful decode never exceeds the ceiling it was given.
    if let Ok(output) = decompress(data, 64) {
        assert!(
            output.len() <= 64,
            "decompress returned {} bytes for a 64-byte ceiling",
            output.len()
        );
    }
    // A zero ceiling can only produce an empty output.
    if let Ok(output) = decompress(data, 0) {
        assert!(output.is_empty(), "a zero ceiling produced bytes");
    }

    // The bomb must fail at the small ceiling whatever the fuzz input is.
    let bomb = bomb();
    let refused = decompress(bomb, 64).expect_err("a decompression bomb passed the ceiling");
    assert_eq!(
        refused.code(),
        "infinity/compression",
        "an over-ceiling frame must be a compression failure"
    );
    // ... and must decompress at a ceiling it fits, or the harness itself is
    // wrong.
    let expanded = decompress(bomb, 1 << 21).expect("the bomb fits a large ceiling");
    assert_eq!(expanded.len(), 1 << 20);

    // Round trip: compress then decompress is the identity when the ceiling
    // admits the input.
    let ceiling = data.len().max(1);
    if let Ok(packed) = compress(data, 3) {
        let round = decompress(&packed, ceiling).expect("a frame we just made decompresses");
        assert_eq!(round, data, "compress/decompress is not the identity");
    }

    // A hostile dictionary is as untrusted as the frame.
    let split = data.len() / 2;
    let _ = decompress_with_dictionary(&data[..split], 64, &data[split..]);
    let _ = decompress_with_dictionary(data, 64, data);
});
