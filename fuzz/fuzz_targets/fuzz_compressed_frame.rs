#![no_main]

//! Compressed frames are attacker-controlled: decompression must fail closed at
//! the caller's ceiling, with or without a dictionary, and must never panic.

use libfuzzer_sys::fuzz_target;

use active_infinity::compress::{decompress, decompress_with_dictionary};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let ceiling = data.len().saturating_mul(4).max(1);
    let _ = decompress(data, ceiling);
    let _ = decompress(data, 0);
    // A hostile dictionary is as untrusted as the frame.
    let split = data.len() / 2;
    let _ = decompress_with_dictionary(&data[..split], ceiling, &data[split..]);
    let _ = decompress_with_dictionary(data, 64, data);
});
