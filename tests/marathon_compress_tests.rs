#![cfg(feature = "zstd")]

//! Marathon I-09: the compression profile's refusal surface.
//!
//! Compression is a transport helper, so its contract is "never surprise the
//! caller": empty input is not a frame, a level outside the build's zstd range
//! is refused instead of silently clamped, and dictionary training refuses
//! parameters zstd cannot use.

use active_infinity::compress::{
    compress, decompress, decompress_with_dictionary, level_range, train_dictionary,
};

#[test]
fn empty_input_is_not_a_frame() {
    let error = decompress(&[], 64).expect_err("empty input is not a zstd frame");
    assert_eq!(error.code(), "infinity/compression", "{error}");
    assert!(
        decompress_with_dictionary(&[], 64, &[]).is_err(),
        "the dictionary path refuses empty input too"
    );
}

#[test]
fn an_out_of_range_level_is_refused() {
    let (minimum, maximum) = level_range();
    assert!(maximum > 0 && minimum < 0, "zstd reports a signed range");
    let high = compress(b"payload", maximum + 1).expect_err("above the range");
    assert_eq!(high.code(), "infinity/invalid-argument", "{high}");
    let low = compress(b"payload", minimum - 1).expect_err("below the range");
    assert_eq!(low.code(), "infinity/invalid-argument", "{low}");
    assert!(compress(b"payload", maximum).is_ok());
    assert!(compress(b"payload", minimum).is_ok());
}

#[test]
fn dictionary_training_refuses_impossible_parameters() {
    let zero = train_dictionary(&[vec![1u8; 8]], 0).expect_err("zero capacity");
    assert_eq!(zero.code(), "infinity/invalid-argument", "{zero}");
    let empty = train_dictionary::<Vec<u8>>(&[], 1024).expect_err("no samples");
    assert_eq!(empty.code(), "infinity/invalid-argument", "{empty}");
}

#[test]
fn a_dictionary_is_a_hint_not_a_gate() {
    // Pinned as documented behaviour: a plain frame decompresses with any
    // dictionary, so a successful dictionary decode says nothing about the
    // producer. Authenticity comes from the signature envelope.
    let image = compress(b"plain frame", 3).expect("compress");
    let via_dictionary = decompress_with_dictionary(&image, 64, b"not the dictionary")
        .expect("a hint is not a requirement");
    assert_eq!(via_dictionary, b"plain frame");
}
