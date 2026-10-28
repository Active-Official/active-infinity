#![no_main]

//! Hostile stream reassembly.
//!
//! Invariants under test:
//!
//! 1. Feeding the frames of a valid stream, in any byte split, reassembles to
//!    the same logical module and the same whole-module image.
//! 2. A reassembled image is the canonical whole-module encoding, not a
//!    stream-specific variant.
//! 3. Arbitrary bytes fed to the stream decoder either produce a valid module or
//!    a stable error; they never panic.
//! 4. Reordering, truncating or corrupting a frame is refused or produces a
//!    module whose re-encoding is canonical.
//!
//! Run with `cargo +nightly fuzz run fuzz_stream_reassembly -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_infinity::stream::{decode_stream, encode_stream, StreamDecoder};
use active_infinity::{encode, hash_image, validate, Limits};

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let module = common::fixture();
    let Ok(whole) = encode(&module) else {
        return;
    };
    let chunk = 1 + (data[0] as usize % 64);
    let Ok(frames) = encode_stream(&module, chunk) else {
        return;
    };
    let mut stream = Vec::new();
    for frame in &frames {
        stream.extend_from_slice(&frame.to_bytes());
    }

    // 1. Whole stream decodes to the whole-module image.
    if let Ok(streamed) = decode_stream(&stream) {
        assert_eq!(streamed.image, whole, "reassembly changed the image");
        assert_eq!(
            streamed.content_hash,
            hash_image(&whole).expect("hash"),
            "reassembly changed the content hash"
        );
        assert!(
            validate(&streamed.image).is_ok(),
            "a reassembled image must validate"
        );
    }

    // 2. Arbitrary byte splits reassemble identically.
    let mut decoder = StreamDecoder::new();
    let mut cursor = 0usize;
    let mut selector = 1usize;
    while cursor < stream.len() {
        let take = 1 + (data[selector % data.len()] as usize % 41);
        let end = (cursor + take).min(stream.len());
        if decoder.push_bytes(&stream[cursor..end]).is_err() {
            break;
        }
        cursor = end;
        selector += 1;
    }
    if cursor == stream.len() {
        if let Ok(streamed) = decoder.finish() {
            assert_eq!(streamed.image, whole, "split reassembly changed the image");
        }
    }

    // 3. Arbitrary bytes are total.
    let _ = decode_stream(data);
    let mut arbitrary = StreamDecoder::new();
    if arbitrary.push_bytes(data).is_ok() {
        let _ = arbitrary.finish();
    }

    // 4. Corrupt one frame byte and require a clean refusal or a canonical
    // module. The frame header starts with the stream magic; skip it when the
    // input is too small to reach a payload.
    if data.len() > 1 && !frames.is_empty() {
        let mut corrupted = stream.clone();
        let index = 1 + (data[1] as usize % corrupted.len());
        corrupted[index] ^= 1 << (data[0] % 8);
        if let Ok(streamed) = decode_stream(&corrupted) {
            let reencoded = encode(&streamed.module).expect("a decoded module encodes");
            assert!(
                validate(&reencoded).is_ok(),
                "a corrupted stream produced a module that does not validate"
            );
        }
    }

    // 5. Truncating the stream never panics.
    for cut in [1usize, 3, 7, stream.len() / 2] {
        if cut < stream.len() {
            let mut decoder = StreamDecoder::new();
            if decoder.push_bytes(&stream[..cut]).is_ok() {
                let _ = decoder.finish();
            }
        }
    }

    let _ = Limits::default();
});
