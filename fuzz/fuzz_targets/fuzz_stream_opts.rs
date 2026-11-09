#![no_main]
//! `encode_stream_with` is the explicit-options stream encoder no target
//! drove: chunk sizes at the edges, every `EncodeOpts` flag, and the
//! `encode_many` batch path must all round-trip through the decoder or
//! refuse with an `infinity/*` code (INF-POLY-05).

use libfuzzer_sys::fuzz_target;

use active_infinity::stream::{
    decode_stream, encode_stream_with, StreamDecoder, StreamEncoder, MAX_FRAME_PAYLOAD,
};
use active_infinity::{encode_many, encode_with, EncodeOpts};

#[path = "common.rs"]
mod common;

/// Chunk sizes at the edges: zero and oversize refuse; 1-byte and
/// frame-sized chunks exercise the section splitter.
const CHUNKS: [usize; 10] = [
    0,
    1,
    8,
    9,
    64,
    4096,
    65_536,
    1 << 20,
    MAX_FRAME_PAYLOAD as usize - 9,
    MAX_FRAME_PAYLOAD as usize,
];

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 || data.len() > 16_384 {
        return;
    }
    let chunk = CHUNKS[(data[0] as usize) % CHUNKS.len()];
    let flags = data[1];
    let opts = EncodeOpts {
        write_hash: flags & 1 != 0,
        mark_canonical: flags & 2 != 0,
        streamed: flags & 4 != 0,
        drop_unreachable: flags & 8 != 0,
    };
    // The module is the fuzz bytes decoded as an image, or the fixture
    // when they do not decode — either way a real module goes in.
    let module = match active_infinity::decode(&data[2..]) {
        Ok(module) => module,
        Err(_) => common::fixture(),
    };
    match encode_stream_with(&module, chunk, opts) {
        Ok(frames) => {
            let mut bytes = Vec::new();
            for frame in &frames {
                bytes.extend_from_slice(&frame.to_bytes());
            }
            let expected = encode_with(&module, opts).expect("the module encodes with opts");
            // The decoder fills the header's content-hash field (bytes
            // 16..48) from the End frame even when the producer left it
            // zero (`write_hash: false`), so a reassembled image is
            // compared with that field masked out. Canonicality is
            // decided by `mark_canonical` alone: without it the decoder
            // refuses the stream (`infinity/not-canonical`); with it the
            // stream feeds and reassembles to the options-encoded image.
            let same_image = |image: &[u8]| {
                let mut got = image.to_vec();
                let mut want = expected.clone();
                if got.len() > 48 {
                    got[16..48].fill(0);
                }
                if want.len() > 48 {
                    want[16..48].fill(0);
                }
                assert_eq!(
                    got, want,
                    "the stream reassembles to the options-encoded image"
                );
                if opts.write_hash {
                    assert_eq!(image, expected, "a hashed stream reassembles byte for byte");
                }
            };
            if opts.mark_canonical {
                // Reassemble byte-split through the decoder, in two uneven halves.
                let mut decoder = StreamDecoder::new();
                let mid = bytes.len() / 2;
                decoder
                    .push_bytes(&bytes[..mid])
                    .expect("producer frames feed");
                decoder
                    .push_bytes(&bytes[mid..])
                    .expect("producer frames feed");
                let streamed = decoder.finish().expect("producer frames finish");
                same_image(&streamed.image);
                // The whole-bytes path agrees with the incremental one.
                let whole = decode_stream(&bytes).expect("producer bytes decode as a stream");
                same_image(&whole.image);
                assert_eq!(
                    whole.content_hash, streamed.content_hash,
                    "both stream paths agree on the hash"
                );
            } else {
                // A non-canonical stream is refused with a codec code, or
                // reassembles exactly (modulo the hash field) if accepted.
                let mut decoder = StreamDecoder::new();
                let mid = bytes.len() / 2;
                match decoder.push_bytes(&bytes[..mid]) {
                    Ok(()) => match decoder.push_bytes(&bytes[mid..]) {
                        Ok(()) => match decoder.finish() {
                            Ok(streamed) => same_image(&streamed.image),
                            Err(error) => assert!(
                                error.code().starts_with("infinity/"),
                                "a non-canonical stream refusal without a codec code: {error}"
                            ),
                        },
                        Err(error) => assert!(
                            error.code().starts_with("infinity/"),
                            "a non-canonical stream refusal without a codec code: {error}"
                        ),
                    },
                    Err(error) => assert!(
                        error.code().starts_with("infinity/"),
                        "a non-canonical stream refusal without a codec code: {error}"
                    ),
                }
                match decode_stream(&bytes) {
                    Ok(whole) => same_image(&whole.image),
                    Err(error) => assert!(
                        error.code().starts_with("infinity/"),
                        "decode_stream refusal without a codec code: {error}"
                    ),
                }
            }
        }
        Err(error) => assert!(
            error.code().starts_with("infinity/"),
            "stream encode refusal without a codec code: {error}"
        ),
    }
    // The `StreamEncoder` path with the same chunk (default options).
    match StreamEncoder::new(&module, chunk) {
        Ok(encoder) => {
            let bytes = encoder.to_bytes();
            let whole = decode_stream(&bytes).expect("encoder bytes decode as a stream");
            assert_eq!(
                whole.image,
                active_infinity::encode(&module).expect("the module encodes"),
                "the encoder round-trips"
            );
        }
        Err(error) => assert!(
            error.code().starts_with("infinity/"),
            "stream encoder refusal without a codec code: {error}"
        ),
    }
    // The batch path: every output validates.
    let mut out = Vec::new();
    match encode_many([&module, &module], &mut out) {
        Ok(()) => {
            assert_eq!(out.len(), 2, "the batch keeps its length");
            for image in &out {
                assert!(
                    active_infinity::validate(image).is_ok(),
                    "a batch image validates"
                );
            }
            assert_eq!(
                out[0], out[1],
                "the batch encodes one module twice, identically"
            );
        }
        Err(error) => assert!(
            error.code().starts_with("infinity/"),
            "batch encode refusal without a codec code: {error}"
        ),
    }
});
