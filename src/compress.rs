//! Optional compression profile.
//!
//! Compression is transport/storage, never identity: the content hash is always
//! over the uncompressed canonical image unless a future ADR defines a separate
//! compressed profile. This module is feature-gated by `zstd`.
//!
//! # Limits and trust
//!
//! - Every decompression takes an explicit output ceiling. The ceiling bounds
//!   the *decoded output*, never the allocation: decoding streams into a
//!   buffer that grows with the bytes actually produced, so a frame that
//!   records no content size costs the decoded bytes plus decoder state,
//!   not the ceiling (INF-COMPRESS-01). Pass the largest output you are
//!   willing to accept (for an image, [`crate::Limits::max_total_bytes`]).
//! - A dictionary is a compression hint. zstd can decompress a frame that does
//!   not use the supplied dictionary, so a successful
//!   [`decompress_with_dictionary`] says nothing about which dictionary the
//!   producer used. Never treat the dictionary as a trust boundary; authenticity
//!   comes from [`crate::SignedImage`] or the content hash.
//! - Compression is length-revealing. Compressing an image that carries secrets
//!   next to attacker-influenced fields and exposing the compressed length is a
//!   CRIME-style oracle; compress the redacted projection instead (see
//!   `docs/spec/security.md`).
//! - Levels outside the build's zstd range are refused instead of being clamped
//!   silently, so a caller's intent is never replaced by a different level.

use std::io::Read;

use crate::{Error, Limits, Result};

/// Compression levels this build's zstd accepts, inclusive.
pub fn level_range() -> (i32, i32) {
    (
        zstd::zstd_safe::min_c_level(),
        zstd::zstd_safe::max_c_level(),
    )
}

fn check_level(level: i32) -> Result<()> {
    let (minimum, maximum) = level_range();
    if !(minimum..=maximum).contains(&level) {
        return Err(Error::InvalidArgument(
            "compression level is outside this build's zstd range",
        ));
    }
    Ok(())
}

/// zstd frame magic: a frame that carries content.
const FRAME_MAGIC: u32 = 0xFD2F_B528;
/// Skippable-frame magic, with the low nibble of the last byte masked off.
const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;
const SKIPPABLE_MASK: u32 = 0xFFFF_FFF0;

/// Whether the stream contains a frame that carries content.
///
/// A skippable frame is legal zstd and decodes to nothing, so an input made of
/// skippable frames only would decode to an empty success that a caller cannot
/// tell apart from an empty payload. Walk the frame headers: a content frame
/// means "decode it", only skippable frames means "refuse". An unrecognized
/// magic is left for zstd to report.
fn carries_content_frame(bytes: &[u8]) -> bool {
    let mut offset = 0usize;
    loop {
        // A skippable frame's declared length can push `offset` past the
        // buffer; compute the windows with checked arithmetic so a 32-bit
        // target cannot wrap `offset + 4` into a reversed range.
        let Some(header) = offset.checked_add(4).and_then(|end| bytes.get(offset..end)) else {
            return false;
        };
        let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        if magic == FRAME_MAGIC {
            return true;
        }
        if magic & SKIPPABLE_MASK != SKIPPABLE_MAGIC {
            return true;
        }
        let Some(length) = offset
            .checked_add(8)
            .and_then(|end| bytes.get(offset + 4..end))
        else {
            return false;
        };
        let length = u32::from_le_bytes([length[0], length[1], length[2], length[3]]) as usize;
        match offset
            .checked_add(8)
            .and_then(|start| start.checked_add(length))
        {
            Some(next) => offset = next,
            None => return false,
        }
    }
}

/// Compress a canonical image or frame payload with zstd.
pub fn compress(bytes: &[u8], level: i32) -> Result<Vec<u8>> {
    check_level(level)?;
    zstd::bulk::compress(bytes, level).map_err(|_| Error::Compression("zstd compress"))
}

/// Read chunk for streaming decompression: zstd's recommended output buffer
/// (`ZSTD_DStreamOutSize()`, 128 KiB), so one `read` can return a full block
/// without the decoder stalling on a small caller buffer. A heap buffer, not
/// a stack array: 128 KiB would eat a small thread's stack, and this crate
/// pins a small-stack fix (INF-15).
const DECODE_CHUNK: usize = 128 * 1024;

/// Decompress through zstd's streaming decoder into a buffer that grows
/// with the decoded output.
///
/// The ceiling bounds the *output*, never the allocation: the output buffer
/// starts from a small seed (the compressed input length, capped at 64 KiB)
/// and grows geometrically as bytes arrive. A frame that records no content
/// size therefore costs the decoded bytes plus decoder state — never the
/// ceiling — no matter how large `max_output` is. The old code called
/// `zstd::bulk::decompress`, which does `Vec::with_capacity(capacity)` with
/// `capacity` falling back to the caller's `max_output` for a size-less
/// frame (INF-COMPRESS-01: 1 GiB committed for a 35-byte payload at a 1 GiB
/// ceiling).
///
/// The ceiling is still enforced exactly: the first chunk that would push
/// the output past `max_output` fails closed with the same
/// `infinity/compression` error the bulk call returned for an oversize
/// frame. Frames that do record a size are unaffected in outcome: zstd
/// itself rejects a frame whose decoded output disagrees with its declared
/// size, so for every input that decodes successfully the streaming
/// ceiling and the old declared-size check agree.
fn decompress_streaming(
    bytes: &[u8],
    max_output: usize,
    dictionary: Option<&[u8]>,
    decode_error: &'static str,
) -> Result<Vec<u8>> {
    let mut decoder = match dictionary {
        Some(dictionary) => zstd::stream::read::Decoder::with_dictionary(bytes, dictionary)
            .map_err(|_| Error::Compression("zstd dictionary decompressor"))?,
        None => zstd::stream::read::Decoder::with_buffer(bytes)
            .map_err(|_| Error::Compression(decode_error))?,
    };
    // Seed from the compressed length, capped: the input is already in
    // memory, so this never allocates more than the caller already holds,
    // and a small frame starts small. Growth after that is geometric
    // (`extend_from_slice`), driven by decoded bytes.
    let mut out = Vec::with_capacity(bytes.len().min(64 * 1024));
    let mut chunk = vec![0u8; DECODE_CHUNK];
    loop {
        match decoder.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if n > max_output.saturating_sub(out.len()) {
                    return Err(Error::Compression(decode_error));
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Compression(decode_error)),
        }
    }
    Ok(out)
}

/// Decompress with an explicit output ceiling. The ceiling is mandatory so a
/// hostile frame cannot expand without bound, and empty input is refused: an
/// empty file is not a zstd frame, and returning empty bytes for it reads as a
/// successful decode.
///
/// The ceiling bounds the decoded output, not the allocation: decoding
/// streams into a buffer that grows with the bytes actually produced, so a
/// size-less frame costs the decoded bytes plus decoder state, never the
/// ceiling (INF-COMPRESS-01).
pub fn decompress(bytes: &[u8], max_output: usize) -> Result<Vec<u8>> {
    if bytes.is_empty() {
        return Err(Error::Compression("empty compressed input"));
    }
    if !carries_content_frame(bytes) {
        return Err(Error::Compression(
            "compressed input carries no content frame",
        ));
    }
    decompress_streaming(bytes, max_output, None, "zstd decompress")
}

/// Compress with a trained dictionary.
///
/// The dictionary is a performance hint, not a key: see the module docs.
pub fn compress_with_dictionary(bytes: &[u8], level: i32, dictionary: &[u8]) -> Result<Vec<u8>> {
    check_level(level)?;
    let mut compressor = zstd::bulk::Compressor::with_dictionary(level, dictionary)
        .map_err(|_| Error::Compression("zstd dictionary compressor"))?;
    compressor
        .compress(bytes)
        .map_err(|_| Error::Compression("zstd compress with dictionary"))
}

/// Decompress with a trained dictionary and an output ceiling.
///
/// A frame that does not use the dictionary still decompresses; the dictionary
/// is a hint, never proof of the producer.
///
/// As with [`decompress`], the ceiling bounds the decoded output, not the
/// allocation: decoding streams into a buffer that grows with the bytes
/// actually produced (INF-COMPRESS-01).
pub fn decompress_with_dictionary(
    bytes: &[u8],
    max_output: usize,
    dictionary: &[u8],
) -> Result<Vec<u8>> {
    if bytes.is_empty() {
        return Err(Error::Compression("empty compressed input"));
    }
    if !carries_content_frame(bytes) {
        return Err(Error::Compression(
            "compressed input carries no content frame",
        ));
    }
    decompress_streaming(
        bytes,
        max_output,
        Some(dictionary),
        "zstd decompress with dictionary",
    )
}

/// Train a dictionary from representative canonical images or frames.
///
/// `max_size` is an allocation ceiling the caller chooses: it is the capacity
/// zstd trains into. Zero is refused rather than passed through.
pub fn train_dictionary<S: AsRef<[u8]>>(samples: &[S], max_size: usize) -> Result<Vec<u8>> {
    if max_size == 0 {
        return Err(Error::InvalidArgument("dictionary size must be non-zero"));
    }
    if samples.is_empty() {
        return Err(Error::InvalidArgument("dictionary training needs samples"));
    }
    // zstd's allocator aborts the process (not an `Err`) for a large enough
    // capacity, so the ceiling is enforced here: this crate's contract is to
    // fail closed on every input.
    if max_size as u64 > Limits::default().max_total_bytes {
        return Err(Error::InvalidArgument(
            "dictionary size is above the codec's image ceiling",
        ));
    }
    zstd::dict::from_samples(samples, max_size)
        .map_err(|_| Error::Compression("zstd dictionary training"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{content_hash, decode, encode, InfinityModule, Inode};
    use std::io::{Read, Write};

    fn image(seed: i64) -> Vec<u8> {
        let mut module = InfinityModule::new();
        let mut fields = Vec::new();
        for index in 0..200 {
            let value = module.push(Inode::Int(index + seed));
            fields.push((format!("field-{index}"), value));
        }
        let root = module.push(Inode::Table { fields });
        module.set_root(Some(root));
        encode(&module).expect("encode")
    }

    /// A zstd frame with NO content-size field, from the streaming encoder
    /// (which cannot know the total size up front). This is the frame shape
    /// INF-COMPRESS-01 is about: the old bulk path allocated the caller's
    /// full ceiling for exactly this input.
    fn sizeless_frame(payload: &[u8]) -> Vec<u8> {
        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).expect("streaming encoder");
        encoder.write_all(payload).expect("encode");
        let frame = encoder.finish().expect("finish");
        // Frame header descriptor, byte 4: bit 5 (0x20) is the content-size flag.
        assert_eq!(
            frame[4] & 0x20,
            0,
            "streaming encoder must not record a content size"
        );
        frame
    }

    #[test]
    fn train_refuses_a_dictionary_size_above_the_codec_ceiling() {
        let samples = vec![image(0), image(1)];
        let ceiling = Limits::default().max_total_bytes as usize;
        let error = train_dictionary(&samples, ceiling + 1).expect_err("refused");
        assert_eq!(error.code(), "infinity/invalid-argument", "{error}");
    }

    #[test]
    fn skippable_only_input_is_refused() {
        let mut frame = 0x184D_2A50u32.to_le_bytes().to_vec();
        frame.extend_from_slice(&4u32.to_le_bytes());
        frame.extend_from_slice(&[0u8; 4]);
        let error = decompress(&frame, 1024).expect_err("no content frame");
        assert_eq!(error.code(), "infinity/compression", "{error}");
    }

    #[test]
    fn concatenated_content_frames_decode_in_order() {
        // Standard zstd: a decoder concatenates the output of every frame, and
        // the caller's ceiling still bounds the total. Documented in
        // docs/spec/streaming.md section 6.
        let first = compress(b"first-", 3).expect("compress");
        let second = compress(b"second", 3).expect("compress");
        let mut stream = first;
        stream.extend_from_slice(&second);
        let restored = decompress(&stream, 16).expect("decompress");
        assert_eq!(restored, b"first-second");
    }

    #[test]
    fn a_skippable_frame_before_content_still_decompresses() {
        let image = image(3);
        let compressed = compress(&image, 3).expect("compress");
        let mut stream = 0x184D_2A51u32.to_le_bytes().to_vec();
        stream.extend_from_slice(&2u32.to_le_bytes());
        stream.extend_from_slice(&[7u8; 2]);
        stream.extend_from_slice(&compressed);
        let restored = decompress(&stream, image.len() + 1).expect("decompress");
        assert_eq!(restored, image);
    }

    #[test]
    fn compression_round_trips_and_does_not_move_identity() {
        let image = image(0);
        let compressed = compress(&image, 3).expect("compress");
        let restored = decompress(&compressed, image.len() + 1).expect("decompress");
        assert_eq!(restored, image);
        assert_eq!(
            content_hash(&restored).unwrap(),
            content_hash(&image).unwrap()
        );
        decode(&restored).expect("decode restored image");
    }

    #[test]
    fn dictionary_round_trips() {
        let image0 = image(0);
        let samples: Vec<Vec<u8>> = (0..32i64).map(image).collect();
        let dictionary = train_dictionary(&samples, 4_096).expect("train");
        let compressed = compress_with_dictionary(&image0, 3, &dictionary).expect("compress");
        let restored = decompress_with_dictionary(&compressed, image0.len() + 1, &dictionary)
            .expect("decompress");
        assert_eq!(restored, image0);
    }

    #[test]
    fn decompression_ceiling_fails_closed() {
        let image = image(0);
        let compressed = compress(&image, 3).expect("compress");
        assert!(decompress(&compressed, 8).is_err());
    }

    #[test]
    fn sizeless_frame_round_trips() {
        // INF-COMPRESS-01: the streaming path must decode a frame that
        // records no content size, not just the sized frames `compress`
        // produces.
        let payload = b"hello world, this is a tiny payload";
        let frame = sizeless_frame(payload);
        let restored = decompress(&frame, 1 << 30).expect("decompress");
        assert_eq!(restored.as_slice(), payload);
    }

    #[test]
    fn sizeless_frame_with_dictionary_round_trips() {
        // INF-COMPRESS-01, dictionary path: same streaming decode, same
        // allocation behaviour as the plain path.
        let payload = b"hello world, this is a tiny payload";
        let samples: Vec<Vec<u8>> = (0..32u8)
            .map(|seed| {
                let mut sample = payload.to_vec();
                sample.push(seed);
                sample
            })
            .collect();
        let dictionary = train_dictionary(&samples, 4_096).expect("train");
        let mut reader = zstd::stream::read::Encoder::with_dictionary(
            std::io::Cursor::new(payload.as_slice()),
            3,
            &dictionary,
        )
        .expect("streaming dictionary encoder");
        let mut frame = Vec::new();
        reader.read_to_end(&mut frame).expect("encode");
        assert_eq!(
            frame[4] & 0x20,
            0,
            "streaming encoder must not record a content size"
        );
        let restored =
            decompress_with_dictionary(&frame, 1 << 30, &dictionary).expect("decompress");
        assert_eq!(restored.as_slice(), payload);
    }

    #[test]
    fn sizeless_frame_ceiling_still_fails_closed() {
        // INF-COMPRESS-01: the ceiling is enforced on the decoded output
        // even when there is no declared size for a bulk path to lean on —
        // the loop aborts as soon as the output would pass the ceiling.
        let payload = vec![b'x'; 100];
        let frame = sizeless_frame(&payload);
        let error = decompress(&frame, 8).expect_err("ceiling exceeded");
        assert_eq!(error.code(), "infinity/compression", "{error}");
        // One 100-byte sample of a single repeated byte cannot train a
        // dictionary (zstd refuses it), so train from varied samples, as
        // the other dictionary tests do.
        let samples: Vec<Vec<u8>> = (0..32u8)
            .map(|seed| {
                let mut sample = payload.clone();
                sample.push(seed);
                sample
            })
            .collect();
        let dictionary = train_dictionary(&samples, 4_096).expect("train");
        let mut reader = zstd::stream::read::Encoder::with_dictionary(
            std::io::Cursor::new(payload.as_slice()),
            3,
            &dictionary,
        )
        .expect("streaming dictionary encoder");
        let mut dict_frame = Vec::new();
        reader.read_to_end(&mut dict_frame).expect("encode");
        let error =
            decompress_with_dictionary(&dict_frame, 8, &dictionary).expect_err("ceiling exceeded");
        assert_eq!(error.code(), "infinity/compression", "{error}");
    }
}
