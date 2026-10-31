//! Optional compression profile.
//!
//! Compression is transport/storage, never identity: the content hash is always
//! over the uncompressed canonical image unless a future ADR defines a separate
//! compressed profile. This module is feature-gated by `zstd`.
//!
//! # Limits and trust
//!
//! - Every decompression takes an explicit output ceiling. The ceiling bounds
//!   the allocation; pass the largest output you are willing to accept (for an
//!   image, [`crate::Limits::max_total_bytes`]).
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

use crate::{Error, Result};

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

/// Compress a canonical image or frame payload with zstd.
pub fn compress(bytes: &[u8], level: i32) -> Result<Vec<u8>> {
    check_level(level)?;
    zstd::bulk::compress(bytes, level).map_err(|_| Error::Compression("zstd compress"))
}

/// Decompress with an explicit output ceiling. The ceiling is mandatory so a
/// hostile frame cannot expand without bound, and empty input is refused: an
/// empty file is not a zstd frame, and returning empty bytes for it reads as a
/// successful decode.
pub fn decompress(bytes: &[u8], max_output: usize) -> Result<Vec<u8>> {
    if bytes.is_empty() {
        return Err(Error::Compression("empty compressed input"));
    }
    zstd::bulk::decompress(bytes, max_output).map_err(|_| Error::Compression("zstd decompress"))
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
pub fn decompress_with_dictionary(
    bytes: &[u8],
    max_output: usize,
    dictionary: &[u8],
) -> Result<Vec<u8>> {
    if bytes.is_empty() {
        return Err(Error::Compression("empty compressed input"));
    }
    let mut decompressor = zstd::bulk::Decompressor::with_dictionary(dictionary)
        .map_err(|_| Error::Compression("zstd dictionary decompressor"))?;
    decompressor
        .decompress(bytes, max_output)
        .map_err(|_| Error::Compression("zstd decompress with dictionary"))
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
    zstd::dict::from_samples(samples, max_size)
        .map_err(|_| Error::Compression("zstd dictionary training"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{content_hash, decode, encode, InfinityModule, Inode};

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
}
