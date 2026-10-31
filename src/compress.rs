//! Optional compression profile.
//!
//! Compression is transport/storage, never identity: the content hash is always
//! over the uncompressed canonical image unless a future ADR defines a separate
//! compressed profile. This module is feature-gated by `zstd`.

use crate::{Error, Result};

/// Compress a canonical image or frame payload with zstd.
pub fn compress(bytes: &[u8], level: i32) -> Result<Vec<u8>> {
    zstd::bulk::compress(bytes, level).map_err(|_| Error::Compression("zstd compress"))
}

/// Decompress with an explicit output ceiling. The ceiling is mandatory so a
/// hostile frame cannot expand without bound.
pub fn decompress(bytes: &[u8], max_output: usize) -> Result<Vec<u8>> {
    zstd::bulk::decompress(bytes, max_output).map_err(|_| Error::Compression("zstd decompress"))
}

/// Compress with a trained dictionary.
pub fn compress_with_dictionary(bytes: &[u8], level: i32, dictionary: &[u8]) -> Result<Vec<u8>> {
    let mut compressor = zstd::bulk::Compressor::with_dictionary(level, dictionary)
        .map_err(|_| Error::Compression("zstd dictionary compressor"))?;
    compressor
        .compress(bytes)
        .map_err(|_| Error::Compression("zstd compress with dictionary"))
}

/// Decompress with a trained dictionary and an output ceiling.
pub fn decompress_with_dictionary(
    bytes: &[u8],
    max_output: usize,
    dictionary: &[u8],
) -> Result<Vec<u8>> {
    let mut decompressor = zstd::bulk::Decompressor::with_dictionary(dictionary)
        .map_err(|_| Error::Compression("zstd dictionary decompressor"))?;
    decompressor
        .decompress(bytes, max_output)
        .map_err(|_| Error::Compression("zstd decompress with dictionary"))
}

/// Train a dictionary from representative canonical images or frames.
pub fn train_dictionary<S: AsRef<[u8]>>(samples: &[S], max_size: usize) -> Result<Vec<u8>> {
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
