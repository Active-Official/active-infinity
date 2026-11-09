#![no_main]
//! zstd dictionary training takes attacker-chosen samples and a size, then
//! the trained dictionary compresses and decompresses: training must refuse
//! absurd sizes with an `infinity/*` code, and a trained dictionary must
//! round-trip every sample and refuse a too-small output ceiling
//! (INF-POLY-05).

use libfuzzer_sys::fuzz_target;

use active_infinity::compress::{
    compress_with_dictionary, decompress_with_dictionary, train_dictionary,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 || data.len() > 65_536 {
        return;
    }
    // [count:1][size_lo:1][size_hi:1][samples...]: 2..=8 samples, and a
    // training size in 256..=65,791 — inside the codec ceiling, so the
    // refusal under test is the trainer's, not the allocator's. (zstd's
    // trainer needs at least seven samples: counts 2..=6 exercise the
    // refusal arm, 7..=8 the round-trip.)
    let count = 2 + (data[0] % 7) as usize;
    let max_size = 256 + (u16::from(data[1]) | (u16::from(data[2]) << 8)) as usize % (1 << 20);
    let rest = &data[3..];
    let mut samples = Vec::with_capacity(count);
    let mut start = 0usize;
    for index in 0..count {
        // The last sample takes the tail; the others take equal shares.
        let end = if index + 1 == count {
            rest.len()
        } else {
            rest.len() * (index + 1) / count
        };
        samples.push(&rest[start..end]);
        start = end;
    }
    match train_dictionary(&samples, max_size) {
        Ok(dictionary) => {
            assert!(
                !dictionary.is_empty() && dictionary.len() <= max_size,
                "a trained dictionary is non-empty and within its ceiling"
            );
            for sample in &samples {
                let compressed = match compress_with_dictionary(sample, 3, &dictionary) {
                    Ok(compressed) => compressed,
                    Err(error) => panic!("a trained dictionary compresses: {error}"),
                };
                let restored =
                    match decompress_with_dictionary(&compressed, sample.len(), &dictionary) {
                        Ok(restored) => restored,
                        Err(error) => panic!("a trained dictionary round-trips: {error}"),
                    };
                assert_eq!(restored, *sample, "dictionary round-trip is the identity");
                if !sample.is_empty() {
                    // One byte short of the true output must refuse, not truncate.
                    assert!(
                        decompress_with_dictionary(&compressed, sample.len() - 1, &dictionary)
                            .is_err(),
                        "a too-small decompression ceiling refuses"
                    );
                }
            }
            // Hostile compressed bytes under the trained dictionary stay total.
            if let Err(error) = decompress_with_dictionary(data, 1 << 20, &dictionary) {
                assert!(
                    error.code().starts_with("infinity/"),
                    "dictionary decompression refusal without a codec code: {error}"
                );
            }
        }
        Err(error) => assert!(
            error.code().starts_with("infinity/"),
            "dictionary training refusal without a codec code: {error}"
        ),
    }
});
