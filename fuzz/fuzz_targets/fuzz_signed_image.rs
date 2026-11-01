#![no_main]
//! Signed envelopes are an untrusted boundary: any bytes must produce a clean
//! `infinity/signature` (or a resource ceiling), never a panic and never an
//! envelope that does not verify.

use libfuzzer_sys::fuzz_target;

use active_infinity::SignedImage;

fuzz_target!(|data: &[u8]| {
    match SignedImage::from_bytes(data) {
        Ok(signed) => {
            // A parsed envelope already verified; asking again must not differ.
            assert!(signed.verify().is_ok(), "a parsed envelope must verify");
            assert!(signed.content_hash().is_ok(), "a parsed envelope has a hash");
        }
        Err(error) => assert!(
            error.code() == "infinity/signature" || error.code() == "infinity/limit",
            "unexpected envelope code {}",
            error.code()
        ),
    }
});
