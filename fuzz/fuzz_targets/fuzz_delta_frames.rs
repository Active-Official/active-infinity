#![no_main]
//! A Delta frame payload is the untrusted part of an incremental stream. The
//! decoder must apply it into a valid module or refuse it with a stream code;
//! a partial arena, a panic or an unbounded allocation is a failure.

use libfuzzer_sys::fuzz_target;

use active_infinity::stream::{
    encode_stream, Frame, FrameKind, StreamDecoder, MAX_FRAME_PAYLOAD,
};

fn fixture() -> Vec<u8> {
    let mut module = active_infinity::InfinityModule::new();
    let value = module.push(active_infinity::Inode::Str("delta-fixture".into()));
    let root = module.push(active_infinity::Inode::Table {
        fields: vec![("value".into(), value)],
    });
    module.set_root(Some(root));
    active_infinity::encode(&module).expect("fixture encodes")
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FRAME_PAYLOAD as usize {
        return;
    }
    let Ok(frames) = encode_stream(
        &active_infinity::decode(&fixture()).expect("fixture decodes"),
        64,
    ) else {
        return;
    };
    // The Begin frame plus an attacker-controlled Delta frame.
    let mut stream = frames[0].to_bytes();
    stream.extend_from_slice(&Frame::new(FrameKind::Delta, 1, data.to_vec()).to_bytes());

    let mut decoder = StreamDecoder::new();
    match decoder.push_bytes(&stream) {
        Ok(()) => {
            if let Err(error) = decoder.finish() {
                assert!(
                    error.code().starts_with("infinity/"),
                    "delta finish without a codec code: {error}"
                );
            }
        }
        Err(error) => assert!(
            error.code().starts_with("infinity/"),
            "delta refusal without a codec code: {error}"
        ),
    }
});
