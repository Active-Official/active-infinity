//! Stream a canonical module in frames and reassemble it byte-for-byte.
//!
//! Run with `cargo run --example streaming`.
//!
//! The stream is a sequence of self-describing `AINS` frames. A receiver may
//! push arbitrary byte chunks: frame boundaries need not line up with socket
//! reads. Reassembly must produce the same canonical image as a whole-module
//! encode; the example asserts that and prints the frame count.

use active_infinity::stream::{decode_stream, StreamDecoder, StreamEncoder};
use active_infinity::{encode, InfinityModule, Inode};

fn main() {
    let mut module = InfinityModule::new();
    let mut fields = Vec::new();
    for index in 0..32 {
        let value = module.push(Inode::Int(index));
        fields.push((format!("item_{index:02}"), value));
    }
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));

    let image = encode(&module).expect("encode");

    // Encoder: one frame per chunk, with a sequence number on each frame.
    let encoder = StreamEncoder::new(&module, 64).expect("encoder");
    let frames = encoder.frames();
    let bytes = encoder.to_bytes();
    println!("canonical={} bytes frames={}", image.len(), frames.len());

    // Reassemble through the streaming decoder in odd-sized chunks, so no chunk
    // ends on a frame boundary except by accident.
    let mut decoder = StreamDecoder::new();
    for chunk in bytes.chunks(7) {
        decoder.push_bytes(chunk).expect("push");
    }
    let streamed = decoder.finish().expect("finish");
    assert_eq!(streamed.image, image);

    // The convenience path parses the whole buffer and must agree.
    let decoded = decode_stream(&bytes).expect("decode_stream");
    assert_eq!(decoded.image, image);
    println!(
        "reassembled={} bytes, hash-stable={}",
        streamed.image.len(),
        streamed.image == image
    );
}
