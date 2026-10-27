//! End-to-end tour: text → Infinity → validate → view → decode → stream.
//!
//! ```bash
//! cargo run --example roundtrip
//! ```
//!
//! The output is deterministic; the run-twice launch check in the release
//! procedure compares two invocations byte for byte.

use active_infinity::stream::{self, StreamDecoder};
use active_infinity::{
    content_hash, decode, encode, validate, InfinityModule, InfinityView, Limits,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let module = build()?;
    let bytes = encode(&module)?;
    let meta = validate(&bytes)?;
    println!(
        "module:      {} nodes, {} bytes",
        meta.nodes, meta.total_size
    );
    println!(
        "content:     blake3:{}",
        active_infinity::ir::hash_hex(&meta.content_hash)
    );

    let view = InfinityView::new(&bytes, Limits::default())?;
    println!(
        "view:        {} nodes, hash agrees: {}",
        view.node_count(),
        view.content_hash() == meta.content_hash
    );

    let decoded = decode(&bytes)?;
    let reencoded = encode(&decoded)?;
    println!("round-trip:  equal values: {}", decoded == module);
    println!("round-trip:  identical bytes: {}", reencoded == bytes);

    // Streaming: one generation, reassembled chunk by chunk.
    let frames = stream::encode_stream(&module, 32)?;
    let mut wire = Vec::new();
    for frame in &frames {
        wire.extend_from_slice(&frame.to_bytes());
    }
    let mut decoder = StreamDecoder::new();
    for piece in wire.chunks(7) {
        decoder.push_bytes(piece)?;
    }
    let streamed = decoder.finish()?;
    println!(
        "stream:      {} frames, identical image: {}, identical hash: {}",
        frames.len(),
        streamed.image == bytes,
        streamed.content_hash == content_hash(&bytes)?
    );

    // Redacted projection: secret material never appears.
    #[cfg(feature = "json")]
    {
        let json = active_infinity::interop::to_redacted_json(&decoded)?;
        println!("projection:  {} bytes of redacted JSON", json.len());
        println!("projection:  contains secret: {}", json.contains("hunter2"));
    }
    Ok(())
}

fn build() -> Result<InfinityModule, Box<dyn std::error::Error>> {
    #[cfg(feature = "active-core")]
    {
        let source = r#"
# @intent: "Round-trip fixture"
[app]
name  = "roundtrip"
port  = 8080
ratio = 25%
label = "v1"
"#;
        Ok(active_infinity::interop::from_active_source(
            source,
            "roundtrip.active",
        )?)
    }
    #[cfg(not(feature = "active-core"))]
    {
        use active_infinity::Inode;
        let mut module = InfinityModule::new();
        let text = module.push(Inode::Str("roundtrip".into()));
        let port = module.push(Inode::Int(8080));
        let root = module.push(Inode::Table {
            fields: vec![("name".into(), text), ("port".into(), port)],
        });
        module.set_root(Some(root));
        Ok(module)
    }
}
