//! Batch encoding: identical bytes, reused buffers.

use active_infinity::{content_hash, encode, encode_into, encode_many, InfinityModule, Inode};

fn fixture(fields: usize) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut table = Vec::with_capacity(fields);
    for index in 0..fields {
        let value = module.push(Inode::Int(index as i64));
        table.push((format!("field-{index}"), value));
    }
    let root = module.push(Inode::Table { fields: table });
    module.set_root(Some(root));
    module
}

#[test]
fn encode_into_produces_the_same_bytes_as_encode() {
    let module = fixture(64);
    let expected = encode(&module).expect("encode");
    let mut buffer = Vec::with_capacity(expected.len() + 512);
    encode_into(&module, &mut buffer).expect("encode_into");
    assert_eq!(buffer, expected);
    assert_eq!(
        content_hash(&buffer).expect("hash"),
        content_hash(&expected).expect("hash")
    );
}

#[test]
fn encode_into_reuses_capacity_across_modules() {
    let large = fixture(512);
    let small = fixture(4);
    let mut buffer = Vec::new();
    encode_into(&large, &mut buffer).expect("large");
    let capacity = buffer.capacity();
    assert!(capacity >= buffer.len());
    encode_into(&small, &mut buffer).expect("small");
    assert_eq!(buffer.capacity(), capacity, "buffer capacity is reused");
    assert_eq!(buffer, encode(&small).expect("encode"));
}

#[test]
fn encode_many_matches_a_loop_and_keeps_buffers() {
    let modules: Vec<InfinityModule> = (0..8).map(|index| fixture(index * 16 + 1)).collect();
    let mut buffers = Vec::new();
    encode_many(modules.iter(), &mut buffers).expect("batch");
    assert_eq!(buffers.len(), modules.len());
    for (buffer, module) in buffers.iter().zip(&modules) {
        assert_eq!(buffer, &encode(module).expect("encode"));
    }
    let capacities: Vec<usize> = buffers.iter().map(Vec::capacity).collect();
    encode_many(modules.iter(), &mut buffers).expect("second batch");
    assert_eq!(
        capacities,
        buffers.iter().map(Vec::capacity).collect::<Vec<_>>(),
        "a second batch reuses every buffer"
    );

    let mut shrunk = buffers;
    encode_many(modules.iter().take(3), &mut shrunk).expect("short batch");
    assert_eq!(shrunk.len(), 3);
}
