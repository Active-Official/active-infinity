//! INF-05: a stream Delta `PutNode` fragment is charged for the decoded
//! payload bytes it buys, per reference — not just its node count.
//!
//! Before the fix the charge was `node_count × (size_of::<Inode>() + 32) +
//! table_entries × 40`, so a fragment whose image is ~150 KiB but decodes
//! to ~128 MiB (one 64 KiB string shared by 2000 `Str` nodes) was charged
//! only 272,136 and accepted by a decoder with an 8 MiB total budget. The
//! bound the code claims ("the bound is on decoded state, not on wire
//! bytes") was not enforced for the largest decoded component.

use active_infinity::stream::{DeltaOp, StreamDecoder, StreamEncoder};
use active_infinity::{encode, InfinityModule, Inode};

fn base_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(0));
    module.set_root(Some(root));
    let image = encode(&module).expect("encode");
    active_infinity::decode(&image).expect("decode")
}

/// One 64 KiB string shared by 2000 `Str` nodes: a ~150 KiB image that
/// decodes to ~128 MiB. The verifier's probe shape (W4-R1-INF-CORE).
fn amplified_string_fragment() -> InfinityModule {
    let mut fragment = InfinityModule::new();
    let shared = "x".repeat(64 << 10);
    let mut elements = Vec::with_capacity(2000);
    for _ in 0..2000 {
        elements.push(fragment.push(Inode::Str(shared.clone())));
    }
    let root = fragment.push(Inode::Array { elements });
    fragment.set_root(Some(root));
    let image = encode(&fragment).expect("encode fragment");
    active_infinity::decode(&image).expect("decode fragment")
}

/// One 1 MiB blob payload shared by 200 `Blob` nodes: ~200 MiB decoded.
fn amplified_blob_fragment() -> InfinityModule {
    let payload = vec![0xABu8; 1 << 20];
    let hash = *blake3::hash(&payload).as_bytes();
    let mut fragment = InfinityModule::new();
    let mut elements = Vec::with_capacity(200);
    for _ in 0..200 {
        elements.push(fragment.push(Inode::Blob {
            hash,
            size: payload.len() as u64,
            tainted: false,
            media_type: "application/octet-stream".to_string(),
            payload: Some(payload.clone()),
        }));
    }
    let root = fragment.push(Inode::Array { elements });
    fragment.set_root(Some(root));
    let image = encode(&fragment).expect("encode fragment");
    active_infinity::decode(&image).expect("decode fragment")
}

/// Push `ops` as one delta generation and return the delta frame, with the
/// base generation already decoded by the returned decoder.
fn decoder_with_delta(
    ops: &[DeltaOp],
    limits: active_infinity::Limits,
) -> (StreamDecoder, active_infinity::stream::Frame) {
    let base = base_module();
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    let base_frames = encoder.frames();
    encoder.push_delta(&base, ops).expect("delta");
    let all = encoder.frames();
    let delta = all[base_frames.len()].clone();
    assert_eq!(delta.kind, active_infinity::stream::FrameKind::Delta);
    let mut decoder = StreamDecoder::new().with_limits(limits);
    for frame in &base_frames {
        decoder.push(frame).expect("base frames");
    }
    (decoder, delta)
}

fn strict_limits() -> active_infinity::Limits {
    active_infinity::Limits {
        max_total_bytes: 8 << 20,
        ..Default::default()
    }
}

#[test]
fn strict_decoder_refuses_amplified_string_fragment() {
    let base = base_module();
    let root = base.root().expect("root");
    let fragment = amplified_string_fragment();
    // The image is ~150 KiB; the decoded module holds 2000 × 64 KiB.
    assert!(encode(&fragment).expect("encode").len() < 1 << 20);
    assert_eq!(
        fragment.decoded_payload_bytes(),
        2000 * (64 << 10),
        "the shared string is charged once per referencing node"
    );
    let (mut decoder, delta) = decoder_with_delta(
        &[DeltaOp::PutNode {
            target: root,
            fragment: Box::new(fragment),
        }],
        strict_limits(),
    );
    let before = decoder.pending_decoded_bytes();
    let error = decoder
        .push(&delta)
        .expect_err("an amplified fragment must be refused");
    assert_eq!(error.code(), "infinity/limit", "{error:?}");
    assert!(error.to_string().contains("delta decoded bytes"), "{error}");
    assert_eq!(
        decoder.pending_decoded_bytes(),
        before,
        "a refused frame kept its decoded-byte charge"
    );
}

#[test]
fn strict_decoder_refuses_amplified_blob_fragment() {
    let base = base_module();
    let root = base.root().expect("root");
    let fragment = amplified_blob_fragment();
    assert!(encode(&fragment).expect("encode").len() < 2 << 20);
    assert_eq!(
        fragment.decoded_payload_bytes(),
        200 * (1 << 20) + 200 * "application/octet-stream".len() as u64,
        "a blob payload is charged once per Blob node that carries it"
    );
    let (mut decoder, delta) = decoder_with_delta(
        &[DeltaOp::PutNode {
            target: root,
            fragment: Box::new(fragment),
        }],
        strict_limits(),
    );
    let error = decoder
        .push(&delta)
        .expect_err("an amplified blob fragment must be refused");
    assert_eq!(error.code(), "infinity/limit", "{error:?}");
    assert!(error.to_string().contains("delta decoded bytes"), "{error}");
}

#[test]
fn fragment_charge_counts_payload_bytes_per_reference() {
    // Two Str nodes sharing "hello", one Table with two one-byte field names:
    // nodes 3, entries 2, payload 5 + 5 + 1 + 1 = 12. Both strings are
    // reachable (INF-04: encode refuses unreachable nodes).
    let base = base_module();
    let root = base.root().expect("root");
    let mut fragment = InfinityModule::new();
    let first = fragment.push(Inode::Str("hello".to_string()));
    let second = fragment.push(Inode::Str("hello".to_string()));
    let table = fragment.push(Inode::Table {
        fields: vec![("f".to_string(), first), ("g".to_string(), second)],
    });
    fragment.set_root(Some(table));
    let image = encode(&fragment).expect("encode fragment");
    let fragment = active_infinity::decode(&image).expect("decode fragment");
    assert_eq!(fragment.decoded_payload_bytes(), 12);

    let (mut decoder, delta) = decoder_with_delta(
        &[DeltaOp::PutNode {
            target: root,
            fragment: Box::new(fragment),
        }],
        active_infinity::Limits::default(),
    );
    decoder.push(&delta).expect("small fragment accepted");
    let expected = (3u64)
        .saturating_mul(std::mem::size_of::<Inode>() as u64 + 32)
        .saturating_add(2 * 40)
        .saturating_add(12);
    assert_eq!(
        decoder.pending_decoded_bytes(),
        expected,
        "nodes + entries + payload bytes, nothing else"
    );
}

#[test]
fn large_fragment_still_decodes_under_default_limits() {
    // The fix must not over-refuse: a 128 MiB fragment is under the default
    // 1 GiB total budget and the 256 MiB decoded-bytes budget (INF-01).
    let base = base_module();
    let root = base.root().expect("root");
    let fragment = amplified_string_fragment();
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder
        .push_delta(
            &base,
            &[DeltaOp::PutNode {
                target: root,
                fragment: Box::new(fragment),
            }],
        )
        .expect("delta");
    let bytes = encoder.to_bytes();
    let streamed = active_infinity::stream::decode_stream(&bytes).expect("decode stream");
    // 1 Array + 2000 Str: the fragment's own Array node is orphaned by the
    // graft and dropped by the stream's re-encode (INF-04 opt-in).
    assert_eq!(streamed.module.node_count(), 2001);
}
