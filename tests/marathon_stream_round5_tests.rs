//! I-13 round 5: the work ceiling must latch before the work, deltas must
//! change something, and a refused op list must leave the module untouched.

use active_infinity::stream::{
    apply_delta_in_place, encode_stream, DeltaOp, Frame, FrameKind, StreamDecoder, StreamEncoder,
};
use active_infinity::{encode, InfinityModule, Inode, NodeId, Provenance};

fn base_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("gateway".to_string()));
    let port = module.push(Inode::Int(8080));
    let root = module.push(Inode::Table {
        fields: vec![("name".to_string(), name), ("port".to_string(), port)],
    });
    module.set_root(Some(root));
    module.bind("gateway", root);
    let image = encode(&module).expect("encode");
    active_infinity::decode(&image).expect("decode")
}

fn replay(frames: &[Frame]) -> StreamDecoder {
    let mut decoder = StreamDecoder::new();
    for frame in frames {
        decoder.push(frame).expect("frame");
    }
    decoder
}

/// Every generation must change the module: a delta that re-encodes to the same
/// image still costs a clone, a merge and a full encode.
#[test]
fn a_no_op_delta_is_refused() {
    let base = base_module();
    let root = base.root().expect("root");
    // The encoder refuses these too, so the frames are built by hand: this test
    // is about the decoder's own guard. Payloads are the wire form of one op.
    let mut set_root = Vec::new();
    set_root.extend_from_slice(&1u32.to_le_bytes());
    set_root.push(0); // SetRoot
    set_root.extend_from_slice(&root.0.to_le_bytes());

    let mut set_provenance = Vec::new();
    set_provenance.extend_from_slice(&1u32.to_le_bytes());
    set_provenance.push(7); // SetProvenance
    set_provenance.push(0); // None

    for (index, payload) in [set_root, set_provenance].into_iter().enumerate() {
        let frames = encode_stream(&base, 4096).expect("frames");
        let mut decoder = replay(&frames);
        let delta = Frame {
            kind: FrameKind::Delta,
            sequence: decoder.frames(),
            payload,
        };
        decoder
            .push(&delta)
            .expect("the delta frame itself is valid");
        let end = Frame {
            kind: FrameKind::End,
            sequence: decoder.frames(),
            payload: vec![0u8; 40],
        };
        let error = decoder
            .push(&end)
            .expect_err("a no-op delta must be refused");
        assert_eq!(
            error.code(),
            "infinity/stream-delta",
            "case {index}: {error}"
        );
        assert!(
            error.to_string().contains("did not change"),
            "case {index}: {error}"
        );
    }
}

/// A wrong-hash `End` is retryable, but the retry must charge the work budget:
/// replaying it cannot buy unbounded CPU, and the ceiling eventually latches.
/// A wider module, so one replayed `End` costs measurable assembly work.
fn wide_base(fields: usize) -> InfinityModule {
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Int(1));
    let mut entries = Vec::with_capacity(fields);
    for field in 0..fields {
        entries.push((format!("field{field:05}"), value));
    }
    let root = module.push(Inode::Table { fields: entries });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode");
    active_infinity::decode(&image).expect("decode")
}

#[test]
fn replaying_a_wrong_hash_end_latches_the_ceiling() {
    let base = wide_base(5_000);
    let size = encode(&base).expect("encode").len() as u64;
    let frames = encode_stream(&base, 4096).expect("frames");
    let mut decoder = StreamDecoder::new().with_limits(active_infinity::Limits {
        max_total_bytes: size + 64,
        ..active_infinity::Limits::default()
    });
    for frame in &frames[..frames.len() - 1] {
        decoder.push(frame).expect("begin and batches");
    }
    let mut end = frames.last().expect("end").clone();
    end.payload[0] ^= 0xFF; // break the hash, keep the frame legal
    let mut saw_limit = false;
    for _ in 0..1_000 {
        match decoder.push(&end) {
            Ok(()) => panic!("a wrong hash must never be accepted"),
            Err(error) if error.code() == "infinity/limit" => {
                saw_limit = true;
                break;
            }
            Err(error) => assert_eq!(error.code(), "infinity/stream-hash", "{error}"),
        }
    }
    assert!(saw_limit, "the work ceiling never latched");
    // After the latch every replay is refused before doing any work.
    let start = std::time::Instant::now();
    for _ in 0..10_000 {
        let error = decoder.push(&end).expect_err("latched");
        assert_eq!(error.code(), "infinity/limit");
    }
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "10000 latched replays took {:?}",
        start.elapsed()
    );
}

/// The hash covers `total_size`, so a size mismatch must not have its own code:
/// that would be a one-bit oracle over the receiver's private image size.
#[test]
fn a_size_mismatch_is_a_hash_fault() {
    let base = base_module();
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder
        .push_delta(
            &base,
            &[DeltaOp::SetProvenance(Some(Provenance {
                timestamp_ms: 7,
                ..Provenance::default()
            }))],
        )
        .expect("delta");
    let frames = encoder.frames();
    let mut decoder = StreamDecoder::new();
    for frame in &frames[..frames.len() - 1] {
        decoder.push(frame).expect("frames before end");
    }
    let mut end = frames.last().expect("end").clone();
    let size = u64::from_le_bytes(end.payload[32..40].try_into().expect("size"));
    end.payload[32..40].copy_from_slice(&(size + 1).to_le_bytes());
    let error = decoder.push(&end).expect_err("size mismatch");
    assert_eq!(error.code(), "infinity/stream-hash", "{error}");
}

/// The public in-place delta API is fail-closed: a list that fails halfway
/// leaves the module byte-identical.
#[test]
fn a_failed_delta_list_leaves_the_module_unchanged() {
    let base = base_module();
    let mut module = base.clone();
    // Encode the baseline before pushing the replacement (INF-04): the
    // replacement is unreachable until the delta runs, and encode now
    // refuses unreachable nodes.
    let before = encode(&module).expect("encode");
    let replacement = module.push(Inode::Int(1));
    let error = apply_delta_in_place(
        &mut module,
        &[
            DeltaOp::SetRoot(Some(replacement)),
            DeltaOp::SetRoot(Some(NodeId(99))),
        ],
    )
    .expect_err("the dangling root is refused");
    assert_eq!(error.code(), "infinity/stream-delta", "{error}");
    // The failed delta rolled the root back, but the pushed replacement node
    // is still orphaned in the arena (INF-04), so the after-image opts in
    // to the drop. It must equal the baseline: the failed list changed
    // nothing reachable.
    let after = active_infinity::encode_with(
        &module,
        active_infinity::layout::EncodeOpts {
            drop_unreachable: true,
            ..active_infinity::layout::EncodeOpts::default()
        },
    )
    .expect("encode");
    assert_eq!(before, after, "the failed list mutated the module");
}

/// A wrong magic in a 4-31 byte tail is permanent; reporting truncation would
/// make a caller wait for bytes that cannot help.
#[test]
fn a_short_wrong_magic_tail_is_refused() {
    let mut decoder = StreamDecoder::new();
    let error = decoder.push_bytes(b"XXXXXXXX").expect_err("wrong magic");
    assert_eq!(error.code(), "infinity/stream-magic", "{error}");
}

/// A wire boolean is 0 or 1; any other tag is a delta fault.
#[test]
fn a_non_boolean_tag_is_refused() {
    let base = base_module();
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    encoder
        .push_delta(
            &base,
            &[DeltaOp::SetProvenance(Some(Provenance {
                timestamp_ms: 1,
                ..Provenance::default()
            }))],
        )
        .expect("delta");
    let frames = encoder.frames();
    let mut decoder = StreamDecoder::new();
    for frame in &frames[..frames.len() - 2] {
        decoder.push(frame).expect("base generation");
    }
    let mut delta = frames[frames.len() - 2].clone();
    assert_eq!(delta.kind, FrameKind::Delta);
    // payload: op_count u32, op code u8 (`7` = SetProvenance), present u8.
    delta.payload[5] = 2;
    let error = decoder.push(&delta).expect_err("non-boolean tag");
    assert_eq!(error.code(), "infinity/stream-delta", "{error}");
    assert!(error.to_string().contains("boolean"), "{error}");
}
