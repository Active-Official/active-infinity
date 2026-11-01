#![no_main]

//! Full validate + decode + view path for arbitrary bytes.
//!
//! Invariants under test:
//!
//! 1. `validate` answers for every input: no panic, no hang, no allocation
//!    proportional to a declared count.
//! 2. A buffer that validates decodes.
//! 3. The encoder emits canonical bytes: a decoded image re-encodes to a
//!    canonical fixpoint, and an image that already passes the canonical proof
//!    re-encodes to itself.
//! 4. The zero-copy view never panics on validated input.
//! 5. Projections are total on validated input and the Protobuf projection is
//!    deterministic.
//!
//! Run with `cargo +nightly fuzz run fuzz_decode_infinity -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_infinity::{
    decode, decode_with, encode, hash_image, validate, validate_canonical, DecodeOpts,
    InfinityView, Limits,
};

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    // 1. The gate always answers with a stable code.
    let meta = match validate(data) {
        Ok(meta) => meta,
        Err(error) => {
            assert!(
                error.code().starts_with("infinity/"),
                "unexpected code {}",
                error.code()
            );
            return;
        }
    };

    // 2. A validated image decodes, densely and under the strict options.
    let module = decode(data).expect("a validated image decodes");
    // The strict options must agree with the canonical proof: a valid but
    // non-canonical image is `infinity/not-canonical`, never a silent success.
    let strict = decode_with(
        data,
        DecodeOpts {
            limits: Limits::default(),
            verify_hash: true,
            verify_canonical: true,
        },
    );
    if validate_canonical(data, Limits::default()).is_ok() {
        assert!(strict.is_ok(), "a canonical image decodes under strict options");
    } else {
        assert_eq!(
            strict.expect_err("a non-canonical image is refused").code(),
            "infinity/not-canonical",
            "strict decode code"
        );
    }

    // 3. Canonical identity.
    {
        let image = encode(&module).expect("a decoded module encodes");
        assert!(
            validate_canonical(&image, Limits::default()).is_ok(),
            "the encoder must emit bytes that pass the canonical proof"
        );
        let again = decode(&image).expect("a canonical image decodes");
        assert_eq!(
            encode(&again).expect("re-encode"),
            image,
            "canonical form is a fixpoint of decode/encode"
        );
        if validate_canonical(data, Limits::default()).is_ok() {
            assert_eq!(
                image.as_slice(),
                data,
                "an image that passes the canonical proof must re-encode to itself"
            );
        }
        assert_eq!(
            hash_image(&image).expect("hash"),
            active_infinity::layout::Header::parse(&image)
                .expect("header")
                .content_hash,
            "the header hash must be the image hash"
        );
    }

    // 4. Zero-copy views never panic on validated input.
    let view = InfinityView::new(data, Limits::default()).expect("a validated image is viewable");
    {
        assert_eq!(view.node_count(), meta.nodes);
        // The view path is O(nodes); cap the walk so one large valid input
        // cannot spend the whole fuzz budget. Large-graph projection work is
        // gated separately below.
        for index in 0..view.node_count().min(4096) {
            let id = active_infinity::NodeId(index);
            let node = view.node(id).expect("a validated node reads");
            view.children(id)
                .expect("a validated node has readable children");
            let _ = node.kind_name();
        }
    }

    // 5. Projections are total and deterministic. A projection walks the graph,
    // so the work is bounded here; the conformance suite covers large modules.
    if meta.nodes <= 4096 {
        // A valid module projects; only a resource ceiling may refuse.
        if let Err(error) = active_infinity::interop::to_redacted_json(&module) {
            assert_eq!(error.code(), "infinity/limit", "JSON projection refused");
        }
        let _ = active_infinity::interop::provenance_lines(&module);
        let _ = active_infinity::interop::value_paths(&module);
        let first = active_infinity::to_protobuf(&module);
        let second = active_infinity::to_protobuf(&module);
        match (first, second) {
            (Ok(first), Ok(second)) => assert_eq!(
                first, second,
                "the protobuf projection must be deterministic"
            ),
            (Err(first), Err(second)) => {
                assert_eq!(first.code(), "infinity/limit", "protobuf refused");
                assert_eq!(second.code(), "infinity/limit", "protobuf refused");
            }
            _ => panic!("the protobuf projection is not deterministic"),
        }
    }

    let _ = common::canary(data);
});
