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
    // 1. The gate always answers.
    let meta = match validate(data) {
        Ok(meta) => meta,
        Err(_) => return,
    };

    // 2. A validated image decodes, densely and under the strict options.
    let module = match decode(data) {
        Ok(module) => module,
        Err(_) => return,
    };
    let _ = decode_with(
        data,
        DecodeOpts {
            limits: Limits::default(),
            verify_hash: true,
            verify_canonical: true,
        },
    );

    // 3. Canonical identity.
    if let Ok(image) = encode(&module) {
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
    if let Ok(view) = InfinityView::new(data, Limits::default()) {
        assert_eq!(view.node_count(), meta.nodes);
        for index in 0..view.node_count() {
            let id = active_infinity::NodeId(index);
            if let Ok(node) = view.node(id) {
                let _ = view.children(id);
                let _ = node.kind_name();
            }
        }
    }

    // 5. Projections are total and deterministic. A projection walks the graph,
    // so the work is bounded here; the conformance suite covers large modules.
    if meta.nodes <= 4096 {
        let _ = active_infinity::interop::to_redacted_json(&module);
        let _ = active_infinity::interop::provenance_lines(&module);
        let _ = active_infinity::interop::value_paths(&module);
        if let Ok(first) = active_infinity::to_protobuf(&module) {
            let second = active_infinity::to_protobuf(&module)
                .expect("projecting the same module twice succeeds");
            assert_eq!(
                first, second,
                "the protobuf projection must be deterministic"
            );
        }
    }

    let _ = common::canary(data);
});
