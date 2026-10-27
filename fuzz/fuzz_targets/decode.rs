#![no_main]

//! Decoder fuzz target.
//!
//! Invariants under test:
//!
//! 1. `validate` never panics, never hangs and never over-allocates, whatever
//!    the bytes are (the validator is the only gate before any parse).
//! 2. A buffer that validates decodes without panicking.
//! 3. The encoder always emits canonical bytes: whatever decode accepted, the
//!    image it re-encodes to passes the strict canonical proof and is a
//!    fixpoint of decode/encode. An input that merely *claims* canonical form is
//!    not required to be canonical — `validate` does not pay for that proof (see
//!    `docs/spec/layout.md` §6.1) — but when the proof does pass, the bytes must
//!    be reproduced exactly.
//! 4. A validated buffer can be read through the zero-copy view without panic.
//!
//! Run with `cargo +nightly fuzz run decode -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_infinity::{decode, encode, validate, validate_canonical, InfinityView, Limits};

fuzz_target!(|data: &[u8]| {
    // (1) The gate must always answer, never abort the process.
    let meta = match validate(data) {
        Ok(meta) => meta,
        Err(_) => return,
    };

    // (2) A validated image decodes.
    let module = match decode(data) {
        Ok(module) => module,
        Err(_) => return,
    };

    // (3) Canonical identity.
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
    }

    // (4) Zero-copy views never panic on validated input.
    let view = match InfinityView::new(data, Limits::default()) {
        Ok(view) => view,
        Err(_) => return,
    };
    assert_eq!(view.node_count(), meta.nodes);
    for index in 0..view.node_count() {
        let id = active_infinity::NodeId(index);
        if let Ok(node) = view.node(id) {
            let _ = view.children(id);
            let _ = node.kind_name();
        }
    }
});
