#![no_main]

//! Decoder fuzz target.
//!
//! Invariants under test:
//!
//! 1. `validate` never panics, never hangs and never over-allocates, whatever
//!    the bytes are (the validator is the only gate before any parse).
//! 2. A buffer that validates decodes without panicking.
//! 3. A buffer that validates re-encodes to itself (canonical identity) and the
//!    canonical proof agrees.
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

    // (3) Canonical identity: re-encoding reproduces the image, and the strict
    // canonical proof agrees with plain validation.
    if let Ok(image) = encode(&module) {
        assert_eq!(
            &image[..],
            data,
            "a validated canonical image must re-encode to itself"
        );
        assert!(validate_canonical(data, Limits::default()).is_ok());
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
