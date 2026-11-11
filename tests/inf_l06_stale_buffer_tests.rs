//! INF-L06: `encode_into_with` / `encode_many` leave a stale buffer on error.
//!
//! Before the fix, `encode_into_with` returned `Err` without clearing `out`
//! whenever `check_reachable()` or `prepare()` failed — the caller's buffer
//! kept its previous (stale) bytes, i.e. the previous good image. `encode_many`
//! reuses buffers across a batch, so a failed item left a previous item's
//! complete image in its slot (and every later slot kept its previous
//! image too, untouched); a caller that reads `out[i]` without checking the
//! `Err` — or that retries — could publish or use a stale image for the
//! wrong module. This is the audit's probe P-H: the buffer equals the
//! previous good image after a failed `encode_into`.
//!
//! After the fix: `encode_into_with` clears `out` at entry (before
//! `check_reachable()` / `prepare()`), and clears it again if emission
//! itself fails mid-image, so `Err` always leaves `out` empty; `encode_many`
//! clears every slot at entry, so on `Err` the slots before the failure hold
//! the fresh images for their modules, and the failed slot and every later
//! slot are empty — no slot anywhere holds bytes from a previous batch.
//! Clearing preserves capacity (`Vec::clear` never shrinks), so the
//! buffer-reuse contract the batch tests pin is unchanged on success.
//!
//! The second half of INF-L06 — the unchecked truncating casts
//! (`secret.len() as u32`, blob `len as u32`, `string.len() as u32` in the
//! strings heap accumulation) — is fixed in `src/encode.rs` with the same
//! checked conversion `encode_extensions` already uses, namely
//! `u32::try_from(..).map_err(|_| Error::TooLarge)?`. It has no test of
//! its own here: a live value past 4 GiB cannot be built without a
//! multi-gigabyte allocation, and the INF-L05 exact-size gate already
//! refuses any module whose total exceeds `u32::MAX` before emission (see
//! the record); the checked conversions are defence in depth, and the
//! emission exactness tests in `src/encode.rs` pin that the changed lines
//! still emit byte-identical images.

use active_infinity::{encode, encode_into, encode_many, InfinityModule, Inode, SecretBytes};

/// A small module that encodes fine: a string root.
fn good_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Str("hello".into()));
    module.set_root(Some(root));
    module
}

/// A module that fails `check_reachable()` (hence `encode_into_with`
/// before `prepare()` even runs): a string root plus one unreachable
/// secret node. Same shape as the INF-04 probe.
fn unreachable_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Str("hello".into()));
    let secret = module.push(Inode::Secret(SecretBytes::new(
        b"top-secret-value".to_vec(),
    )));
    let _ = secret;
    module.set_root(Some(root));
    module
}

/// A module that passes `check_reachable()` but fails `prepare()`: the
/// root is a blob whose payload does not hash to its declared hash, so
/// `prepare()` refuses it with "blob payload hash mismatch"
/// (`infinity/encode`). This is the audit's exact scenario — failure
/// inside `prepare()`, after the reachability check has passed.
fn prepare_failing_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Blob {
        hash: [0u8; 32],
        size: 3,
        tainted: false,
        media_type: String::new(),
        payload: Some(b"abc".to_vec()),
    });
    module.set_root(Some(root));
    module
}

/// A buffer holding a previous good image, with spare capacity — the
/// state a server or store reuses across encodes.
fn stale_buffer() -> (InfinityModule, Vec<u8>) {
    let good = good_module();
    let mut buffer = Vec::new();
    encode_into(&good, &mut buffer).expect("good module must encode");
    assert!(!buffer.is_empty(), "stale buffer must hold a real image");
    (good, buffer)
}

#[test]
fn encode_into_clears_stale_buffer_when_reachability_check_fails() {
    let (_good, mut buffer) = stale_buffer();
    let stale = buffer.clone();
    let capacity = buffer.capacity();
    let bad = unreachable_module();
    // The reachability check is the first fallible step; before the fix
    // this returned Err and left `buffer` equal to the previous image.
    let error = encode_into(&bad, &mut buffer).expect_err("unreachable node must fail");
    assert_eq!(error.code(), "infinity/node", "{error}");
    assert!(
        buffer.is_empty(),
        "failed encode_into must leave the buffer empty, but it still holds {} bytes \
         (the previous good image): {buffer:?} vs stale {stale:?}",
        buffer.len()
    );
    assert_eq!(
        buffer.capacity(),
        capacity,
        "clearing must not shrink the buffer: capacity is the reuse contract"
    );
}

#[test]
fn encode_into_clears_stale_buffer_when_prepare_fails() {
    let (_good, mut buffer) = stale_buffer();
    let stale = buffer.clone();
    let capacity = buffer.capacity();
    let bad = prepare_failing_module();
    // Audit probe P-H, word for word: the buffer equals the previous good
    // image after a failed encode_into — before the fix.
    assert!(
        bad.check_reachable().is_ok(),
        "fixture must pass reachability"
    );
    let error = encode_into(&bad, &mut buffer).expect_err("hash-mismatched blob must fail");
    assert_eq!(error.code(), "infinity/encode", "{error}");
    assert!(
        error.to_string().contains("hash mismatch"),
        "unexpected prepare error: {error}"
    );
    assert!(
        buffer.is_empty(),
        "failed encode_into must leave the buffer empty, but it still holds {} bytes \
         (the previous good image): {buffer:?} vs stale {stale:?}",
        buffer.len()
    );
    assert_eq!(
        buffer.capacity(),
        capacity,
        "clearing must not shrink the buffer"
    );
}

#[test]
fn encode_many_clears_failed_and_later_slots() {
    // Three previous-batch images sitting in the reused buffers.
    let modules: Vec<InfinityModule> = (0..3).map(|_| good_module()).collect();
    let mut buffers = Vec::new();
    encode_many(modules.iter(), &mut buffers).expect("first batch must encode");
    assert_eq!(buffers.len(), 3);
    let stale: Vec<Vec<u8>> = buffers.clone();
    let capacities: Vec<usize> = buffers.iter().map(Vec::capacity).collect();
    assert!(
        stale.iter().all(|b| !b.is_empty()),
        "stale slots must hold images"
    );

    // Batch [good, bad, good]: item 1 fails in prepare().
    let batch: Vec<InfinityModule> = vec![good_module(), prepare_failing_module(), good_module()];
    let error = encode_many(batch.iter(), &mut buffers).expect_err("batch must fail on item 1");
    assert_eq!(error.code(), "infinity/encode", "{error}");
    // Slot 0 is the fresh image for batch item 0 — the successful prefix
    // is kept, not wiped.
    assert_eq!(
        buffers[0],
        encode(&batch[0]).expect("item 0 must encode"),
        "the successful prefix must keep its fresh image"
    );
    // The failed slot must be empty, not the previous batch's image.
    assert!(
        buffers[1].is_empty(),
        "failed slot must be empty, but it still holds the previous batch's image: {:?}",
        buffers[1]
    );
    // Later slots were never processed in this batch: they must be empty
    // too, not stale — before the fix they kept the previous batch's images.
    assert!(
        buffers[2].is_empty(),
        "unprocessed later slot must be empty, but it still holds the previous batch's image: {:?}",
        buffers[2]
    );
    assert_eq!(
        buffers.iter().map(Vec::capacity).collect::<Vec<_>>(),
        capacities,
        "clearing must not shrink any buffer: capacity is the reuse contract"
    );
}

#[test]
fn encode_many_clears_every_slot_when_the_first_item_fails() {
    let modules: Vec<InfinityModule> = (0..2).map(|_| good_module()).collect();
    let mut buffers = Vec::new();
    encode_many(modules.iter(), &mut buffers).expect("first batch must encode");
    let capacities: Vec<usize> = buffers.iter().map(Vec::capacity).collect();

    let batch: Vec<InfinityModule> = vec![prepare_failing_module(), good_module()];
    let error = encode_many(batch.iter(), &mut buffers).expect_err("batch must fail on item 0");
    assert_eq!(error.code(), "infinity/encode", "{error}");
    assert!(
        buffers.iter().all(|b| b.is_empty()),
        "every slot must be empty after a first-item failure, got lengths {:?}",
        buffers.iter().map(Vec::len).collect::<Vec<_>>()
    );
    assert_eq!(
        buffers.iter().map(Vec::capacity).collect::<Vec<_>>(),
        capacities,
        "clearing must not shrink any buffer"
    );
}

#[test]
fn encode_into_success_after_failure_reuses_the_buffer() {
    let (good, mut buffer) = stale_buffer();
    let capacity = buffer.capacity();
    let bad = prepare_failing_module();
    assert!(encode_into(&bad, &mut buffer).is_err());
    assert!(buffer.is_empty(), "buffer must be empty after the failure");
    // Recovery: the same buffer encodes the next good module, byte-identical
    // to `encode`, and still at the original capacity.
    encode_into(&good, &mut buffer).expect("retry must succeed");
    assert_eq!(buffer, encode(&good).expect("encode"));
    assert_eq!(
        buffer.capacity(),
        capacity,
        "capacity must survive failure + retry"
    );
}
