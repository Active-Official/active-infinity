//! INF-13: the stream work limit undercharges ~3x per generation.
//!
//! The streaming decoder's per-generation work limit (`StreamDecoder`, in
//! `src/stream.rs`) charges each generation at ~1x the image length, while a
//! generation really does a full validate-canonical-class pass: apply (clone
//! the base module and merge), re-encode, `Validated::new` with
//! `verify_canonical: true` (validate + hash + decode + re-encode +
//! re-validate), and a final `decode_validated`. W4 measured 20 toggling
//! `SetProvenance` generations on a 10,493,712-byte image at 118.9 ms/gen
//! against one `validate_canonical` at 76.6 ms; round 2 measured 72
//! generations before the latch on a ~900 KiB image with a 1 MiB
//! `max_total_bytes` (64 MiB charged budget), where 4x charging would give
//! ~18. The audit's recommended fix is to charge each generation at 4x the
//! image length and lower the total multiplier (e.g. 8x `max_total_bytes`).
//!
//! These tests measure the real work per generation (wall time of each
//! sub-pass, counted as image-sized passes) and pin the latch point: the
//! latch must trip at a small multiple of the 4x charge, not after ~64
//! generations of 1x charging.

use active_infinity::stream::{apply_delta, DeltaOp, StreamDecoder, StreamEncoder};
use active_infinity::{
    decode, encode, validate_canonical, InfinityModule, Inode, Limits, Provenance,
};
use std::time::{Duration, Instant};

/// W4's builder: `count` strings of `each` bytes under one Array root.
/// (W4-R1-INF-CORE `w4_inf13_generation_work`: 160 x 64 KiB = 10,493,712
/// bytes; round 2's `t10_inf13_work_limit_undercharges`: 14 x 64 KiB =
/// 921,936 bytes.)
fn array_of_strs(count: usize, each: usize) -> (InfinityModule, Vec<u8>) {
    let mut module = InfinityModule::new();
    let mut ids = Vec::new();
    for i in 0..count {
        let s = format!("s{i:06}-").repeat(each / 8 + 1);
        ids.push(module.push(Inode::Str(s[..each].to_string())));
    }
    let root = module.push(Inode::Array { elements: ids });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode");
    (module, image)
}

/// Round 5's wide base: one shared Int under a 5,000-field Table.
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
    decode(&image).expect("decode")
}

/// Minimum of three runs: the least-noisy estimate of a pass's true cost on
/// a machine shared with other workers.
fn min_of_three<F>(mut run: F) -> Duration
where
    F: FnMut() -> Duration,
{
    let mut best = run();
    for _ in 0..2 {
        best = best.min(run());
    }
    best
}

/// Measure the real work per generation on the W4 shape (160 x 64 KiB
/// strings, ~10 MiB image): time one `validate_canonical`, one encode, one
/// decode, one `apply_delta`, and the average decoder generation, and print
/// every number with the ratios. This test passes before and after the fix:
/// it measures real work, not the charge. The latch tests below are the
/// fail-before / pass-after discriminators.
#[test]
fn inf13_generation_work_is_measured_not_asserted() {
    let (mut current, image) = array_of_strs(160, 64 * 1024);
    let size = image.len();
    println!("INF-13 image bytes={size}");
    assert!(
        size > 10_000_000,
        "the W4 shape must stay a ~10 MiB image, got {size}"
    );

    // One validate_canonical = validate + hash + decode + re-encode +
    // re-validate: four image-sized passes.
    let vc = min_of_three(|| {
        let start = Instant::now();
        validate_canonical(&image, Limits::default()).expect("validate_canonical");
        start.elapsed()
    });
    let t_encode = min_of_three(|| {
        let start = Instant::now();
        let _ = encode(&current).expect("encode");
        start.elapsed()
    });
    let t_decode = min_of_three(|| {
        let start = Instant::now();
        let _ = decode(&image).expect("decode");
        start.elapsed()
    });
    let probe_ops = [DeltaOp::SetProvenance(Some(Provenance {
        producer: Some("probe".to_string()),
        ..Provenance::default()
    }))];
    let t_apply = min_of_three(|| {
        let start = Instant::now();
        let _ = apply_delta(&current, &probe_ops).expect("apply_delta");
        start.elapsed()
    });
    println!("INF-13 one validate_canonical={vc:?} encode={t_encode:?} decode={t_decode:?} apply_delta={t_apply:?}");

    // A generation = apply + encode + Validated::new(verify_canonical) +
    // decode_validated, i.e. strictly more than one validate_canonical.
    let mut encoder = StreamEncoder::new(&current, 65_536).expect("encoder");
    let mut decoder = StreamDecoder::new();
    decoder
        .push_bytes(&encoder.to_bytes())
        .expect("base generation");
    assert!(decoder.module().is_some(), "initial generation present");
    let generations = 8usize;
    let mut total = Duration::ZERO;
    for i in 0..generations {
        let ops = [DeltaOp::SetProvenance(Some(Provenance {
            producer: Some(format!("gen-{i}")),
            ..Provenance::default()
        }))];
        encoder.push_delta(&current, &ops).expect("delta");
        current = apply_delta(&current, &ops).expect("apply");
        let frames = encoder.frames();
        let bytes: Vec<u8> = frames[frames.len() - 2..]
            .iter()
            .flat_map(|frame| frame.to_bytes())
            .collect();
        let start = Instant::now();
        decoder.push_bytes(&bytes).expect("generation");
        total += start.elapsed();
        assert_eq!(
            decoder
                .module()
                .expect("module")
                .provenance()
                .expect("provenance")
                .producer
                .as_deref(),
            Some(format!("gen-{i}").as_str()),
            "generation {i} applied"
        );
    }
    let _ = decoder.finish().expect("finish");
    let avg = total / generations as u32;
    // A generation does a validate-canonical-class pass plus apply, encode
    // and decode, so its cost in validate_canonical units is the pass
    // count: validate_canonical is ~4 image-sized passes, a generation is
    // ~6-8, i.e. a ratio of ~1.3-1.9 in release (up to ~2.4 in debug).
    let ratio = avg.as_secs_f64() / vc.as_secs_f64();
    println!(
        "INF-13 {generations} toggling generations: decoder total={total:?} avg={avg:?}; one validate_canonical={vc:?}; ratio avg/vc={ratio:.2}; implied image-sized passes per generation ~{:.1}",
        ratio * 4.0
    );
    assert!(
        total > vc * 5,
        "{generations} generations ({total:?}) must cost far more than one validation ({vc:?})"
    );
    assert!(
        avg >= vc / 2,
        "one generation ({avg:?}) must cost at least half a validate_canonical ({vc:?}): it re-validates canonically"
    );
}

/// Count completed generations before the latch on the wide 5,000-field
/// base with `max_total_bytes` just above the image size, and pin the count
/// to the 4x charge. Pre-fix the charge is ~1x image length, so ~64
/// generations complete (the old 64x limit divided by a 1x charge); with
/// the 4x charge and the 32x total, ~8 complete. The bound below is the old
/// 64x limit divided by the 4x charge, plus slack: it pins the charge
/// factor, not the total multiplier. The floor pins legitimate use: the base
/// generation plus at least one delta generation must complete.
#[test]
fn inf13_latch_trips_at_the_measured_point() {
    let base = wide_base(5_000);
    let size = encode(&base).expect("encode").len() as u64;
    // +4096 slack, as in round 4: the first SetProvenance delta grows the
    // image by a whole provenance section (~100 bytes), and `Validated::new`
    // refuses any image past `max_total_bytes` with "total bytes" -- with
    // only +64 slack the first delta would trip that ceiling instead of the
    // generation-work latch this test pins.
    let max_total = size + 4096;
    let mut encoder = StreamEncoder::new(&base, 4096).expect("encoder");
    let mut decoder = StreamDecoder::new().with_limits(Limits {
        max_total_bytes: max_total,
        ..Limits::default()
    });
    for frame in encoder.frames() {
        decoder.push(&frame).expect("first generation");
    }
    let mut completed = 1u64;
    let mut latched = false;
    for tick in 1..=500u64 {
        encoder
            .push_delta(
                &base,
                &[DeltaOp::SetProvenance(Some(Provenance {
                    timestamp_ms: tick,
                    ..Provenance::default()
                }))],
            )
            .expect("delta");
        let all = encoder.frames();
        let mut result = Ok(());
        for frame in &all[all.len() - 2..] {
            result = decoder.push(frame);
            if result.is_err() {
                break;
            }
        }
        match result {
            Ok(()) => completed += 1,
            Err(error) => {
                assert_eq!(error.code(), "infinity/limit", "{error}");
                assert!(
                    error.to_string().contains("generation work"),
                    "the latch must be the generation-work ceiling: {error}"
                );
                latched = true;
                break;
            }
        }
    }
    assert!(latched, "no work ceiling was reached in 500 generations");
    // The charged work itself pins the 4x rate: every completed generation
    // contributed at least 4x the image length (base End 4x assembled,
    // delta Ends 4x the pre-delta image, plus the 1x delta wire bytes and
    // the tripping charge on top).
    let charged = decoder.generation_work();
    println!("INF-13 wide-base latch: charged={charged}");
    assert!(
        charged >= completed * 4 * size,
        "charged work {charged} for {completed} generations of a {size}-byte image is below the 4x rate"
    );
    // Old limit (64x) / 4x charge + slack: ~18 for this shape. At 1x
    // charging ~64 generations complete, so this fails before the fix.
    let bound = (max_total.saturating_mul(64) / (4 * size)) + 2;
    println!("INF-13 wide-base latch: image={size} max_total={max_total} completed={completed} bound={bound}");
    assert!(
        completed <= bound,
        "{completed} generations completed before the latch; at a 4x charge at most {bound} may"
    );
    assert!(
        completed <= 10,
        "{completed} generations completed; the 32x total predicts ~8 at this tight limit, so the total budget must trip within a few generations"
    );
    assert!(
        completed >= 2,
        "only {completed} generation completed: the base plus one delta must fit the budget"
    );
}

/// The round-2 reproduction: a ~900 KiB image (14 x 64 KiB strings,
/// 921,936 bytes) with `max_total_bytes` = 1 MiB. Round 2 measured the
/// latch tripping only after 72 generations; at a 4x charge and the 32x
/// total, ~9 complete.
#[test]
fn inf13_round2_latch_reproduction() {
    let (module, image) = array_of_strs(14, 64 * 1024);
    let size = image.len() as u64;
    println!("INF-13 round-2 image bytes={size}");
    let max_total = 1 << 20;
    let mut encoder = StreamEncoder::new(&module, 65_536).expect("encoder");
    let mut decoder = StreamDecoder::new().with_limits(Limits {
        max_total_bytes: max_total,
        ..Limits::default()
    });
    for frame in encoder.frames() {
        decoder.push(&frame).expect("first generation");
    }
    let mut completed = 1u64;
    let mut latched = false;
    for tick in 1..=500u64 {
        encoder
            .push_delta(
                &module,
                &[DeltaOp::SetProvenance(Some(Provenance {
                    timestamp_ms: tick,
                    ..Provenance::default()
                }))],
            )
            .expect("delta");
        let all = encoder.frames();
        let mut result = Ok(());
        for frame in &all[all.len() - 2..] {
            result = decoder.push(frame);
            if result.is_err() {
                break;
            }
        }
        match result {
            Ok(()) => completed += 1,
            Err(error) => {
                assert_eq!(error.code(), "infinity/limit", "{error}");
                assert!(
                    error.to_string().contains("generation work"),
                    "the latch must be the generation-work ceiling: {error}"
                );
                latched = true;
                break;
            }
        }
    }
    assert!(latched, "no work ceiling was reached in 500 generations");
    // The charged work itself pins the 4x rate (see the wide-base test).
    let charged = decoder.generation_work();
    println!("INF-13 round-2 latch: charged={charged}");
    assert!(
        charged >= completed * 4 * size,
        "charged work {charged} for {completed} generations of a {size}-byte image is below the 4x rate"
    );
    let bound = (max_total.saturating_mul(64) / (4 * size)) + 2;
    println!("INF-13 round-2 latch: image={size} max_total={max_total} completed={completed} bound={bound}");
    assert!(
        completed <= bound,
        "{completed} generations completed before the latch; at a 4x charge at most {bound} may (round 2 measured 72 at a 1x charge)"
    );
    assert!(
        completed <= 10,
        "{completed} generations completed; the 32x total predicts ~9 at this tight limit, so the total budget must trip within a few generations"
    );
    assert!(
        completed >= 2,
        "only {completed} generation completed: the base plus one delta must fit the budget"
    );
}

/// The stream work limit and the INF-06 working-bytes budget must agree:
/// each generation's validate passes run under the same `Limits`, so a
/// working budget too small for the image refuses the generation with the
/// working-budget error (not the generation-work error), and a working
/// budget with room lets the generation through.
#[test]
fn inf13_working_budget_and_generation_budget_agree() {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("gateway".to_string()));
    let port = module.push(Inode::Int(8080));
    let root = module.push(Inode::Table {
        fields: vec![("name".to_string(), name), ("port".to_string(), port)],
    });
    module.set_root(Some(root));
    module.bind("gateway", root);
    let image = encode(&module).expect("encode");
    println!("INF-13 gateway image bytes={}", image.len());

    // 32 KiB of working budget cannot hold even this tiny image's validate
    // transient (the fixed 64 KiB allowance alone exceeds it).
    let frames = active_infinity::stream::encode_stream(&module, 4096).expect("frames");
    let mut decoder = StreamDecoder::new().with_limits(Limits {
        max_working_bytes: 32 << 10,
        ..Limits::default()
    });
    let mut error = None;
    for frame in &frames {
        if let Err(found) = decoder.push(frame) {
            error = Some(found);
            break;
        }
    }
    let error = error.expect("a 32 KiB working budget must refuse the generation");
    assert_eq!(error.code(), "infinity/limit", "{error}");
    assert!(
        error.to_string().contains("working bytes"),
        "the refusal must name the working budget, not the generation budget: {error}"
    );

    // 128 KiB of working budget admits the same image: the two budgets
    // compose instead of conflicting.
    let mut decoder = StreamDecoder::new().with_limits(Limits {
        max_working_bytes: 128 << 10,
        ..Limits::default()
    });
    for frame in &frames {
        decoder.push(frame).expect("frame");
    }
    let streamed = decoder.finish().expect("finish");
    assert_eq!(streamed.image, image, "the admitted image round-trips");
}
