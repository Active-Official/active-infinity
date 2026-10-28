#![no_main]

//! Header section descriptors: offsets, counts, total size and overlap.
//!
//! Invariants under test:
//!
//! 1. Any section descriptor that points outside the image, is misaligned, or
//!    overlaps another section is refused with a stable `infinity/*` code.
//! 2. A count that cannot be satisfied by the remaining bytes is refused before
//!    an allocation proportional to the count.
//! 3. A mutated image that still validates re-encodes canonically.
//!
//! Run with `cargo +nightly fuzz run fuzz_layout_sections -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_infinity::layout::{Header, Section};
use active_infinity::{decode, encode, validate, validate_canonical, Limits};

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let Ok(base) = encode(&common::fixture()) else {
        return;
    };
    if data.len() < 12 {
        return;
    }

    for round in 0..4usize {
        let mut bytes = base.clone();
        let section = Section::ALL[data[round] as usize % Section::ALL.len()];
        let descriptor = 64 + section as usize * 8;
        if descriptor + 8 > bytes.len() {
            continue;
        }
        let offset = common::get_u32(&bytes, descriptor).unwrap_or(0);
        let count = common::get_u32(&bytes, descriptor + 4).unwrap_or(0);
        match data[(round + 4) % data.len()] % 5 {
            0 => {
                // Offset: header, past the end, and one byte off alignment.
                let choices = [
                    0,
                    bytes.len() as u32 + 1,
                    offset.wrapping_add(1),
                    offset.wrapping_sub(1),
                    u32::MAX,
                ];
                common::put_u32(
                    &mut bytes,
                    descriptor,
                    choices[data[(round + 5) % data.len()] as usize % choices.len()],
                );
            }
            1 => {
                // Count: zero, one, huge, and one past the current value.
                let choices = [0, 1, u32::MAX, count.wrapping_add(1), count / 2];
                common::put_u32(
                    &mut bytes,
                    descriptor + 4,
                    choices[data[(round + 6) % data.len()] as usize % choices.len()],
                );
            }
            2 => {
                // Total size: shorter and longer than the real buffer.
                let choices = [
                    0u64,
                    1,
                    bytes.len() as u64 - 1,
                    bytes.len() as u64 + 1,
                    u64::MAX,
                ];
                let value = choices[data[(round + 7) % data.len()] as usize % choices.len()];
                common::put_u64(&mut bytes, 56, value);
            }
            3 => {
                // Overlap: point this section at another section's start.
                let other = Section::ALL[data[(round + 8) % data.len()] as usize % Section::ALL.len()];
                let other_offset = Header::parse(&bytes)
                    .map(|header| header.span(other).offset)
                    .unwrap_or(0);
                common::put_u32(&mut bytes, descriptor, other_offset);
            }
            _ => {
                // Truncate the buffer itself, keeping the declared total size.
                let cut = 1 + (data[(round + 9) % data.len()] as usize % bytes.len());
                bytes.truncate(cut.max(1));
            }
        }
        if !common::rehash(&mut bytes) {
            continue;
        }
        match validate(&bytes) {
            Ok(_) => {
                if let Ok(module) = decode(&bytes) {
                    let image = encode(&module).expect("validated module encodes");
                    assert!(
                        validate_canonical(&image, Limits::default()).is_ok(),
                        "a validated layout mutation did not re-encode canonically"
                    );
                }
            }
            Err(error) => {
                assert!(
                    error.code().starts_with("infinity/"),
                    "unexpected error code {}",
                    error.code()
                );
            }
        }
    }
});
