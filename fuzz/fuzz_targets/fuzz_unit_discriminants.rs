#![no_main]

//! Unit discriminants: unknown and boundary values must fail closed.
//!
//! Invariants under test (I-8, I-10):
//!
//! 1. Every built-in unit discriminant round-trips through encode/decode.
//! 2. An unknown discriminant in the unit table is `infinity/unknown-unit`.
//! 3. A quantity that points past the unit table is `infinity/unit-ref`.
//!
//! Run with `cargo +nightly fuzz run fuzz_unit_discriminants -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_infinity::layout::{Header, Section};
use active_infinity::{decode, encode, validate, InfinityModule, Inode, UnitTag};

#[path = "common.rs"]
mod common;

fn quantity_with(unit: UnitTag) -> InfinityModule {
    let mut module = InfinityModule::new();
    let number = module.push(Inode::Int(42));
    let quantity = module.push(Inode::Quantity {
        value: number,
        unit,
    });
    module.set_root(Some(quantity));
    module
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // 1. Known discriminants (including the boundary ones the fuzzer picks).
    let discriminants: [u32; 8] = [0, 1, 2, 3, 4, 5, u32::from(data[0] % 8), 255];
    for disc in discriminants {
        if let Some(unit) = UnitTag::from_discriminant(disc) {
            let module = quantity_with(unit.clone());
            let image = encode(&module).expect("a built-in unit encodes");
            assert!(validate(&image).is_ok(), "unit {disc} must validate");
            let decoded = decode(&image).expect("a validated image decodes");
            let again = encode(&decoded).expect("re-encode");
            assert_eq!(image, again, "unit {disc} is not canonical");
            assert_eq!(again, image, "unit {} changed identity", unit.name());
        }
    }

    // 2 and 3. Mutate the unit table and the quantity's unit index.
    let module = quantity_with(UnitTag::Milliseconds);
    let Ok(base) = encode(&module) else {
        return;
    };
    let Ok(header) = Header::parse(&base) else {
        return;
    };
    let nodes = header.span(Section::Nodes).offset as usize;
    let units = header.span(Section::Units).offset as usize;
    let unit_count = header.span(Section::Units).count;
    if unit_count == 0 {
        return;
    }

    // Unknown discriminant in the table.
    let mut unknown = base.clone();
    let disc = u32::from_le_bytes([
        data[0],
        data.get(1).copied().unwrap_or(0),
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0),
    ]);
    common::put_u32(&mut unknown, units, disc);
    if common::rehash(&mut unknown) {
        let outcome = validate(&unknown);
        // `0..=UNIT_MAX_BUILTIN` are valid units and `UNIT_NAMED` is the named
        // escape hatch; everything else must be refused.
        if UnitTag::from_discriminant(disc).is_some() || disc == active_infinity::unit::UNIT_NAMED {
            let _ = outcome;
        } else {
            let error = outcome.expect_err("an unknown unit discriminant must be refused");
            assert_eq!(error.code(), "infinity/unknown-unit");
        }
    }

    // Quantity points past the unit table.
    let mut out_of_range = base.clone();
    let mut found = false;
    for index in 0..header.span(Section::Nodes).count {
        let at = nodes + index as usize * 32;
        if at + 32 <= out_of_range.len() && out_of_range[at] == 6 {
            common::put_u64(&mut out_of_range, at + 8, u64::MAX);
            found = true;
            break;
        }
    }
    if found && common::rehash(&mut out_of_range) {
        let error = validate(&out_of_range).expect_err("an out-of-range unit must be refused");
        assert_eq!(error.code(), "infinity/unit-ref");
    }
});
