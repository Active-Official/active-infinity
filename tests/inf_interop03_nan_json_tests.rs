//! Regression tests for INF-INTEROP-03: `to_redacted_json` silently rendered
//! non-finite floats as JSON `null`.
//!
//! Before the fix `serde_json::Value::from(f64)` yielded `Value::Null` for a
//! non-finite float, so a module whose root was `[Float(NaN), Float(inf)]`
//! rendered as `[null,null]` with no error and no marker (W4, probe
//! `audit_modules_probe::probe_json_nan`, CONFIRMED at 6aad041). A consumer
//! could not tell a NaN from a real null, and the data loss was silent: the
//! protobuf projection of the same module preserves the NaN bits, so the two
//! projections disagreed about what the module contains.
//!
//! Design decision (recorded in `records/F2-INF/INF-INTEROP-03.md`): tag,
//! not error. `to_redacted_json` is public API and a redaction/projection
//! surface; a legal module holding a NaN must still project, and returning
//! `Err` would turn a rendering question into a hard failure for every
//! caller that today gets (lossy but successful) output -- including callers
//! outside this repo, whose error handling cannot be enumerated here. The
//! fix renders a non-finite float as a tagged object, `{"$float": "NaN"}` /
//! `{"$float": "Infinity"}` / `{"$float": "-Infinity"}`, following the
//! renderer's existing marker convention (`$env`, `$expr`, `$active.blob`).
//! The tag is unambiguous: a real null renders as bare `null`, a real string
//! renders as a bare JSON string, and a data record key starting with `$` is
//! escaped by doubling (`$$...`) in this same renderer, so no data record
//! can produce a bare `{"$float": ...}` object. The tag preserves the float
//! class (NaN vs +inf vs -inf); it does not preserve NaN payload bits, which
//! JSON has no vocabulary for -- the canonical form already normalizes every
//! NaN to one quiet NaN (`layout::canonical_f64`), so the class is exactly
//! what the canonical form preserves. There is no in-repo JSON consumer that
//! parses markers back, so the tag is documented as the marker rather than
//! wired into a round-trip parser; a future parser can recognize
//! `{"$float": "NaN"}` exactly.

#![cfg(feature = "json")]

use active_infinity::interop::{to_redacted_json, to_redacted_json_pretty};
use active_infinity::{InfinityModule, Inode, UnitTag};

/// A module whose root is an array of the given values.
fn array_module(values: Vec<Inode>) -> InfinityModule {
    let mut module = InfinityModule::new();
    let ids: Vec<_> = values.into_iter().map(|value| module.push(value)).collect();
    let root = module.push(Inode::Array { elements: ids });
    module.set_root(Some(root));
    module
}

/// Parse the projection and hand back its JSON value; the projection must
/// always be valid JSON, tagged floats included.
fn projected(module: &InfinityModule) -> serde_json::Value {
    let json = to_redacted_json(module).expect("a legal module must project");
    serde_json::from_str(&json).expect("the projection must be valid JSON")
}

/// A rendered float tag must be exactly `{"$float": "<class>"}`: one key,
/// the marker name, the class string. Anything else is not the tag.
fn assert_float_tag(value: &serde_json::Value, expected: &str) {
    assert_eq!(
        value,
        &serde_json::json!({ "$float": expected }),
        "expected the ${{float}} tag for {expected}, got {value}"
    );
}

/// W4's reproduction, extended to all three non-finite classes: the root
/// `[Float(NaN), Float(+inf), Float(-inf)]` rendered as `[null,null,null]`.
/// It must now render as three tagged objects, with no `null` anywhere.
#[test]
fn probe_json_nan_no_longer_null() {
    let module = array_module(vec![
        Inode::Float(f64::NAN),
        Inode::Float(f64::INFINITY),
        Inode::Float(f64::NEG_INFINITY),
    ]);
    let raw = to_redacted_json(&module).expect("a legal module must project");
    assert!(
        !raw.contains("null"),
        "no non-finite float may render as null; got {raw}"
    );
    let value = projected(&module);
    let items = value.as_array().expect("the root is an array");
    assert_eq!(items.len(), 3, "all three floats must survive, got {value}");
    assert_float_tag(&items[0], "NaN");
    assert_float_tag(&items[1], "Infinity");
    assert_float_tag(&items[2], "-Infinity");
}

/// A negative NaN (sign bit set) tags as `"NaN"`, like every other NaN: the
/// canonical form normalizes every NaN to one quiet NaN, so the tag carries
/// the class, never a payload or a sign.
#[test]
fn probe_json_negative_nan_tags_as_nan() {
    let negative_nan = f64::from_bits(0xfff8_0000_0000_0000);
    assert!(negative_nan.is_nan() && negative_nan.is_sign_negative());
    let module = array_module(vec![Inode::Float(negative_nan)]);
    let value = projected(&module);
    let items = value.as_array().expect("the root is an array");
    assert_float_tag(&items[0], "NaN");
}

/// Control: finite floats still render as JSON numbers, unchanged by the
/// fix -- including -0.0, which stays a (finite) number.
#[test]
fn probe_json_finite_floats_still_numbers() {
    let module = array_module(vec![
        Inode::Float(1.5),
        Inode::Float(2.5),
        Inode::Float(0.0),
        Inode::Float(-0.0),
    ]);
    let value = projected(&module);
    let items = value.as_array().expect("the root is an array");
    assert_eq!(items.len(), 4, "all four floats must survive, got {value}");
    for (item, expected) in items.iter().zip([1.5f64, 2.5, 0.0, -0.0]) {
        assert!(
            item.is_number(),
            "a finite float must render as a JSON number, got {item}"
        );
        assert_eq!(
            item.as_f64(),
            Some(expected),
            "finite float {expected} must round-trip, got {item}"
        );
    }
}

/// Control: a real null still renders as JSON `null`. The tag must be
/// distinguishable from a real null -- if both rendered the same way, the
/// fix would have changed nothing.
#[test]
fn probe_json_real_null_still_null() {
    let module = array_module(vec![Inode::Null, Inode::Float(f64::NAN)]);
    let raw = to_redacted_json(&module).expect("a legal module must project");
    assert_eq!(
        raw, "[null,{\"$float\":\"NaN\"}]",
        "a real null stays null next to a tagged NaN; got {raw}"
    );
}

/// The tag applies wherever a float can nest, not just at the top level:
/// a record field holding NaN and a quantity whose value is +inf. The same
/// record also proves the tag cannot collide with data: a field literally
/// named `$float` holding the string `"NaN"` renders with its key escaped
/// to `$$float` and its value as a bare string -- never as the tag object.
#[test]
fn probe_json_nan_inside_record_and_quantity() {
    let mut module = InfinityModule::new();
    let nan = module.push(Inode::Float(f64::NAN));
    let inf = module.push(Inode::Float(f64::INFINITY));
    let quantity = module.push(Inode::Quantity {
        value: inf,
        unit: UnitTag::Named("m".to_string()),
    });
    let text = module.push(Inode::Str("NaN".to_string()));
    let root = module.push(Inode::Table {
        fields: vec![
            ("reading".to_string(), nan),
            ("distance".to_string(), quantity),
            ("$float".to_string(), text),
        ],
    });
    module.set_root(Some(root));
    let value = projected(&module);
    assert_float_tag(&value["reading"], "NaN");
    assert_eq!(
        value["distance"]["value"],
        serde_json::json!({ "$float": "Infinity" }),
        "a quantity value is rendered through the same float arm, got {value}"
    );
    assert_eq!(
        value["distance"]["unit"],
        serde_json::json!("m"),
        "the quantity unit is untouched, got {value}"
    );
    assert_eq!(
        value["$$float"],
        serde_json::json!("NaN"),
        "a data key named $float is escaped to $$float and its string value \
         stays a bare string, got {value}"
    );
    assert!(
        value.get("$float").is_none(),
        "no bare $float key may appear from data; the tag object is the only \
         shape that carries it, got {value}"
    );
}

/// Control: a real string that spells a float class renders as a bare JSON
/// string, never as the tag object -- the tag is an object, a string is a
/// string, and a consumer can tell them apart by shape alone.
#[test]
fn probe_json_text_nan_is_not_a_tag() {
    let module = array_module(vec![
        Inode::Str("NaN".to_string()),
        Inode::Str("Infinity".to_string()),
        Inode::Str("-Infinity".to_string()),
    ]);
    let value = projected(&module);
    let items = value.as_array().expect("the root is an array");
    for (item, expected) in items.iter().zip(["NaN", "Infinity", "-Infinity"]) {
        assert_eq!(
            item,
            &serde_json::Value::String(expected.to_string()),
            "the string {expected:?} must stay a bare string, got {item}"
        );
    }
}

/// The pretty printer shares `to_serde` with the compact printer, so it
/// must tag non-finite floats the same way -- and emit no `null` for them.
#[test]
fn probe_json_pretty_tags_non_finite_floats() {
    let module = array_module(vec![
        Inode::Float(f64::NAN),
        Inode::Float(f64::NEG_INFINITY),
    ]);
    let pretty = to_redacted_json_pretty(&module).expect("a legal module must project");
    assert!(
        pretty.contains("\"$float\": \"NaN\"") && pretty.contains("\"$float\": \"-Infinity\""),
        "the pretty printer must tag both classes; got {pretty}"
    );
    assert!(
        !pretty.contains("null"),
        "no non-finite float may render as null; got {pretty}"
    );
}
