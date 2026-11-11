//! Regression tests for INF-L01: `decode.rs` casts/loops relied entirely on
//! the `Validated` invariant, with no local defence-in-depth.
//!
//! Audit (`AUDIT-REPORT.md:785`, at 6aad041): no local range check before any
//! `as u32` cast or `rec.a..rec.a+rec.b` loop; a future `Validated`
//! constructor or a validator regression silently turns these into
//! truncation/panic (`Vec::with_capacity(rec.b as usize)` with `rec.b` up to
//! 2^64-1 would attempt a huge allocation / abort before any bounds check).
//! W4 confirmed it by code-read: safe *conditional* on the invariant, with
//! no local defence if the invariant ever breaks.
//!
//! The fix (record `records/F2-INF/INF-L01.md`):
//!
//! - Every `rec.a` / `rec.b` / `rec.c` `u64 -> u32` conversion in
//!   `decode.rs` goes through `node_u32` (`u32::try_from`, `Error::Node` on
//!   overflow); every `start..start+len` range goes through `node_range_end`
//!   / `type_range_end` (`checked_add`, `Error::Node` / `Error::Type` on
//!   overflow); every `Vec::with_capacity(rec.b as usize)` hint goes
//!   through `capacity_hint`, capped at the size of the table the range
//!   draws from (children / fields / parts), so a validator regression can
//!   no longer abort on capacity overflow before any bounds check runs.
//! - `rec.a as i64` (kind 2, `Int`) is left alone: it is a bit-preserving
//!   reinterpretation, not a truncating cast. `u32 -> usize` / `u32 -> u64`
//!   widening casts are left alone: they cannot truncate on any target.
//!
//! Why there is no public-path fail-before probe: a broken `Validated`
//! cannot be built through any public API -- its fields are private and
//! `new()` is the only constructor -- so no crafted image can reach the
//! new checks. The fail-before evidence is the mechanism probe
//! (`inf_l01_failbefore.log`: the old `as u32` truncation is silent, the
//! old release `start+len` wraps, the old `with_capacity(u64::MAX)`
//! aborts), and the pass-after evidence is the unit tests in `src/decode.rs`
//! proving each helper rejects exactly those inputs. The tests below pin
//! the other half: behaviour on every changed arm is unchanged, through
//! both `decode` and the `Validated` + `decode_validated` entry point.

use active_infinity::decode::decode_validated;
use active_infinity::ir::{
    BinOp, Constraint, InterpPart, PatchOp, SchemaFieldSpec, SecretBytes, SemanticTag, TypeSpec,
    UnOp,
};
use active_infinity::layout::DecodeOpts;
use active_infinity::{decode, encode, InfinityModule, Inode, NodeId, UnitTag, Validated};

/// A module exercising every `decode_node` / `decode_constraint` /
/// `decode_patch` / `decode_schema_field` / `decode_type` arm the INF-L01
/// fix touched, plus the `check_decoded_budget` pre-pass that runs first.
/// No `Secret` / `Blob` node here: module equality treats them specially
/// (see `inf_l01_blob_and_secret_round_trip`), so they get their own test.
fn kitchen_sink_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let int1 = module.push(Inode::Int(1));
    let int2 = module.push(Inode::Int(-42));
    let float = module.push(Inode::Float(1.5));
    let text = module.push(Inode::Str("hello".to_string()));
    let boolean = module.push(Inode::Bool(true));
    let null = module.push(Inode::Null);
    let duration = module.push(Inode::DurationMs(1234));
    let quantity = module.push(Inode::Quantity {
        value: int1,
        unit: UnitTag::Named("furlong".to_string()),
    });
    let seconds = module.push(Inode::Quantity {
        value: int2,
        unit: UnitTag::Seconds,
    });
    let array = module.push(Inode::Array {
        elements: vec![int1, int2, float, text, boolean, null],
    });
    let table = module.push(Inode::Table {
        fields: vec![
            ("a".to_string(), int1),
            ("b".to_string(), text),
            ("c".to_string(), array),
        ],
    });
    let interpolate = module.push(Inode::Interpolate {
        parts: vec![
            InterpPart::Literal("x=".to_string()),
            InterpPart::Expr(int1),
            InterpPart::Literal("!".to_string()),
        ],
    });
    let env_default = module.push(Inode::Env {
        name: "HOME".to_string(),
        default: Some(text),
    });
    let env_no_default = module.push(Inode::Env {
        name: "MISSING".to_string(),
        default: None,
    });
    let secret_ref = module.push(Inode::SecretRef { locator: int1 });
    let reference = module.push(Inode::Ref(int1));
    let binary = module.push(Inode::Binary {
        op: BinOp::Add,
        lhs: int1,
        rhs: int2,
    });
    let unary = module.push(Inode::Unary {
        op: UnOp::Neg,
        expr: int1,
    });
    let semantic = module.push(Inode::Semantic {
        tag: SemanticTag::Prompt,
        inner: text,
    });
    let content = module.push(Inode::ContentAddressed {
        media_type: text,
        data: int1,
    });
    let mut constrained = Vec::new();
    for constraint in [
        Constraint::MinMax {
            min: Some(-5),
            max: Some(100),
        },
        Constraint::Enum(vec!["a".to_string(), "b".to_string()]),
        Constraint::Pattern("^[a-z]+$".to_string()),
        Constraint::Odd,
        Constraint::Custom("custom-payload".to_string()),
    ] {
        constrained.push(module.push(Inode::Constrained {
            target: int1,
            constraint,
        }));
    }
    let mut patches = Vec::new();
    for op in [
        PatchOp::Set {
            path: "a.b".to_string(),
            value: int1,
        },
        PatchOp::Remove {
            path: "a".to_string(),
        },
        PatchOp::Rename {
            from: "a".to_string(),
            to: "b".to_string(),
        },
    ] {
        patches.push(module.push(Inode::Patch(op)));
    }
    let mut spec = SchemaFieldSpec::bare(TypeSpec::Enum(vec!["a".to_string(), "b".to_string()]));
    spec.min = Some(int1);
    spec.max = Some(int2);
    spec.min_len = Some(int1);
    spec.max_len = Some(int2);
    spec.pattern = Some(text);
    spec.default = Some(int1);
    spec.deprecated = Some("use the new field".to_string());
    let schema_field = module.push(Inode::SchemaField(spec));
    let schema_table = module.push(Inode::SchemaTable {
        fields: vec![("x".to_string(), int1), ("y".to_string(), text)],
        closed: true,
    });
    let schema_array = module.push(Inode::SchemaArray { element: int1 });
    let mut elements = vec![
        quantity,
        seconds,
        array,
        table,
        interpolate,
        env_default,
        env_no_default,
        secret_ref,
        reference,
        binary,
        unary,
        semantic,
        content,
        schema_field,
        schema_table,
        schema_array,
        duration,
    ];
    elements.extend(constrained);
    elements.extend(patches);
    let root = module.push(Inode::Array { elements });
    module.set_root(Some(root));
    module
}

#[test]
fn inf_l01_kitchen_sink_round_trip() {
    let module = kitchen_sink_module();
    let image = encode(&module).expect("encode kitchen-sink module");
    let decoded = decode(&image).expect("decode kitchen-sink module");
    assert_eq!(
        decoded, module,
        "decode must be unchanged by the checked casts"
    );
}

#[test]
fn inf_l01_decode_validated_path_agrees() {
    let module = kitchen_sink_module();
    let image = encode(&module).expect("encode kitchen-sink module");
    let validated =
        Validated::new(&image, DecodeOpts::default()).expect("validate kitchen-sink image");
    let via_validated = decode_validated(&validated).expect("decode_validated");
    let via_decode = decode(&image).expect("decode");
    assert_eq!(via_validated, via_decode);
    assert_eq!(via_validated, module);
}

#[test]
fn inf_l01_blob_and_secret_round_trip() {
    let payload = vec![0xABu8; 1024];
    let hash = *blake3::hash(&payload).as_bytes();
    let mut module = InfinityModule::new();
    let blob = module.push(Inode::Blob {
        hash,
        size: payload.len() as u64,
        tainted: false,
        media_type: "application/octet-stream".to_string(),
        payload: Some(payload.clone()),
    });
    let secret = module.push(Inode::Secret(SecretBytes::new(b"top-secret".to_vec())));
    let root = module.push(Inode::Array {
        elements: vec![blob, secret],
    });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode blob/secret module");
    let decoded = decode(&image).expect("decode blob/secret module");
    assert!(decoded.has_secret(), "the secret node must survive decode");
    let mut saw_blob = false;
    for node in decoded.nodes() {
        if let Inode::Blob {
            hash: got_hash,
            size,
            payload: got_payload,
            ..
        } = node
        {
            assert_eq!(*got_hash, hash);
            assert_eq!(*size, payload.len() as u64);
            assert_eq!(got_payload.as_deref(), Some(payload.as_slice()));
            saw_blob = true;
        }
    }
    assert!(saw_blob, "the blob node must survive decode");
}

#[test]
fn inf_l01_wide_table_round_trip() {
    // Wide-but-legal ranges: the capacity cap must never truncate a real
    // table (300 fields / 300 elements / 100 parts, all far below the
    // section counts the cap is drawn from).
    let mut module = InfinityModule::new();
    let mut fields: Vec<(String, NodeId)> = Vec::with_capacity(300);
    let mut elements = Vec::with_capacity(300);
    for i in 0..300 {
        let id = module.push(Inode::Int(i));
        fields.push((format!("f{i:03}"), id));
        elements.push(id);
    }
    let table = module.push(Inode::Table { fields });
    let array = module.push(Inode::Array { elements });
    let mut parts = Vec::with_capacity(100);
    for i in 0..100 {
        parts.push(InterpPart::Literal(format!("p{i}")));
    }
    let interpolate = module.push(Inode::Interpolate { parts });
    let root = module.push(Inode::Array {
        elements: vec![table, array, interpolate],
    });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode wide-table module");
    let decoded = decode(&image).expect("decode wide-table module");
    assert_eq!(decoded, module);
    let mut saw_table = false;
    let mut saw_array = false;
    for node in decoded.nodes() {
        match node {
            Inode::Table { fields } if fields.len() == 300 => saw_table = true,
            Inode::Array { elements } if elements.len() == 300 => saw_array = true,
            _ => {}
        }
    }
    assert!(saw_table, "the 300-field table must decode whole");
    assert!(saw_array, "the 300-element array must decode whole");
}
