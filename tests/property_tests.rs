//! Property tests: generated modules must round-trip, canonicalize
//! deterministically, hash sensitively and reject arbitrary bytes without
//! panicking.
//!
//! `proptest` reports the number of cases it ran; the tests also assert that the
//! generators produced non-trivial modules so a green run means something.

use std::collections::BTreeMap;

use active_infinity::{
    decode, encode, validate, AnnotationKind, Constraint, DecodeOpts, InfinityModule, Inode,
    InterpPart, Limits, SerializedKind, UnitTag,
};
use proptest::prelude::*;

/// A small, node-free description of a value that the generator can compose.
#[derive(Debug, Clone)]
enum Spec {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Quantity(f64, UnitTag),
    Array(Vec<Spec>),
    Table(BTreeMap<String, Spec>),
}

fn unit_strategy() -> impl Strategy<Value = UnitTag> {
    prop_oneof![
        Just(UnitTag::Milliseconds),
        Just(UnitTag::Bytes),
        Just(UnitTag::TokensPerSecond),
        Just(UnitTag::Percent),
        Just(UnitTag::Named("widgets".to_string())),
    ]
}

fn spec_strategy() -> impl Strategy<Value = Spec> {
    let leaf = prop_oneof![
        Just(Spec::Null),
        any::<bool>().prop_map(Spec::Bool),
        any::<i64>().prop_map(Spec::Int),
        (-1_000_000.0f64..1_000_000.0).prop_map(Spec::Float),
        "[a-zA-Z0-9_.:/-]{0,24}".prop_map(Spec::Str),
        (any::<f64>(), unit_strategy()).prop_map(|(value, unit)| Spec::Quantity(value, unit)),
    ];
    leaf.prop_recursive(3, 32, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Spec::Array),
            prop::collection::btree_map("[a-z][a-z0-9_]{0,8}", inner, 0..4).prop_map(Spec::Table),
        ]
    })
}

fn build(module: &mut InfinityModule, spec: &Spec) -> active_infinity::NodeId {
    match spec {
        Spec::Null => module.push(Inode::Null),
        Spec::Bool(flag) => module.push(Inode::Bool(*flag)),
        Spec::Int(number) => module.push(Inode::Int(*number)),
        Spec::Float(number) => module.push(Inode::Float(*number)),
        Spec::Str(text) => module.push(Inode::Str(text.clone())),
        Spec::Quantity(amount, unit) => {
            let value = module.push(Inode::Float(*amount));
            module.push(Inode::Quantity {
                value,
                unit: unit.clone(),
            })
        }
        Spec::Array(items) => {
            let elements = items.iter().map(|item| build(module, item)).collect();
            module.push(Inode::Array { elements })
        }
        Spec::Table(entries) => {
            let fields = entries
                .iter()
                .map(|(name, value)| (name.clone(), build(module, value)))
                .collect();
            module.push(Inode::Table { fields })
        }
    }
}

fn module_from(spec: &Spec) -> InfinityModule {
    let mut module = InfinityModule::new();
    let root = build(&mut module, spec);
    module.set_root(Some(root));
    module.bind("root", root);
    module
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn round_trip_and_canonical_stability(spec in spec_strategy()) {
        let module = module_from(&spec);
        let bytes = encode(&module).expect("encode");
        let decoded = decode(&bytes).expect("decode");
        prop_assert_eq!(&decoded, &module);
        prop_assert_eq!(encode(&decoded).expect("re-encode"), bytes.clone());
        // Rebuilding the same logical value produces the same bytes.
        let rebuilt = module_from(&spec);
        prop_assert_eq!(encode(&rebuilt).expect("rebuild"), bytes);
    }

    #[test]
    fn hash_changes_when_a_value_changes(spec in spec_strategy(), delta in 1i64..1000) {
        let module = module_from(&spec);
        let bytes = encode(&module).expect("encode");
        let mut changed = module.clone();
        let marker = changed.push(Inode::Int(delta));
        let root = changed.root().expect("root");
        // Wrap the root in a table with an added key: always a real change.
        let wrapper = changed.push(Inode::Table {
            fields: vec![
                ("original".to_string(), root),
                ("marker".to_string(), marker),
            ],
        });
        changed.set_root(Some(wrapper));
        let changed_bytes = encode(&changed).expect("encode");
        prop_assert_ne!(changed_bytes, bytes);
    }

    #[test]
    fn arbitrary_bytes_are_rejected_without_panicking(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        // No panic, and the only accepted inputs are complete valid images
        // (essentially never for random bytes).
        match validate(&bytes) {
            Ok(_) => prop_assert!(decode(&bytes).is_ok()),
            Err(error) => prop_assert!(!error.code().is_empty()),
        }
    }

    #[test]
    fn byte_flips_are_always_rejected(spec in spec_strategy(), positions in prop::collection::vec(0usize..64, 1..4)) {
        let bytes = encode(&module_from(&spec)).expect("encode");
        for position in positions {
            let index = position % bytes.len();
            let mut mutated = bytes.clone();
            mutated[index] ^= 0x5a;
            prop_assert!(validate(&mutated).is_err(), "flip at {} accepted", index);
        }
    }
}

#[test]
fn generators_produce_real_modules() {
    // Guard against a vacuous property suite: a hand-built module exercises the
    // same paths and must be non-trivial.
    let mut module = InfinityModule::new();
    let text = module.push(Inode::Str("x".into()));
    let number = module.push(Inode::Int(1));
    let value = module.push(Inode::Quantity {
        value: number,
        unit: UnitTag::Named("widgets".into()),
    });
    let array = module.push(Inode::Array {
        elements: vec![text, value],
    });
    let constraint = module.push(Inode::Constrained {
        target: number,
        constraint: Constraint::Enum(vec!["a".into()]),
    });
    let interpolate = module.push(Inode::Interpolate {
        parts: vec![InterpPart::Literal("v=".into()), InterpPart::Expr(number)],
    });
    let root = module.push(Inode::Table {
        fields: vec![
            ("array".into(), array),
            ("constraint".into(), constraint),
            ("interpolate".into(), interpolate),
        ],
    });
    module.set_root(Some(root));
    module.annotate(root, AnnotationKind::Intent("property fixture".into()));
    let bytes = encode(&module).unwrap();
    assert!(bytes.len() > 512);
    assert!(decode(&bytes).is_ok());
    assert_eq!(
        active_infinity::validate_with(
            &bytes,
            DecodeOpts {
                limits: Limits::strict(),
                verify_hash: true,
                verify_canonical: true,
            }
        )
        .unwrap()
        .nodes,
        module.node_count() as u32
    );
}

/// The public `SerializedKind` helper exists so downstream tools can name a
/// kind without depending on the wire ids.
#[test]
fn serialized_kind_names_are_stable() {
    assert_eq!(
        SerializedKind::Table.code(),
        Inode::Table { fields: vec![] }.kind_code()
    );
    assert_eq!(SerializedKind::Secret.name(), "Secret");
}
