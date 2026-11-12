//! Property tests: generated modules must round-trip, canonicalize
//! deterministically, hash sensitively and reject arbitrary bytes without
//! panicking.
//!
//! `proptest` reports the number of cases it ran; the tests also assert that the
//! generators produced non-trivial modules so a green run means something.

use std::collections::{BTreeMap, HashSet};

use active_infinity::{
    decode, encode, validate, AnnotationKind, Constraint, DecodeOpts, InfinityModule, Inode,
    InterpPart, Limits, NodeId, SerializedKind, UnitTag,
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

/// Collect, in depth-first encounter order, the ordered field-name vector of
/// every table in the module reachable from its root.
///
/// This is the assertion TEST-13 needs. `InfinityModule::eq` is canonical
/// structural equality, so it cannot see field order, and `encode` re-sorts
/// table fields before writing them: a decoded module with every table's
/// fields reversed still compares equal and still re-encodes to the same
/// bytes. The ordered vectors collected here are the only check in this file
/// that can see decoded field order. `SchemaTable` is collected the same way:
/// `decode` materialises its fields in wire order too, so the same blindness
/// would apply to it even though the generator below never builds one.
/// The `seen` set keeps the walk total on a shared (DAG) node instead of
/// revisiting it; both modules share the same structure, so encounter order
/// still matches between them.
fn ordered_table_fields(module: &InfinityModule) -> Vec<Vec<String>> {
    fn walk(
        module: &InfinityModule,
        id: NodeId,
        seen: &mut HashSet<NodeId>,
        out: &mut Vec<Vec<String>>,
    ) {
        if !seen.insert(id) {
            return;
        }
        let Some(node) = module.get(id) else {
            return;
        };
        match node {
            Inode::Table { fields } | Inode::SchemaTable { fields, .. } => {
                out.push(fields.iter().map(|(name, _)| name.clone()).collect());
                for (_, child) in fields {
                    walk(module, *child, seen, out);
                }
            }
            other => {
                for child in other.children() {
                    walk(module, child, seen, out);
                }
            }
        }
    }

    let mut out = Vec::new();
    if let Some(root) = module.root() {
        walk(module, root, &mut HashSet::new(), &mut out);
    }
    out
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
        // TEST-13: the three assertions above are all order-blind — `==`
        // is canonical structural equality and `encode` re-sorts table
        // fields — so they pass even with every decoded table's fields
        // reversed (mutation M09). Compare the materialised field-name
        // vectors in order instead: that is the property the mutation
        // breaks. The generator builds tables from a `BTreeMap`, so the
        // original order is sorted and the decoded order must match it
        // exactly, nested tables included.
        prop_assert_eq!(
            ordered_table_fields(&decoded),
            ordered_table_fields(&module)
        );
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

/// TEST-13 pin: decode materialises table fields in wire order, and the
/// ordered comparison in `round_trip_and_canonical_stability` really sees
/// that order. A hand-built module whose root table is inserted in
/// non-sorted order (`b` before `a`) encodes to the canonical (sorted)
/// image, so the decoded root table must read `["a", "b"]` — and the nested
/// table `["c", "d"]`. If `ordered_table_fields` ever returned empty
/// vectors, this test would fail: the expected vectors are non-empty.
/// A non-sorted insertion order cannot be asserted through strict `decode`
/// itself — the canonical proof re-encodes and rejects any non-canonical
/// image — so sorted order is the strongest case the strict path admits.
#[test]
fn decoded_table_fields_keep_wire_order_sorted() {
    let mut module = InfinityModule::new();
    let inner_int = module.push(Inode::Int(1));
    let inner_str = module.push(Inode::Str("x".into()));
    let nested = module.push(Inode::Table {
        fields: vec![("d".to_string(), inner_str), ("c".to_string(), inner_int)],
    });
    let outer_int = module.push(Inode::Int(2));
    let root = module.push(Inode::Table {
        fields: vec![("b".to_string(), nested), ("a".to_string(), outer_int)],
    });
    module.set_root(Some(root));
    let bytes = encode(&module).expect("encode");
    let decoded = decode(&bytes).expect("decode");
    assert_eq!(
        ordered_table_fields(&decoded),
        vec![
            vec!["a".to_string(), "b".to_string()],
            vec!["c".to_string(), "d".to_string()],
        ]
    );
    // The collector reports the original's insertion order, not a sorted
    // view of it: if it sorted, this would read `["a", "b"]` / `["c", "d"]`.
    assert_eq!(
        ordered_table_fields(&module),
        vec![
            vec!["b".to_string(), "a".to_string()],
            vec!["d".to_string(), "c".to_string()],
        ]
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

/// Redaction is a fixpoint for every secret set, and it never leaves a secret
/// behind unless that secret is itself part of the marker (in which case the text
/// collapses to the marker).
#[test]
fn redaction_is_a_fixpoint_for_arbitrary_secrets_and_texts() {
    let text = "[a-zA-Z0-9 *]{0,24}";
    let secret = "[a-zA-Z0-9*]{0,5}";
    proptest!(|(text in text, secrets in prop::collection::vec(secret, 0..4))| {
        let once = active_infinity::interop::redact_text(&text, &secrets);
        let twice = active_infinity::interop::redact_text(&once, &secrets);
        prop_assert_eq!(&once, &twice, "redaction must be a fixpoint");

        let marker = active_infinity::interop::SECRET_MARKER;
        let marker_tainted = secrets
            .iter()
            .any(|secret| !secret.is_empty() && marker.contains(secret.as_str()));
        if !marker_tainted {
            for secret in &secrets {
                if secret.is_empty() {
                    continue;
                }
                prop_assert!(
                    !once.contains(secret.as_str()),
                    "a clean-marker redaction left {secret:?} in {once:?}"
                );
            }
        }
    });
}

/// Canonicalization is a fixpoint for modules that embed secrets in metadata,
/// including short secrets and secrets that are part of the marker.
#[test]
fn canonicalization_is_a_fixpoint_for_secret_metadata() {
    proptest!(|(secret in "[a-zA-Z*]{1,6}", note in "[ -~]{0,24}", key in "[ -~]{0,16}")| {
        let mut module = InfinityModule::new();
        let root = module.push(Inode::Int(1));
        module.set_root(Some(root));
        let secret_node = module.push(Inode::Secret(active_infinity::SecretBytes::from(secret.as_str())));
        module.bind("secret", secret_node);
        module.annotate(root, AnnotationKind::Intent(note.clone()));
        module.set_provenance(Some(active_infinity::Provenance {
            producer: if key.is_empty() { None } else { Some(key.clone()) },
            entries: vec![active_infinity::ProvEntry {
                key: key.clone(),
                value: active_infinity::ProvValue::Text(note.clone()),
            }],
            ..active_infinity::Provenance::default()
        }));

        // A secret that is a substring of the marker cannot be represented in
        // redacted text: the encode refuses rather than publishing it. For every
        // other module the canonical form is still a fixpoint.
        let first = match encode(&module) {
            Ok(image) => image,
            Err(error) => {
                prop_assert_eq!(error.code(), "infinity/encode");
                prop_assert!(
                    secret.contains('*')
                        || "***SECRET***".contains(secret.as_str()),
                    "only a marker collision may refuse: {secret:?}"
                );
                return Ok(());
            }
        };
        let second = encode(&decode(&first).unwrap()).unwrap();
        prop_assert!(
            !"***SECRET***".contains(secret.as_str()) || !note.contains(secret.as_str()),
            "a marker-colliding secret reached redacted text"
        );
        prop_assert_eq!(first, second, "canonical form must be a fixpoint");
    });
}
