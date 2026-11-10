//! Regression tests for INF-10: the annotation-subject ordering key
//! (`content_key_with`, `src/canonical.rs`) refuses legal modules — any
//! subtree whose render exceeds 1 MiB (`KEY_BYTES`) or whose depth exceeds
//! 256 (`KEY_DEPTH`) fails `encode()` with `infinity/limit`, although the
//! same subtree encodes fine without the annotation and the wire allows
//! strings to 64 MiB (`Limits::max_string_bytes`) and depth to 4096
//! (`Limits::default().max_depth`, INF-09). So `encode()` is not total
//! over modules `decode()` accepts, and the failure depends on the
//! unrelated choice of annotating a node. The depth asymmetry is sharp:
//! `prepare()` allows 4096 (INF-09) while the key allows 256.
//!
//! Spec clauses (AUDIT-REPORT.md §INF-10, W4-R1-INF-CORE §INF-10,
//! CONFIRMED by W4 probe P-F): a 2 MiB `Str` annotated returns
//! `infinity/limit` while the unannotated module encodes; a 300-deep
//! `Unary` chain annotated returns `infinity/limit` in release (and
//! aborts the process with a stack overflow in debug — INF-15, the
//! recursive `render()`).
//!
//! The fix (audit recommendation): hash large subtrees instead of
//! materialising the full key string, and remove the depth cap for the
//! key — the ordering key keeps its injectivity (up to a Blake3
//! collision, the same assumption the format already makes) while
//! accepting every legal module. The render must also become iterative:
//! a 4096-deep legal chain cannot be rendered recursively in debug.
//!
//! Fail-before note: the two deep-chain legs abort the test process in
//! debug before the fix (INF-15's stack overflow), so they are run
//! separately from the rest of this file — in release for the clean
//! `infinity/limit` refusal, and once in debug to confirm the abort.
//! Every other test in this file fails cleanly pre-fix with
//! `infinity/limit` (or passes pre-fix where marked as a pin).

use active_infinity::{
    decode, encode, validate_canonical, AnnotationKind, BinOp, Constraint, InfinityModule, Inode,
    InterpPart, Limits, NodeId, PatchOp, SchemaFieldSpec, SecretBytes, SemanticTag, TypeSpec, UnOp,
    UnitTag,
};

/// A unary chain of `depth` nodes: the leaf `Int` is depth `depth`, the
/// root `Unary` depth 1. (W4's INF-09 reproduction used this shape, and
/// INF-09's `inf09_depth_tests.rs` has the same builder.)
fn chain(depth: u32) -> InfinityModule {
    assert!(depth >= 1, "a chain needs at least the leaf node");
    let mut module = InfinityModule::new();
    let mut cur = module.push(Inode::Int(1));
    for _ in 1..depth {
        cur = module.push(Inode::Unary {
            op: UnOp::Neg,
            expr: cur,
        });
    }
    module.set_root(Some(cur));
    module
}

/// The chain's root (the outermost `Unary`): annotating it makes the
/// whole chain the annotation subject.
fn chain_root(module: &InfinityModule) -> NodeId {
    module.root().expect("the chain has a root")
}

/// A 2 MiB string: its render is ~2 MiB, past the 1 MiB key ceiling,
/// while the string itself is far inside the 64 MiB wire ceiling.
fn big_string() -> String {
    "x".repeat(2 << 20)
}

/// Assert a module encodes, validates canonical, decodes, and
/// re-encodes to identical bytes (the canonical fixed point).
fn assert_fixed_point(module: &InfinityModule, what: &str) -> Vec<u8> {
    let image = encode(module).unwrap_or_else(|e| panic!("{what}: encode failed: {e}"));
    validate_canonical(&image, Limits::default())
        .unwrap_or_else(|e| panic!("{what}: not canonical: {e}"));
    let decoded = decode(&image).unwrap_or_else(|e| panic!("{what}: decode failed: {e}"));
    let re_encoded = encode(&decoded).unwrap_or_else(|e| panic!("{what}: re-encode failed: {e}"));
    assert_eq!(
        re_encoded, image,
        "{what}: encode/decode must be a fixed point"
    );
    image
}

/// Build two modules holding the same two subjects in opposite push
/// order (so the subjects get opposite arena ids) with the same
/// annotation on each, and assert they encode to identical bytes.
///
/// Push order — not just `annotate` call order — is reversed on purpose:
/// if the two subjects' ordering keys collide, the order falls back to
/// arena id (`break_key_ties`), and opposite arena ids then produce
/// different bytes. Identical bytes therefore prove the keys separate
/// the two subjects by content. (The marathon canonical test only
/// reverses `annotate` order, which leaves the arena ids in place and
/// cannot catch an id fallback.)
fn assert_pair_orders_by_content(
    name: &str,
    make_first: impl Fn(&mut InfinityModule) -> NodeId,
    make_second: impl Fn(&mut InfinityModule) -> NodeId,
) {
    let build = |first_is_a: bool| {
        let mut module = InfinityModule::new();
        let root = module.push(Inode::Int(0));
        module.set_root(Some(root));
        let (a, b) = if first_is_a {
            (make_first(&mut module), make_second(&mut module))
        } else {
            (make_second(&mut module), make_first(&mut module))
        };
        // The same intent on both subjects: the annotation signature must
        // not be what separates them — only the content key may.
        module.annotate(a, AnnotationKind::Intent("probe".into()));
        module.annotate(b, AnnotationKind::Intent("probe".into()));
        module
    };
    let forward =
        encode(&build(true)).unwrap_or_else(|e| panic!("{name}: forward encode failed: {e}"));
    let reversed =
        encode(&build(false)).unwrap_or_else(|e| panic!("{name}: reversed encode failed: {e}"));
    assert_eq!(
        forward, reversed,
        "{name}: subject order must be content-defined, not arena-defined"
    );
    validate_canonical(&forward, Limits::default())
        .unwrap_or_else(|e| panic!("{name}: not canonical: {e}"));
}

/// One over-ceiling subject: a table holding a 2 MiB string, so the
/// subject's render is ~2 MiB whichever aspect the caller varies.
/// Builders push the aspect node first and build the table in one
/// literal (`InfinityModule` has no `nodes_mut`, by design).
fn big_table_with(module: &mut InfinityModule, extra: (String, NodeId)) -> NodeId {
    let big = module.push(Inode::Str(big_string()));
    module.push(Inode::Table {
        fields: vec![("s".into(), big), extra],
    })
}

#[test]
fn a_two_mib_string_annotation_subject_encodes() {
    // W4's P-F reproduction, first arm: a 2 MiB string is legal on the
    // wire (64 MiB ceiling) and encodes fine unannotated, but annotated
    // it is refused with `infinity/limit` ("annotation key bytes").
    let mut unannotated = InfinityModule::new();
    let root = unannotated.push(Inode::Str(big_string()));
    unannotated.set_root(Some(root));
    encode(&unannotated).expect("the same subtree encodes unannotated");

    let mut module = InfinityModule::new();
    let subject = module.push(Inode::Str(big_string()));
    module.set_root(Some(subject));
    module.annotate(subject, AnnotationKind::Intent("note".into()));
    assert_fixed_point(&module, "a 2 MiB annotated string");
}

#[test]
fn a_three_hundred_deep_annotated_chain_encodes() {
    // W4's P-F reproduction, second arm: a 300-deep chain is legal
    // (4096 ceiling) and encodes fine unannotated, but annotated it is
    // refused with `infinity/limit` ("annotation key depth") in release
    // — and aborts the process with a stack overflow in debug (INF-15:
    // the recursive render). This test must run on its own pre-fix.
    let mut module = chain(300);
    let root = chain_root(&module);
    module.annotate(root, AnnotationKind::Intent("note".into()));
    let image = assert_fixed_point(&module, "a 300-deep annotated chain");
    let decoded = decode(&image).expect("decode");
    assert_eq!(decoded.node_count(), 300);
}

#[test]
fn an_annotated_chain_at_the_default_depth_ceiling_encodes() {
    // The ceiling the key must now reach: depth 4096 is the last depth
    // `prepare()` allows (INF-09), so an annotated 4096-deep chain must
    // encode. Its render is ~20 KiB — under the byte ceiling — so this
    // leg pins the depth-cap removal, not the digest.
    let mut module = chain(4096);
    let root = chain_root(&module);
    module.annotate(root, AnnotationKind::Intent("note".into()));
    let image = assert_fixed_point(&module, "a 4096-deep annotated chain");
    let decoded = decode(&image).expect("decode");
    assert_eq!(decoded.node_count(), 4096);
}

#[test]
fn an_annotated_chain_past_the_default_depth_ceiling_is_still_refused() {
    // PIN (passes pre- and post-fix): removing the key's 256 cap moves
    // the depth ceiling to the layer that owns it — `prepare()` /
    // `Limits::default().max_depth` (4096) — it does not remove it.
    // Depth 4097 is the first refusal, with `infinity/depth` naming
    // the default ceiling.
    let mut module = chain(4097);
    let root = chain_root(&module);
    module.annotate(root, AnnotationKind::Intent("note".into()));
    let error = encode(&module).expect_err("depth 4097 must still be refused");
    assert_eq!(error.code(), "infinity/depth", "{error}");
    assert!(
        error.to_string().contains("4096"),
        "the refusal names the default ceiling: {error}"
    );
}

#[test]
fn a_shared_subtree_annotation_subject_encodes_without_expanding_the_share() {
    // A doubling DAG: node i is `Binary(node[i-1], node[i-1])`, so the
    // subject's flat render is ~2^60 bytes from 60 nodes — no render
    // can ever be materialised, hashed or otherwise. The key must be
    // computable from the shared structure (memoised), not from an
    // expansion of it. Pre-fix this is refused with `infinity/limit`
    // after 1 MiB of render; a naive hash-the-render fix would hang
    // here instead of refusing, so this test also proves the fix does
    // not trade a refusal for a hang. Depth 60 stays under the debug
    // stack-overflow threshold (~100–200, INF-15), so the fail-before
    // run of this test returns the clean refusal instead of aborting.
    let mut module = InfinityModule::new();
    let leaf = module.push(Inode::Int(1));
    let mut cur = leaf;
    for _ in 1..60 {
        cur = module.push(Inode::Binary {
            op: BinOp::Add,
            lhs: cur,
            rhs: cur,
        });
    }
    module.set_root(Some(cur));
    module.annotate(cur, AnnotationKind::Intent("note".into()));
    let image = assert_fixed_point(&module, "a doubling-DAG subject");
    let decoded = decode(&image).expect("decode");
    assert_eq!(decoded.node_count(), 60);
}

#[test]
fn over_ceiling_subjects_order_by_content_not_construction() {
    // Two 2 MiB strings differing in one byte: their renders differ,
    // so their keys must differ, and the subject order — hence the
    // bytes — must not depend on which subject was pushed first.
    assert_pair_orders_by_content(
        "one-byte-different 2 MiB strings",
        |module| module.push(Inode::Str(format!("{}y", "x".repeat((2 << 20) - 1)))),
        |module| module.push(Inode::Str(big_string())),
    );
}

#[test]
fn an_annotated_module_with_a_large_subject_is_a_fixed_point() {
    // The hashed key must be a pure function of content: decode and
    // re-encode gives identical bytes, so the order is stable across
    // passes and the image is canonical.
    let mut module = InfinityModule::new();
    let subject = module.push(Inode::Str(big_string()));
    let root = module.push(Inode::Int(0));
    module.set_root(Some(root));
    module.annotate(subject, AnnotationKind::Intent("note".into()));
    assert_fixed_point(&module, "a large annotated subject");
}

#[test]
fn a_large_constraint_expression_encodes() {
    // Constraint expressions go through the same key via the framed
    // render (`annotation_signature` → `content_key_framed`), so a
    // 2 MiB expression must encode too — the finding is not only about
    // subjects.
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(0));
    module.set_root(Some(root));
    let expr = module.push(Inode::Str(big_string()));
    module.annotate(
        root,
        AnnotationKind::Constraint {
            source: "len > 0".into(),
            expr,
        },
    );
    assert_fixed_point(&module, "a 2 MiB constraint expression");
}

#[test]
fn two_large_subjects_with_the_same_content_tie_break_identically() {
    // Two distinct arena nodes with identical 2 MiB content: their
    // keys tie (as they must — the key is content-defined), the framed
    // keys tie, the signatures tie, and the id fallback orders two
    // interchangeable subjects. The image must still be a fixed point.
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(0));
    module.set_root(Some(root));
    let first = module.push(Inode::Str(big_string()));
    let second = module.push(Inode::Str(big_string()));
    module.annotate(first, AnnotationKind::Intent("probe".into()));
    module.annotate(second, AnnotationKind::Intent("probe".into()));
    assert_fixed_point(&module, "two identical large subjects");
}

#[test]
fn a_subject_rendering_exactly_one_mib_uses_the_exact_key() {
    // PIN (passes pre- and post-fix): a `Str` of 1,048,567 bytes
    // renders as 's' + "1048567" + ':' + the bytes = exactly 1,048,576
    // bytes (`KEY_BYTES`). The ceiling is "past the budget is refused",
    // so exactly at it still renders exactly.
    let mut module = InfinityModule::new();
    let subject = module.push(Inode::Str("x".repeat(1_048_567)));
    module.set_root(Some(subject));
    module.annotate(subject, AnnotationKind::Intent("note".into()));
    assert_fixed_point(&module, "a subject rendering exactly 1 MiB");
}

#[test]
fn a_subject_rendering_one_byte_past_one_mib_uses_the_digest() {
    // Boundary: one more byte (1,048,568) renders 1,048,577 bytes — one
    // past `KEY_BYTES` — and pre-fix is refused with
    // `infinity/limit` ("annotation key bytes"). Post-fix it takes the
    // digest path and encodes.
    let mut module = InfinityModule::new();
    let subject = module.push(Inode::Str("x".repeat(1_048_568)));
    module.set_root(Some(subject));
    module.annotate(subject, AnnotationKind::Intent("note".into()));
    assert_fixed_point(&module, "a subject rendering 1 MiB + 1 byte");
}

#[test]
fn a_large_subject_holding_a_secret_encodes_and_keeps_it() {
    // A secret inside an over-ceiling subject: the key renders it as
    // the constant (never the bytes — the same rule as the exact
    // render), the secret survives the round trip, and the image is a
    // fixed point. The digest must not become a new oracle: it folds
    // secrets exactly as the render does (R2-INF-CANON-01's placement
    // blindness is unchanged by this fix and stays that finding's).
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(0));
    module.set_root(Some(root));
    let big = module.push(Inode::Str(big_string()));
    let secret = module.push(Inode::Secret(SecretBytes::from("hunter2-secret")));
    let subject = module.push(Inode::Table {
        fields: vec![("s".into(), big), ("p".into(), secret)],
    });
    module.annotate(subject, AnnotationKind::Intent("note".into()));
    let image = assert_fixed_point(&module, "a large secret-bearing subject");
    let decoded = decode(&image).expect("decode");
    assert_eq!(decoded, module, "the secret survives the round trip");
}

#[test]
fn over_ceiling_subjects_that_differ_in_one_aspect_order_by_content() {
    // The digest must distinguish everything the exact render
    // distinguishes: for each pair below the two subjects differ in
    // exactly one aspect of their content, and the pair is built in
    // opposite push order in the two modules. If the digest omitted
    // that aspect, the keys would tie, the order would fall back to
    // arena id, and the two modules would encode differently.
    //
    // Two pairs differ ONLY in the framed render — the named-unit name
    // and the schema-field slot — so they pin the framed digest as
    // well as the primary one.

    // (a) string content, one byte.
    assert_pair_orders_by_content(
        "string content",
        |module| module.push(Inode::Str(format!("{}y", "x".repeat((2 << 20) - 1)))),
        |module| module.push(Inode::Str(big_string())),
    );
    // (b) int value.
    assert_pair_orders_by_content(
        "int value",
        |module| {
            let value = module.push(Inode::Int(1));
            big_table_with(module, ("a".into(), value))
        },
        |module| {
            let value = module.push(Inode::Int(2));
            big_table_with(module, ("a".into(), value))
        },
    );
    // (c) float bits.
    assert_pair_orders_by_content(
        "float bits",
        |module| {
            let value = module.push(Inode::Float(1.5));
            big_table_with(module, ("a".into(), value))
        },
        |module| {
            let value = module.push(Inode::Float(2.5));
            big_table_with(module, ("a".into(), value))
        },
    );
    // (d) table field name.
    assert_pair_orders_by_content(
        "table field name",
        |module| {
            let value = module.push(Inode::Int(1));
            big_table_with(module, ("a".into(), value))
        },
        |module| {
            let value = module.push(Inode::Int(1));
            big_table_with(module, ("b".into(), value))
        },
    );
    // (e) binary op.
    assert_pair_orders_by_content(
        "binary op",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Binary {
                op: BinOp::Add,
                lhs: big,
                rhs: big,
            })
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Binary {
                op: BinOp::Sub,
                lhs: big,
                rhs: big,
            })
        },
    );
    // (f) unary op.
    assert_pair_orders_by_content(
        "unary op",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Unary {
                op: UnOp::Neg,
                expr: big,
            })
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Unary {
                op: UnOp::Not,
                expr: big,
            })
        },
    );
    // (g) interpolate interleaving: literal-then-expr vs expr-then-literal.
    assert_pair_orders_by_content(
        "interpolate interleaving",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Interpolate {
                parts: vec![InterpPart::Literal("a".into()), InterpPart::Expr(big)],
            })
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Interpolate {
                parts: vec![InterpPart::Expr(big), InterpPart::Literal("a".into())],
            })
        },
    );
    // (h) constraint MinMax bound.
    assert_pair_orders_by_content(
        "constraint MinMax bound",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Constrained {
                target: big,
                constraint: Constraint::MinMax {
                    min: Some(1),
                    max: None,
                },
            })
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Constrained {
                target: big,
                constraint: Constraint::MinMax {
                    min: Some(2),
                    max: None,
                },
            })
        },
    );
    // (i) constraint Enum members.
    assert_pair_orders_by_content(
        "constraint Enum members",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Constrained {
                target: big,
                constraint: Constraint::Enum(vec!["a".into()]),
            })
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Constrained {
                target: big,
                constraint: Constraint::Enum(vec!["b".into()]),
            })
        },
    );
    // (j) constraint Pattern text.
    assert_pair_orders_by_content(
        "constraint Pattern text",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Constrained {
                target: big,
                constraint: Constraint::Pattern("a.*".into()),
            })
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Constrained {
                target: big,
                constraint: Constraint::Pattern("b.*".into()),
            })
        },
    );
    // (k) constraint Custom text.
    assert_pair_orders_by_content(
        "constraint Custom text",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Constrained {
                target: big,
                constraint: Constraint::Custom("x".into()),
            })
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Constrained {
                target: big,
                constraint: Constraint::Custom("y".into()),
            })
        },
    );
    // (l) constraint Odd vs an empty MinMax (different kind, same target).
    assert_pair_orders_by_content(
        "constraint kind",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Constrained {
                target: big,
                constraint: Constraint::Odd,
            })
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Constrained {
                target: big,
                constraint: Constraint::MinMax {
                    min: None,
                    max: None,
                },
            })
        },
    );
    // (m) quantity unit.
    assert_pair_orders_by_content(
        "quantity unit",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Quantity {
                value: big,
                unit: UnitTag::Seconds,
            })
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Quantity {
                value: big,
                unit: UnitTag::Minutes,
            })
        },
    );
    // (n) named-unit name — framed only: every `Named` unit shares one
    // discriminant, so the primary render cannot tell them apart and
    // only the framed key can. This pair pins the framed digest.
    assert_pair_orders_by_content(
        "named-unit name (framed only)",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Quantity {
                value: big,
                unit: UnitTag::Named("alpha".into()),
            })
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Quantity {
                value: big,
                unit: UnitTag::Named("beta".into()),
            })
        },
    );
    // (o) blob hash.
    assert_pair_orders_by_content(
        "blob hash",
        |module| {
            let blob = module.push(Inode::Blob {
                hash: [7u8; 32],
                size: 100,
                tainted: false,
                media_type: "text/plain".into(),
                payload: None,
            });
            big_table_with(module, ("a".into(), blob))
        },
        |module| {
            let blob = module.push(Inode::Blob {
                hash: [8u8; 32],
                size: 100,
                tainted: false,
                media_type: "text/plain".into(),
                payload: None,
            });
            big_table_with(module, ("a".into(), blob))
        },
    );
    // (p) blob media type.
    assert_pair_orders_by_content(
        "blob media type",
        |module| {
            let blob = module.push(Inode::Blob {
                hash: [7u8; 32],
                size: 100,
                tainted: false,
                media_type: "text/plain".into(),
                payload: None,
            });
            big_table_with(module, ("a".into(), blob))
        },
        |module| {
            let blob = module.push(Inode::Blob {
                hash: [7u8; 32],
                size: 100,
                tainted: false,
                media_type: "text/html".into(),
                payload: None,
            });
            big_table_with(module, ("a".into(), blob))
        },
    );
    // (q) blob tainted flag.
    assert_pair_orders_by_content(
        "blob tainted flag",
        |module| {
            let blob = module.push(Inode::Blob {
                hash: [7u8; 32],
                size: 100,
                tainted: false,
                media_type: "text/plain".into(),
                payload: None,
            });
            big_table_with(module, ("a".into(), blob))
        },
        |module| {
            let blob = module.push(Inode::Blob {
                hash: [7u8; 32],
                size: 100,
                tainted: true,
                media_type: "text/plain".into(),
                payload: None,
            });
            big_table_with(module, ("a".into(), blob))
        },
    );
    // (r) schema-field type Enum members.
    assert_pair_orders_by_content(
        "schema-field type Enum members",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            let mut spec = SchemaFieldSpec::bare(TypeSpec::Enum(vec!["a".into()]));
            spec.default = Some(big);
            module.push(Inode::SchemaField(spec))
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            let mut spec = SchemaFieldSpec::bare(TypeSpec::Enum(vec!["b".into()]));
            spec.default = Some(big);
            module.push(Inode::SchemaField(spec))
        },
    );
    // (s) schema-field type Table closed flag.
    assert_pair_orders_by_content(
        "schema-field type Table closed flag",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            let mut spec = SchemaFieldSpec::bare(TypeSpec::Table { closed: true });
            spec.default = Some(big);
            module.push(Inode::SchemaField(spec))
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            let mut spec = SchemaFieldSpec::bare(TypeSpec::Table { closed: false });
            spec.default = Some(big);
            module.push(Inode::SchemaField(spec))
        },
    );
    // (t) schema-field deprecation text.
    assert_pair_orders_by_content(
        "schema-field deprecation text",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            let mut spec = SchemaFieldSpec::bare(TypeSpec::Int);
            spec.default = Some(big);
            spec.deprecated = Some("old".into());
            module.push(Inode::SchemaField(spec))
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            let mut spec = SchemaFieldSpec::bare(TypeSpec::Int);
            spec.default = Some(big);
            spec.deprecated = Some("older".into());
            module.push(Inode::SchemaField(spec))
        },
    );
    // (u) schema-field slot — framed only: the unframed render writes a
    // slot child with no marker, so `min` and `max` holding the same
    // node render identically and only the framed key (slot marker)
    // can tell them apart. This pair pins the framed digest's slot
    // markers.
    assert_pair_orders_by_content(
        "schema-field slot (framed only)",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            let mut spec = SchemaFieldSpec::bare(TypeSpec::Int);
            spec.min = Some(big);
            module.push(Inode::SchemaField(spec))
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            let mut spec = SchemaFieldSpec::bare(TypeSpec::Int);
            spec.max = Some(big);
            module.push(Inode::SchemaField(spec))
        },
    );
    // (v) env name.
    assert_pair_orders_by_content(
        "env name",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Env {
                name: "A".into(),
                default: Some(big),
            })
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Env {
                name: "B".into(),
                default: Some(big),
            })
        },
    );
    // (w) env default presence, with a 2 MiB name so both sides stay
    // over the byte ceiling.
    assert_pair_orders_by_content(
        "env default presence",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Env {
                name: "n".repeat(2 << 20),
                default: Some(big),
            })
        },
        |module| {
            module.push(Inode::Env {
                name: "n".repeat(2 << 20),
                default: None,
            })
        },
    );
    // (x) patch Set path.
    assert_pair_orders_by_content(
        "patch Set path",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Patch(PatchOp::Set {
                path: "a".into(),
                value: big,
            }))
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Patch(PatchOp::Set {
                path: "b".into(),
                value: big,
            }))
        },
    );
    // (y) patch Rename target, with a 2 MiB source path so both sides
    // stay over the byte ceiling.
    assert_pair_orders_by_content(
        "patch Rename target",
        |module| {
            module.push(Inode::Patch(PatchOp::Rename {
                from: "f".repeat(2 << 20),
                to: "b".into(),
            }))
        },
        |module| {
            module.push(Inode::Patch(PatchOp::Rename {
                from: "f".repeat(2 << 20),
                to: "c".into(),
            }))
        },
    );
    // (z) semantic tag.
    assert_pair_orders_by_content(
        "semantic tag",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Semantic {
                tag: SemanticTag::Prompt,
                inner: big,
            })
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Semantic {
                tag: SemanticTag::Policy,
                inner: big,
            })
        },
    );
    // (aa) schema-table closed flag.
    assert_pair_orders_by_content(
        "schema-table closed flag",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::SchemaTable {
                fields: vec![("s".into(), big)],
                closed: true,
            })
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::SchemaTable {
                fields: vec![("s".into(), big)],
                closed: false,
            })
        },
    );
    // (ab) schema-table field name.
    assert_pair_orders_by_content(
        "schema-table field name",
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::SchemaTable {
                fields: vec![("s".into(), big)],
                closed: false,
            })
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::SchemaTable {
                fields: vec![("t".into(), big)],
                closed: false,
            })
        },
    );
    // (ac) duration value.
    assert_pair_orders_by_content(
        "duration value",
        |module| {
            let value = module.push(Inode::DurationMs(1));
            big_table_with(module, ("a".into(), value))
        },
        |module| {
            let value = module.push(Inode::DurationMs(2));
            big_table_with(module, ("a".into(), value))
        },
    );
    // (ad) bool value.
    assert_pair_orders_by_content(
        "bool value",
        |module| {
            let value = module.push(Inode::Bool(true));
            big_table_with(module, ("a".into(), value))
        },
        |module| {
            let value = module.push(Inode::Bool(false));
            big_table_with(module, ("a".into(), value))
        },
    );
    // (ae) ref target content.
    assert_pair_orders_by_content(
        "ref target content",
        |module| {
            let big = module.push(Inode::Str(format!("{}y", "x".repeat((2 << 20) - 1))));
            module.push(Inode::Ref(big))
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Ref(big))
        },
    );
    // (af) secret-ref locator content.
    assert_pair_orders_by_content(
        "secret-ref locator content",
        |module| {
            let big = module.push(Inode::Str(format!("{}y", "x".repeat((2 << 20) - 1))));
            module.push(Inode::SecretRef { locator: big })
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::SecretRef { locator: big })
        },
    );
    // (ag) content-addressed data content.
    assert_pair_orders_by_content(
        "content-addressed data content",
        |module| {
            let media = module.push(Inode::Str("text/plain".into()));
            let big = module.push(Inode::Str(format!("{}y", "x".repeat((2 << 20) - 1))));
            module.push(Inode::ContentAddressed {
                media_type: media,
                data: big,
            })
        },
        |module| {
            let media = module.push(Inode::Str("text/plain".into()));
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::ContentAddressed {
                media_type: media,
                data: big,
            })
        },
    );
    // (ah) quantity value content.
    assert_pair_orders_by_content(
        "quantity value content",
        |module| {
            let big = module.push(Inode::Str(format!("{}y", "x".repeat((2 << 20) - 1))));
            module.push(Inode::Quantity {
                value: big,
                unit: UnitTag::Seconds,
            })
        },
        |module| {
            let big = module.push(Inode::Str(big_string()));
            module.push(Inode::Quantity {
                value: big,
                unit: UnitTag::Seconds,
            })
        },
    );
}
