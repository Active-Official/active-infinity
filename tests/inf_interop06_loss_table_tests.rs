//! Regression tests for INF-INTEROP-06: lossy projections, by design but
//! undocumented in one place.
//!
//! The audit (`AUDIT-REPORT.md`, at 6aad041) found that `to_active_core`
//! drops provenance and extensions entirely, `build_projected` renders `Env`
//! as name-only (the default is dropped), and `Binary` / `Unary` /
//! `Constrained` / `Patch` / `SchemaField` / `SchemaTable` / `SchemaArray` /
//! `ContentAddressed` collapse to `Expr(kind-name)` -- and that none of it
//! was documented in one place. W4 confirmed the `Env` loss with
//! `w4_interop06_lossy` (`logs/log-w4-verify-final3.txt`): the redacted JSON
//! of an Env-with-default was `{"$env":"HOME"}`, the default silently gone.
//!
//! Design decisions (recorded in `records/F2-INF/INF-INTEROP-06.md`):
//!
//! - Both parts of the fix land: the full loss table is documented in the
//!   `to_redacted_json` rustdoc (the canonical copy; `to_protobuf` and
//!   `to_active_core` point at it), AND the `Env` default is projected. The
//!   default is the one loss that silently changes semantics -- an unset env
//!   var falls back to the default, and the projection hid that.
//! - The default is a nested projected value, not a string:
//!   `{"$env": name, "default": <projected>}`, so a string default stays a
//!   JSON string, an integer stays a number, and an operator default
//!   collapses to its `$expr` tag. Env-without-default renders exactly as
//!   before (`{"$env": name}`); only Env-with-default gains the field.
//! - A default CAN be secret: `Inode::Env.default` is an arbitrary `NodeId`
//!   with no kind check (`decode.rs` accepts any node id as the default),
//!   and the suite itself builds one (`marathon_redaction_tests.rs`
//!   pushes an `Env` whose default is a `Secret` node). The default is
//!   therefore projected through the same recursive `build_projected` call
//!   as every other node, so the full redaction applies -- a secret default
//!   renders as the marker, never as plaintext. The tests below pin that.
//! - The same default travels in Protobuf as additive field 2 of `message
//!   Env` (`Value default = 2`, omitted when absent); the independent wire
//!   reader in `tests/protobuf_tests.rs` checks it there.
//! - No in-repo consumer parses `$env` markers back (only the renderer and
//!   its comments reference `$env`), so the new field needs no round-trip
//!   parser; a future parser can recognize `{"$env": ..., "default": ...}`
//!   exactly.

#![cfg(feature = "json")]

use active_infinity::interop::{
    from_active_core, to_active_core, to_redacted_json, to_redacted_json_pretty, SECRET_MARKER,
};
use active_infinity::{
    AnnotationKind, BinOp, Constraint, InfinityModule, Inode, PatchOp, ProvEntry, ProvValue,
    Provenance, SchemaFieldSpec, SecretBytes, SemanticTag, TypeSpec, UnOp, UnitTag,
};

/// A module whose root is an `Env` node with the given name and default.
fn env_module(name: &str, default: Option<Inode>) -> InfinityModule {
    let mut module = InfinityModule::new();
    let default = default.map(|node| module.push(node));
    let env = module.push(Inode::Env {
        name: name.to_string(),
        default,
    });
    module.set_root(Some(env));
    module
}

/// Parse the redacted JSON projection and hand back its JSON value.
fn projected(module: &InfinityModule) -> serde_json::Value {
    let json = to_redacted_json(module).expect("a legal module must project");
    serde_json::from_str(&json).expect("the projection must be valid JSON")
}

/// The W4 reproduction, shape and all: an Env without a default renders
/// exactly as it always has -- `{"$env":"HOME"}` -- one key, no `default`.
#[test]
fn env_without_default_renders_name_only() {
    let module = env_module("HOME", None);
    assert_eq!(
        to_redacted_json(&module).expect("a legal module must project"),
        "{\"$env\":\"HOME\"}",
        "Env-without-default must keep rendering exactly as today"
    );
}

/// The W4 shape, fixed: an Env whose default is a string renders the
/// default as a nested projected value -- `{"$env": name, "default": ...}`.
#[test]
fn env_with_string_default_renders_default() {
    let module = env_module("HOME", Some(Inode::Str("/home/dave".into())));
    assert_eq!(
        projected(&module),
        serde_json::json!({ "$env": "HOME", "default": "/home/dave" }),
        "the Env default must survive the projection"
    );
}

/// The default is a nested projected value, not a string: an integer
/// default stays a JSON number.
#[test]
fn env_with_int_default_renders_nested_value() {
    let module = env_module("PORT", Some(Inode::Int(8080)));
    assert_eq!(
        projected(&module),
        serde_json::json!({ "$env": "PORT", "default": 8080 }),
        "the default must project as a value, not stringify"
    );
}

/// A default CAN be secret (an arbitrary node id: `decode.rs` accepts any
/// node as the default, and the suite itself builds an Env whose default
/// is a `Secret`). The projection must redact it, never render it.
#[test]
fn env_with_secret_default_redacts_to_marker() {
    const SECRET: &str = "env-default-secret-canary";
    let module = env_module("TOKEN", Some(Inode::Secret(SecretBytes::from(SECRET))));
    let json = to_redacted_json(&module).expect("a legal module must project");
    assert!(
        !json.contains(SECRET),
        "a secret default must never reach the projection: {json}"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).expect("valid JSON"),
        serde_json::json!({ "$env": "TOKEN", "default": SECRET_MARKER }),
        "a secret default must project as the marker"
    );
}

/// Same rule through a `SecretRef`: the default's locator is a plain
/// string node, the reference itself is secret, and the projection must
/// show the marker -- without leaking the locator's text either (the
/// `SecretRef` arm projects the placeholder, it never projects the
/// locator).
#[test]
fn env_with_secret_ref_default_redacts_to_marker() {
    const LOCATOR: &str = "locator-canary";
    let mut module = InfinityModule::new();
    let locator = module.push(Inode::Str(LOCATOR.into()));
    let secret_ref = module.push(Inode::SecretRef { locator });
    let env = module.push(Inode::Env {
        name: "TOKEN".to_string(),
        default: Some(secret_ref),
    });
    module.set_root(Some(env));
    let json = to_redacted_json(&module).expect("a legal module must project");
    assert!(
        !json.contains(LOCATOR),
        "a SecretRef default must not leak its locator: {json}"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).expect("valid JSON"),
        serde_json::json!({ "$env": "TOKEN", "default": SECRET_MARKER }),
        "a SecretRef default must project as the marker"
    );
}

/// The default projects recursively: an operator default collapses to its
/// kind tag, exactly as it would at the root.
#[test]
fn env_with_expr_default_collapses_to_kind_name() {
    let mut module = InfinityModule::new();
    let one = module.push(Inode::Int(1));
    let two = module.push(Inode::Int(2));
    let binary = module.push(Inode::Binary {
        op: BinOp::Add,
        lhs: one,
        rhs: two,
    });
    let env = module.push(Inode::Env {
        name: "FACTOR".to_string(),
        default: Some(binary),
    });
    module.set_root(Some(env));
    assert_eq!(
        projected(&module),
        serde_json::json!({ "$env": "FACTOR", "default": { "$expr": "Binary" } }),
        "an operator default must collapse like an operator root"
    );
}

/// A composite default projects nested: a quantity default keeps its
/// value and its unit name.
#[test]
fn env_with_quantity_default_projects_nested() {
    let mut module = InfinityModule::new();
    let five = module.push(Inode::Int(5));
    let quantity = module.push(Inode::Quantity {
        value: five,
        unit: UnitTag::Milliseconds,
    });
    let env = module.push(Inode::Env {
        name: "TIMEOUT".to_string(),
        default: Some(quantity),
    });
    module.set_root(Some(env));
    assert_eq!(
        projected(&module),
        serde_json::json!({
            "$env": "TIMEOUT",
            "default": { "value": 5, "unit": "milliseconds" },
        }),
        "a quantity default must project nested, value and unit"
    );
}

/// Every collapsed kind renders as `Expr(kind-name)`: operator, operands,
/// constraint details, patch ops and schema bounds are all lost, and only
/// the kind name survives. One test pins all eight rows of that table.
#[test]
fn collapsed_kinds_render_as_expr_kind_name() {
    let mut module = InfinityModule::new();
    let one = module.push(Inode::Int(1));
    let two = module.push(Inode::Int(2));
    let media = module.push(Inode::Str("text/plain".into()));
    let nodes = [
        Inode::Binary {
            op: BinOp::Add,
            lhs: one,
            rhs: two,
        },
        Inode::Unary {
            op: UnOp::Neg,
            expr: one,
        },
        Inode::Constrained {
            target: one,
            constraint: Constraint::MinMax {
                min: Some(0),
                max: Some(10),
            },
        },
        Inode::Patch(PatchOp::Remove { path: "a.b".into() }),
        Inode::SchemaField(SchemaFieldSpec::bare(TypeSpec::Int)),
        Inode::SchemaTable {
            fields: vec![("port".to_string(), one)],
            closed: true,
        },
        Inode::SchemaArray { element: one },
        Inode::ContentAddressed {
            media_type: media,
            data: one,
        },
    ];
    let ids: Vec<_> = nodes.into_iter().map(|node| module.push(node)).collect();
    let root = module.push(Inode::Array { elements: ids });
    module.set_root(Some(root));
    assert_eq!(
        projected(&module),
        serde_json::json!([
            { "$expr": "Binary" },
            { "$expr": "Unary" },
            { "$expr": "Constrained" },
            { "$expr": "Patch" },
            { "$expr": "SchemaField" },
            { "$expr": "SchemaTable" },
            { "$expr": "SchemaArray" },
            { "$expr": "ContentAddressed" },
        ]),
        "each collapsed kind must render as its kind name only"
    );
}

/// The `Semantic` tag is dropped by the projection: the inner value
/// projects and the Prompt/Policy/Template tag does not survive.
#[test]
fn semantic_tag_is_dropped_inner_projects() {
    let mut module = InfinityModule::new();
    let text = module.push(Inode::Str("hello".into()));
    let semantic = module.push(Inode::Semantic {
        tag: SemanticTag::Prompt,
        inner: text,
    });
    module.set_root(Some(semantic));
    assert_eq!(
        projected(&module),
        serde_json::json!("hello"),
        "a Semantic node must project its inner value, tag dropped"
    );
}

/// The JSON envelope is the root value only: bindings, annotations,
/// provenance and extensions never appear in it, however canary-laden
/// they are. (Protobuf carries them; JSON does not -- loss-table row.)
#[test]
fn json_envelope_is_root_only() {
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Str("v".into()));
    let bound = module.push(Inode::Str("bound-canary".into()));
    module.set_root(Some(value));
    module.bind("bound", bound);
    module.annotate(value, AnnotationKind::Intent("annotation-canary".into()));
    module.add_extension(9, b"extension-canary".to_vec());
    module.set_provenance(Some(Provenance {
        producer: Some("provenance-canary".into()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: None,
        entries: vec![ProvEntry {
            key: "k".into(),
            value: ProvValue::Text("entry-canary".into()),
        }],
    }));
    let json = to_redacted_json(&module).expect("a legal module must project");
    assert_eq!(
        json, "\"v\"",
        "JSON must be the root value and nothing else"
    );
    for canary in [
        "bound-canary",
        "annotation-canary",
        "extension-canary",
        "provenance-canary",
        "entry-canary",
    ] {
        assert!(
            !json.contains(canary),
            "JSON envelope leaked {canary}: {json}"
        );
    }
}

/// The `active-core` bridge drops provenance and extensions entirely:
/// `active-core` 1.4.0 `Module` has no field for either, so there is
/// nowhere to put them. The round trip through the bridge proves it --
/// the module that comes back has no provenance and no extensions -- and
/// the lowered annotations prove the two smaller bridge losses: the path
/// is rewritten to a `node<N>` placeholder and the span is zeroed.
#[test]
#[cfg(feature = "active-core")]
fn bridge_drops_provenance_and_extensions() {
    use active_core::ir::Module as CoreModule;
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Str("v".into()));
    module.set_root(Some(value));
    module.annotate(value, AnnotationKind::Intent("keep me".into()));
    module.add_extension(9, b"extension".to_vec());
    module.set_provenance(Some(Provenance {
        producer: Some("producer".into()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: None,
        entries: vec![],
    }));
    let core: CoreModule = to_active_core(&module).expect("no secrets, no blobs");
    // The schema pointer and the schemas map are dropped with everything
    // else: the bridge never sets them.
    assert!(core.schema.is_none(), "the bridge must not carry a schema");
    assert!(core.schemas.is_empty(), "the bridge must not carry schemas");
    assert_eq!(
        core.annotations.len(),
        1,
        "the one annotation must survive the bridge"
    );
    let annotation = core.annotations.values().next().unwrap().first().unwrap();
    assert_eq!(annotation.path, "node0", "annotation path is a placeholder");
    assert_eq!(annotation.span.line, 0, "annotation span is zeroed");
    assert_eq!(annotation.span.column, 0, "annotation span is zeroed");
    assert_eq!(annotation.span.end_line, 0, "annotation span is zeroed");
    assert_eq!(annotation.span.end_column, 0, "annotation span is zeroed");
    // The node itself survives the bridge (only the metadata is dropped).
    let again = from_active_core(&core).expect("lowering must succeed");
    assert!(again.provenance().is_none(), "provenance is dropped");
    assert!(again.extensions().is_empty(), "extensions are dropped");
    let root = again.root().expect("the lowered module keeps its root");
    assert_eq!(
        again.get(root),
        Some(&Inode::Str("v".into())),
        "the value node itself survives the bridge"
    );
}

/// The pretty printer shares the renderer, so the default travels there
/// too -- and parses back to the same value as the compact form.
#[test]
fn env_default_renders_in_pretty_too() {
    let module = env_module("HOME", Some(Inode::Str("/home/dave".into())));
    let compact = to_redacted_json(&module).expect("a legal module must project");
    let pretty = to_redacted_json_pretty(&module).expect("a legal module must project");
    assert!(
        pretty.contains("\"default\""),
        "pretty must carry the default"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&pretty).expect("valid JSON"),
        serde_json::from_str::<serde_json::Value>(&compact).expect("valid JSON"),
        "pretty and compact must parse to the same value"
    );
}
