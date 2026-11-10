//! Regression tests for INF-INTEROP-02: `from_active_core` silently dropped
//! dangling bindings, annotations, and root instead of erroring.
//!
//! Before the fix a caller-built `CoreModule` with a binding to
//! `NodeId(999)` bridged successfully with the binding gone and no error
//! (W4, probe `audit_modules_probe`, CONFIRMED at 6aad041). The same silent
//! drop applied to the other two shapes that name a node by id: an
//! annotation keyed on an unmapped node was skipped (`continue`), and a
//! dangling root was turned into `set_root(None)` — the bridged module came
//! out rootless with no error. All three shapes must now return
//! `Error::EncodeDangling(id)`, the error the annotation-`expr` path inside
//! the same function already returns for a dangling constraint expression.
//!
//! `active-core`'s own parser never emits these shapes (it only references
//! nodes it created), so only caller-built modules hit this; the parser
//! path is unchanged by the fix.

#![cfg(feature = "active-core")]

use active_core::diag::Span;
use active_core::ir::{
    Annotation as CoreAnnotation, AnnotationKind as CoreAnnotationKind, Module as CoreModule,
    Node as CoreNode, NodeId as CoreNodeId, Value as CoreValue,
};
use active_infinity::error::Error;
use active_infinity::interop::from_active_core;

/// A zero span for hand-built annotations (diagnostics/LSP only; the bridge
/// never reads it). Same construction `to_active_core` uses in
/// `src/interop.rs`.
fn zero_span() -> Span {
    Span {
        line: 0,
        column: 0,
        end_line: 0,
        end_column: 0,
    }
}

/// One real node (`Int(7)`, id 0), valid root, no bindings, no annotations.
/// Each probe mutates exactly one shape of this fixture to dangle, so a
/// failure pins the shape under test.
fn valid_core() -> CoreModule {
    let mut core = CoreModule::new("interop02.active");
    let node = core.add_node(CoreNode::Literal(CoreValue::Int(7)));
    assert_eq!(node, CoreNodeId(0));
    core.root = Some(CoreNodeId(0));
    core
}

/// The error must be exactly `EncodeDangling` carrying the dangling id —
/// not a neighbouring error, and not a silent success.
fn assert_dangling(error: Error, id: u32) {
    assert!(
        matches!(error, Error::EncodeDangling(got) if got == id),
        "expected Error::EncodeDangling({id}), got {error:?}"
    );
}

/// W4's reproduction: a binding to `NodeId(999)` bridged successfully with
/// the binding gone. Must now fail with `EncodeDangling(999)`.
#[test]
fn probe_dangling_binding_errors() {
    let mut core = valid_core();
    core.bindings.insert("ghost".to_string(), CoreNodeId(999));
    let error = from_active_core(&core).expect_err("dangling binding must be refused");
    assert_dangling(error, 999);
}

/// An annotation keyed on an unmapped node was skipped with `continue`.
/// Must now fail with `EncodeDangling(999)`.
#[test]
fn probe_dangling_annotation_target_errors() {
    let mut core = valid_core();
    core.annotations.insert(
        CoreNodeId(999),
        vec![CoreAnnotation {
            kind: CoreAnnotationKind::Intent("ghost note".to_string()),
            path: "ghost".to_string(),
            span: zero_span(),
        }],
    );
    let error = from_active_core(&core).expect_err("dangling annotation target must be refused");
    assert_dangling(error, 999);
}

/// A dangling root was turned into `set_root(None)`: the bridged module
/// came out rootless with no error. Must now fail with
/// `EncodeDangling(999)`.
#[test]
fn probe_dangling_root_errors() {
    let mut core = valid_core();
    core.root = Some(CoreNodeId(999));
    let error = from_active_core(&core).expect_err("dangling root must be refused");
    assert_dangling(error, 999);
}

/// Control, pre-existing behaviour: a constraint annotation whose `expr`
/// names an unmapped node already returned `EncodeDangling` before this
/// fix (the path the fix extends to the other three shapes). Pins that the
/// fix did not change the `expr` shape's error or id.
#[test]
fn probe_dangling_annotation_expr_still_errors() {
    let mut core = valid_core();
    core.annotations.insert(
        CoreNodeId(0),
        vec![CoreAnnotation {
            kind: CoreAnnotationKind::Constraint {
                source: "value > 0".to_string(),
                expr: CoreNodeId(999),
            },
            path: "x".to_string(),
            span: zero_span(),
        }],
    );
    let error = from_active_core(&core).expect_err("dangling annotation expr must be refused");
    assert_dangling(error, 999);
}

/// Control: the valid fixture still bridges, with its binding, annotation
/// and root intact. The fix must refuse only dangling ids, never a
/// well-formed module.
#[test]
fn probe_valid_binding_annotation_root_still_bridge() {
    let mut core = valid_core();
    core.bindings.insert("x".to_string(), CoreNodeId(0));
    core.annotations.insert(
        CoreNodeId(0),
        vec![CoreAnnotation {
            kind: CoreAnnotationKind::Intent("seven".to_string()),
            path: "x".to_string(),
            span: zero_span(),
        }],
    );
    let out = from_active_core(&core).expect("valid module must still bridge");
    assert_eq!(out.node_count(), 1);
    let root = out.root().expect("root survives");
    assert_eq!(out.get(root), Some(&active_infinity::Inode::Int(7)));
    assert!(
        out.bindings().iter().any(|(name, _)| name == "x"),
        "binding x must survive the bridge"
    );
    assert_eq!(
        out.annotations().len(),
        1,
        "annotation must survive the bridge"
    );
}
