//! Marathon section I-04: decode and the zero-copy view.

use active_infinity::layout::Section;
use active_infinity::view::InfinityView;
use active_infinity::{encode, AnnotationKind, DecodeOpts, InfinityModule, Inode, NodeId};

fn image_with_secret() -> Vec<u8> {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(active_infinity::SecretBytes::from(
        "view-canary-8891",
    )));
    let root = module.push(Inode::Table {
        fields: vec![("token".to_string(), secret)],
    });
    module.set_root(Some(root));
    encode(&module).expect("encode")
}

#[test]
fn printing_a_view_never_prints_the_secret_heap() {
    // `Validated` derived `Debug`, so `{:?}` printed the raw buffer — including
    // the secret heap — into any log or panic message that formatted a view.
    let image = image_with_secret();
    let view = InfinityView::new(&image, active_infinity::Limits::default()).expect("view");
    let printed = format!("{view:?}");
    // The buffer's derived form is a decimal byte list, so a substring check on
    // the text is not enough: look for the secret's first bytes in that form.
    assert!(
        !printed.contains("118, 105, 101, 119"),
        "the debug form carries the image bytes: {printed}"
    );
    assert!(
        printed.contains("bytes") && printed.contains("content_hash"),
        "the debug form describes the image instead: {printed}"
    );
}

#[test]
fn count_matches_children_for_every_kind() {
    // `count()` returned zero for kinds that point at another node, so a caller
    // sizing work by it skipped those references.
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Int(5));
    let quantity = module.push(Inode::Quantity {
        value,
        unit: active_infinity::UnitTag::Milliseconds,
    });
    let reference = module.push(Inode::Ref(value));
    let unary = module.push(Inode::Unary {
        op: active_infinity::ir::UnOp::Not,
        expr: value,
    });
    let binary = module.push(Inode::Binary {
        op: active_infinity::ir::BinOp::Add,
        lhs: value,
        rhs: quantity,
    });
    let env = module.push(Inode::Env {
        name: "TOKEN".to_string(),
        default: Some(value),
    });
    let array = module.push(Inode::Array {
        elements: vec![value, quantity],
    });
    let root = module.push(Inode::Table {
        fields: vec![
            ("array".to_string(), array),
            ("binary".to_string(), binary),
            ("env".to_string(), env),
            ("reference".to_string(), reference),
            ("unary".to_string(), unary),
        ],
    });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode");
    let view = InfinityView::new(&image, active_infinity::Limits::default()).expect("view");
    for index in 0..view.node_count() {
        let id = NodeId(index);
        let node = view.node(id).expect("node");
        let children = view.children(id).expect("children");
        assert_eq!(
            node.count() as usize,
            children.len(),
            "kind {} reports {} but carries {}",
            node.kind_name(),
            node.count(),
            children.len()
        );
    }
}

#[test]
fn an_env_node_reports_its_name_as_the_primary_string() {
    let mut module = InfinityModule::new();
    let env = module.push(Inode::Env {
        name: "ACTIVE_TOKEN".to_string(),
        default: None,
    });
    let root = module.push(Inode::Table {
        fields: vec![("env".to_string(), env)],
    });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode");
    let view = InfinityView::new(&image, active_infinity::Limits::default()).expect("view");
    let env_node = (0..view.node_count())
        .map(NodeId)
        .find(|id| view.node(*id).map(|node| node.kind == 12).unwrap_or(false))
        .expect("the fixture has an Env node");
    assert_eq!(
        view.primary_string(env_node).expect("primary string"),
        Some("ACTIVE_TOKEN")
    );
}

#[test]
fn an_annotation_reports_its_constraint_expression() {
    let mut module = InfinityModule::new();
    let target = module.push(Inode::Int(1));
    let expr = module.push(Inode::Int(2));
    let root = module.push(Inode::Array {
        elements: vec![target, expr],
    });
    module.set_root(Some(root));
    module.annotate(
        root,
        AnnotationKind::Constraint {
            source: "port > 0".to_string(),
            expr,
        },
    );
    let image = encode(&module).expect("encode");
    let view = InfinityView::new(&image, active_infinity::Limits::default()).expect("view");
    let annotations = view.annotations().expect("annotations");
    assert_eq!(annotations.len(), 1);
    let (_, _, _, b) = annotations[0];
    assert_ne!(b, 0, "the constraint expression is reported");
    view.node(NodeId(b))
        .expect("the expression is a node in the image");
}

#[test]
fn an_unknown_annotation_kind_is_refused_by_the_accessor() {
    // The compact annotation reader used to map any unknown kind onto
    // `AiImmutable`; a future kind then changed meaning silently.
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Int(1));
    module.set_root(Some(root));
    module.annotate(root, AnnotationKind::Intent("note".to_string()));
    let mut bytes = encode(&module).expect("encode");
    let header = active_infinity::layout::Header::parse(&bytes).expect("header");
    let span = header.span(Section::Annotations);
    let at = span.offset as usize;
    // Record layout: node u32, kind u32, a u32, b u32.
    bytes[at + 4..at + 8].copy_from_slice(&3u32.to_le_bytes());
    // Keep the hash consistent so the kind check is what fires.
    let hash = active_infinity::encode::hash_image(&bytes).expect("hash");
    bytes[16..48].copy_from_slice(&hash);
    let error = active_infinity::decode::decode_annotations(&bytes)
        .expect_err("an unknown kind is refused");
    assert_eq!(error.code(), "infinity/annotation", "{error:?}");
    let opts = DecodeOpts {
        limits: active_infinity::Limits::default(),
        verify_hash: true,
        verify_canonical: false,
    };
    assert!(
        active_infinity::view::InfinityView::with_opts(&bytes, opts).is_err(),
        "the validating path refuses it too"
    );
}
