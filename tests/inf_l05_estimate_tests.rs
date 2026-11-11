//! INF-L05: `estimate_image_size` omitted most tables (children, fields,
//! parts, edges, annotations, aux, provenance), so it was a lower bound and
//! its "fail fast before the encoder allocates the heaps" purpose failed for
//! images whose omitted tables push the true size past 4 GiB. The estimate
//! is now the exact size, computed from the built node tables.
//!
//! The exactness and the >4 GiB refusal are pinned by unit tests in
//! `src/encode.rs` (scalar counts past 4 GiB need no multi-gigabyte module).
//! These integration tests pin the public-API side: modules that exercise
//! every previously-omitted table at moderate scale still encode and
//! round-trip — the new estimate must not over-count and falsely refuse
//! them — and the wire image they produce validates.

use active_infinity::{
    decode, encode,
    ir::{Constraint, InterpPart, PatchOp},
    AnnotationKind, InfinityModule, Inode, Limits, ProvEntry, ProvValue, Provenance,
};

/// A module exercising every table the old estimate omitted — children,
/// fields, parts, edges, annotations, aux, provenance — at a scale where
/// the omitted tables dominate the image (~1 MiB of fields alone).
fn omitted_tables_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let int = module.push(Inode::Int(1));
    let text = module.push(Inode::Str("s".into()));

    // 10_000 children (40 KiB of children table).
    let array = module.push(Inode::Array {
        elements: vec![int; 10_000],
    });
    // 10_000 fields (160 KiB of fields table).
    let table = module.push(Inode::Table {
        fields: (0..10_000).map(|i| (format!("f{i}"), int)).collect(),
    });
    // 1_000 interpolation parts.
    let mut parts = Vec::with_capacity(1_000);
    for i in 0..1_000 {
        if i % 2 == 0 {
            parts.push(InterpPart::Literal(format!("p{i}")));
        } else {
            parts.push(InterpPart::Expr(int));
        }
    }
    let interp = module.push(Inode::Interpolate { parts });
    // Aux entries via constrained nodes and a patch.
    let constrained = module.push(Inode::Constrained {
        target: int,
        constraint: Constraint::Enum(vec!["a".into(), "b".into(), "c".into()]),
    });
    let patch = module.push(Inode::Patch(PatchOp::Set {
        path: "a.b".into(),
        value: int,
    }));
    // 1_000 annotations (16 KiB of annotation table).
    for i in 0..1_000 {
        module.annotate(text, AnnotationKind::Intent(format!("note {i}")));
    }
    // Provenance with 100 entries.
    module.set_provenance(Some(Provenance {
        producer: Some("inf-l05-test".into()),
        timestamp_ms: 1_700_000_000_000,
        model: None,
        tool: None,
        parent: None,
        entries: (0..100)
            .map(|i| ProvEntry {
                key: format!("k{i:03}"),
                value: ProvValue::Int(i),
            })
            .collect(),
    }));
    module.add_extension(1, b"odd".to_vec());
    module.bind("array", array);
    module.bind("table", table);
    module.bind("interp", interp);
    module.bind("constrained", constrained);
    module.bind("patch", patch);
    let root = module.push(Inode::Array {
        elements: vec![array, table, interp, constrained, patch, text],
    });
    module.set_root(Some(root));
    module
}

#[test]
fn omitted_tables_module_still_encodes_and_round_trips() {
    let module = omitted_tables_module();
    let image = encode(&module).expect("omitted-tables module must encode");
    // The fields table alone is 160 KiB; the whole image is well over
    // 200 KiB, so this is not a toy: the previously-omitted tables dominate
    // it, and the new estimate counted all of them without refusing it.
    assert!(
        image.len() > 200_000,
        "image unexpectedly small: {} bytes",
        image.len()
    );
    let decoded = decode(&image).expect("encoded image must decode");
    let _ = decoded;
    let view = active_infinity::view::InfinityView::new(&image, Limits::default())
        .expect("encoded image must validate");
    assert_eq!(
        view.edges().expect("wire edge table must read back").len(),
        module.edges().len(),
        "wire edges must match the module's structural edges"
    );
}

#[test]
fn fields_heavy_module_still_encodes() {
    // 100_000 fields = 1.6 MiB of fields table, now counted by the estimate
    // and still far under the 4 GiB ceiling: no false refusal.
    let mut module = InfinityModule::new();
    let int = module.push(Inode::Int(1));
    let table = module.push(Inode::Table {
        fields: (0..100_000).map(|i| (format!("field-{i}"), int)).collect(),
    });
    module.set_root(Some(table));
    let image = encode(&module).expect("fields-heavy module must encode");
    assert!(image.len() > 1_600_000, "image too small: {}", image.len());
    decode(&image).expect("fields-heavy image must decode");
}

#[test]
fn children_heavy_module_still_encodes() {
    // 100_000 children = 400 KiB of children table, now counted by the
    // estimate and still far under the 4 GiB ceiling: no false refusal.
    // The elements repeat one node id, so the derived edge table dedups to
    // a single edge — children and edges are counted independently.
    let mut module = InfinityModule::new();
    let int = module.push(Inode::Int(1));
    let array = module.push(Inode::Array {
        elements: vec![int; 100_000],
    });
    module.set_root(Some(array));
    let image = encode(&module).expect("children-heavy module must encode");
    assert!(image.len() > 400_000, "image too small: {}", image.len());
    decode(&image).expect("children-heavy image must decode");
    assert_eq!(
        module.edges().len(),
        1,
        "repeated child ids must dedup to one edge"
    );
}
