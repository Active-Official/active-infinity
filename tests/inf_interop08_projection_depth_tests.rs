//! Regression tests for INF-INTEROP-08: projections refuse any module
//! deeper than 256 (`PROJECTION_DEPTH`) while the codec allows depth 4096.
//!
//! Audit (`AUDIT-REPORT.md:935`, at 6aad041): a legal 300-deep module
//! cannot be rendered as JSON or protobuf at all. W4 confirmed it with
//! `w4_interop08_projection_depth`: 300-deep nested Tables give
//! `Err("infinity/limit")`, 200-deep renders fine. (Unary chains do NOT
//! trigger it -- operators collapse to `Expr(kind-name)` without
//! recursing -- so nested Tables are the right shape.)
//!
//! The fix (record `records/F2-INF/INF-INTEROP-08.md`):
//!
//! - The whole projection path is iterative -- `build_projected`,
//!   `resolves_to_secret`, `write_json`, `encode_value` and
//!   `projected_size` run on explicit heap stacks -- and the ceiling is
//!   the codec's 4096 (`PROJECTION_DEPTH`, in edges from the projected
//!   node). A legal 300-deep module now renders on both paths.
//! - Depth counting: the codec counts nodes from 1 (the root Table is
//!   depth 1), the projection counts edges from 0 (the root is depth 0),
//!   so the deepest node of a legal module sits at projection depth 4095,
//!   one inside the 4096 ceiling. A module past the codec ceiling is
//!   refused by the codec first, with `infinity/depth` -- the projection
//!   ceiling itself is defense in depth, pinned by a unit test in
//!   `src/interop.rs` that calls `build_projected` directly on a
//!   4097-table module (leaf at depth 4097, refused with
//!   `infinity/limit`, limit 4096).
//! - Rendering is part of the path, and it was measured, not assumed:
//!   with the walk iterative but the JSON renderer still building a
//!   `serde_json::Value` tree, a 4095-deep module aborted the debug test
//!   process with `STATUS_STACK_OVERFLOW` on the 2 MiB test-thread stack
//!   -- serializing and dropping the Value tree still recurse per level.
//!   The JSON projection therefore writes text straight from the
//!   `Projected` tree (`write_json`, no Value tree at all), and dropping
//!   a `Projected` tree is iterative too. The small-stack tests below pin
//!   that a 4095-deep module renders as JSON on a 256 KiB stack, in
//!   debug -- if that ever regresses, the ceiling must move to where
//!   rendering is safe, not stay at 4096 on faith.
//! - The protobuf path has its own, separate ceiling: the encoder copies
//!   each nested message into its parent, so its work grows with the
//!   square of the depth and `MAX_PROTOBUF_WORK` (64 MiB) trips first.
//!   Measured: a single-field Record chain renders as protobuf to depth
//!   1914 and is refused cleanly with `infinity/limit` (protobuf work
//!   bytes) at 1915. That refusal is loud, documented, and pinned below;
//!   the streaming encoder that would remove the quadratic cost is a
//!   recorded follow-up, not this fix.

use active_infinity::interop::to_redacted_json;
use active_infinity::{encode, Error, InfinityModule, Inode};
use active_infinity::{to_protobuf, validate};

/// A module whose root is `depth` nested single-field Tables over one
/// leaf `Int(1)`: the root Table is at projection depth 0, so the leaf
/// sits at projection depth `depth` (and at codec depth `depth + 1`).
fn nested_tables(depth: usize) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut cur = module.push(Inode::Int(1));
    for _ in 0..depth {
        cur = module.push(Inode::Table {
            fields: vec![("v".to_string(), cur)],
        });
    }
    module.set_root(Some(cur));
    module
}

/// Assert `error` is the codec's depth refusal at the default ceiling.
fn assert_codec_depth_refusal(error: &Error) {
    assert_eq!(error.code(), "infinity/depth", "{error}");
    match error {
        Error::Depth { limit } => assert_eq!(
            *limit,
            active_infinity::Limits::default().max_depth,
            "{error}"
        ),
        other => panic!("expected Error::Depth, got {other:?}"),
    }
}

/// Assert the JSON of a `depth`-deep nested-table module has exactly one
/// field per table and the leaf `Int(1)` innermost.
fn assert_nested_json(json: &str, depth: usize) {
    assert_eq!(
        json.matches("\"v\":").count(),
        depth,
        "one field per table: {json:.200}..."
    );
    assert!(
        json.contains("{\"v\":1}"),
        "the leaf Int(1) is innermost: {json:.200}..."
    );
}

#[test]
fn w4_shape_200_deep_tables_render_as_json() {
    // W4's control: 200-deep renders fine, pre- and post-fix.
    let module = nested_tables(200);
    let json = to_redacted_json(&module).expect("200-deep must project");
    assert_nested_json(&json, 200);
}

#[test]
fn w4_shape_300_deep_tables_render_as_json() {
    // W4's reproduction, fixed: 300-deep nested Tables rendered
    // `Err("infinity/limit")` before the fix; now they project.
    let module = nested_tables(300);
    let json = to_redacted_json(&module).expect("300-deep must project");
    assert_nested_json(&json, 300);
}

#[test]
fn w4_shape_300_deep_tables_render_as_protobuf() {
    // Same fix on the protobuf path: both render the same tree.
    let module = nested_tables(300);
    let bytes = to_protobuf(&module).expect("300-deep must project");
    assert!(!bytes.is_empty(), "a 300-deep module projects to bytes");
}

#[test]
fn thousand_deep_tables_render_on_both_paths() {
    // Mid-range depth: past the old 256 ceiling by 4x, well inside the
    // new 4096 ceiling, on both paths.
    let module = nested_tables(1000);
    let json = to_redacted_json(&module).expect("1000-deep must project");
    assert_nested_json(&json, 1000);
    let bytes = to_protobuf(&module).expect("1000-deep must project");
    assert!(!bytes.is_empty(), "a 1000-deep module projects to bytes");
}

#[test]
fn ceiling_deep_tables_render_as_json() {
    // The deepest legal module: 4095 Tables over a leaf is codec depth
    // 4096, the last depth the ceiling allows. The JSON path renders it.
    let module = nested_tables(4095);
    let json = to_redacted_json(&module).expect("4095-deep must project");
    assert_nested_json(&json, 4095);
}

/// Assert `error` is the protobuf encoder-work refusal.
fn assert_protobuf_work_refusal(error: &Error) {
    assert_eq!(error.code(), "infinity/limit", "{error}");
    match error {
        Error::Limit { kind, limit } => {
            assert_eq!(*kind, "protobuf work bytes", "{error}");
            assert_eq!(*limit, 64 << 20, "{error}");
        }
        other => panic!("expected Error::Limit, got {other:?}"),
    }
}

#[test]
fn protobuf_renders_to_1914_and_refuses_1915() {
    // The protobuf path's own ceiling, measured: the encoder copies each
    // nested message into its parent, so the work grows with the square
    // of the depth and `MAX_PROTOBUF_WORK` (64 MiB) trips first. A
    // single-field Record chain renders to depth 1914 (24,606 bytes out)
    // and is refused cleanly -- no abort, no truncation -- at 1915. The
    // JSON path has no such ceiling: it renders to 4095.
    for depth in [1900usize, 1914] {
        let module = nested_tables(depth);
        let bytes = to_protobuf(&module).expect("{depth}-deep must project");
        assert!(!bytes.is_empty(), "a {depth}-deep module projects to bytes");
    }
    for depth in [1915usize, 4095] {
        let module = nested_tables(depth);
        let error = to_protobuf(&module).expect_err("{depth}-deep must be refused");
        assert_protobuf_work_refusal(&error);
    }
}

#[test]
fn past_ceiling_tables_are_refused_by_the_codec_first() {
    // 4096 Tables put the leaf at codec depth 4097: the codec refuses
    // first, with `infinity/depth`, before the projection ceiling is
    // ever reached -- on both paths.
    let module = nested_tables(4096);
    let error = to_redacted_json(&module).expect_err("4096-deep must be refused");
    assert_codec_depth_refusal(&error);
    let error = to_protobuf(&module).expect_err("4096-deep must be refused");
    assert_codec_depth_refusal(&error);
}

#[test]
fn codec_accepts_4095_deep_tables_and_refuses_4096() {
    // The codec side of the asymmetry, with the depth counting pinned.
    // Codec depth counts nodes from 1 (the root Table is depth 1), so a
    // module of 4095 Tables over a leaf is codec-depth 4096 -- the last
    // depth the ceiling allows -- while 4096 Tables put the leaf at
    // codec-depth 4097 and encode refuses with `infinity/depth`. The
    // projection counts edges from 0 (the root is depth 0), so the
    // deepest legal leaf sits at projection depth 4095, one inside a
    // 4096 ceiling: a 4096 projection ceiling never refuses a legal
    // module, it only matches the codec.
    let module = nested_tables(4095);
    let bytes = encode(&module).expect("encode must accept depth 4096");
    validate(&bytes).expect("a depth-4096 image validates");
    let decoded = active_infinity::decode(&bytes).expect("a depth-4096 image decodes");
    assert_eq!(decoded.node_count(), 4096);
    let past = nested_tables(4096);
    let error = encode(&past).expect_err("encode must refuse depth 4097");
    assert_codec_depth_refusal(&error);
}

/// Render a `depth`-deep nested-table module on both paths inside a
/// 256 KiB thread: 8x smaller than the 2 MiB test-thread stack. If any
/// step of either path still recursed per level of depth, the thread
/// would abort the process with `STATUS_STACK_OVERFLOW` instead of
/// returning -- the `join` below would never run. A clean refusal counts
/// as a pass here: the protobuf path refuses past its work budget, and
/// returning the error proves it did not abort.
fn render_on_small_stack(depth: usize) -> (bool, bool) {
    let handle = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || {
            let module = nested_tables(depth);
            let json_ok = to_redacted_json(&module).is_ok();
            let protobuf_ok = to_protobuf(&module).is_ok();
            (json_ok, protobuf_ok)
        })
        .expect("spawn a 256 KiB thread");
    handle
        .join()
        .expect("the 256 KiB thread must complete, not abort the process")
}

#[test]
fn small_stack_thread_renders_300_deep_tables() {
    // The finding's shape on a small stack: the old recursive walk
    // overflowed a debug stack at ~600 tables; 300 tables on 256 KiB
    // must render on both paths.
    let (json_ok, protobuf_ok) = render_on_small_stack(300);
    assert!(
        json_ok,
        "a 300-deep module must render as JSON on a 256 KiB stack"
    );
    assert!(
        protobuf_ok,
        "a 300-deep module must render as protobuf on a 256 KiB stack"
    );
}

#[test]
fn small_stack_thread_renders_1000_deep_tables() {
    let (json_ok, protobuf_ok) = render_on_small_stack(1000);
    assert!(
        json_ok,
        "a 1000-deep module must render as JSON on a 256 KiB stack"
    );
    assert!(
        protobuf_ok,
        "a 1000-deep module must render as protobuf on a 256 KiB stack"
    );
}

#[test]
fn small_stack_thread_renders_1914_deep_tables_both_paths() {
    // The protobuf path at its own boundary on the small stack: the
    // iterative encode and the iterative `Projected` drop must both hold
    // at 1914, the deepest protobuf rendering.
    let (json_ok, protobuf_ok) = render_on_small_stack(1914);
    assert!(
        json_ok,
        "a 1914-deep module must render as JSON on a 256 KiB stack"
    );
    assert!(
        protobuf_ok,
        "a 1914-deep module must render as protobuf on a 256 KiB stack"
    );
}

#[test]
fn small_stack_thread_renders_ceiling_deep_tables() {
    // The strongest pin: the maximum legal depth (4095 tables, codec
    // depth 4096) on the 256 KiB stack. The JSON path must render it: if
    // `write_json` or the `Projected` drop still recursed per level, this
    // thread would abort the process instead of returning. The protobuf
    // path must refuse it cleanly with the work-budget limit -- returning
    // the error, not aborting, is the pass.
    let (json_ok, protobuf_ok) = render_on_small_stack(4095);
    assert!(
        json_ok,
        "a ceiling-deep module must render as JSON on a 256 KiB stack"
    );
    assert!(
        !protobuf_ok,
        "a ceiling-deep module must be refused by the protobuf work budget"
    );
}
