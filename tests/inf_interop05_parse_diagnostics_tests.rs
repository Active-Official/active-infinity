//! Regression tests for INF-INTEROP-05: `from_active_source` / `evaluate`
//! discarded parse/eval diagnostics.
//!
//! Before the fix every parse failure mapped to generic
//! `Error::Encode("Active source failed to parse")` (`src/interop.rs:2566`
//! at HEAD `f0c28aa`), discarding the parser's line/column/message, and
//! `evaluate` kept only the evaluator's mapped code
//! (`Error::Evaluation(active_error_code(error.code()))`), discarding the
//! diagnostic's position and message. The fix carries the first
//! diagnostic -- line + column + message -- in the returned error:
//! parse failures become `Error::Parse { line, column, message }`
//! (`infinity/parse`); evaluation failures become the reshaped
//! `Error::Evaluation { code, line, column, message }`
//! (`infinity/evaluation`, `sub_code()` unchanged).
//!
//! Positions are asserted exactly, never just "non-empty": the line-1
//! case pins the 1-based origin and the line-3 case proves a later error
//! reports its own position rather than 0/0 or 1/1.

#![cfg(feature = "active-core")]

use active_infinity::interop::{evaluate, from_active_source};
use active_infinity::Error;

const CANARY: &str = "hunter2-canary-interop05";

/// The exact message active-core 1.4.0 reports for a string literal at
/// statement position (E002). Asserted verbatim: the fix must carry the
/// diagnostic's own words, not a reworded summary.
const ORPHAN_MESSAGE: &str =
    "unexpected string literal at statement position (keys must be identifiers)";

/// A parse error on line 1 carries line 1, column 1 and the message.
#[test]
fn parse_error_on_line_1_carries_line_column_and_message() {
    let error = from_active_source("\"orphan\"\n", "probe.active")
        .expect_err("a string literal at statement position must fail to parse");
    assert_eq!(error.code(), "infinity/parse", "{error}");
    match &error {
        Error::Parse {
            line,
            column,
            message,
        } => {
            assert_eq!(*line, 1, "the error is on line 1; got {error}");
            assert_eq!(*column, 1, "the string starts at column 1; got {error}");
            assert_eq!(message, ORPHAN_MESSAGE, "got {error}");
        }
        other => panic!("a parse failure must be Error::Parse; got {other:?}"),
    }
    assert_eq!(
        error.to_string(),
        "Active source failed to parse at line 1, column 1: unexpected string literal at statement position (keys must be identifiers)",
        "the Display must carry the position and the message"
    );
}

/// A parse error on a later line carries that line, not 0/0 or 1/1.
#[test]
fn parse_error_on_a_later_line_carries_the_right_position() {
    let error = from_active_source("a = 1\nb = 2\n\"orphan\"\n", "probe.active")
        .expect_err("a string literal at statement position must fail to parse");
    assert_eq!(error.code(), "infinity/parse", "{error}");
    match &error {
        Error::Parse {
            line,
            column,
            message,
        } => {
            assert_eq!(*line, 3, "the error is on line 3; got {error}");
            assert_eq!(*column, 1, "the string starts at column 1; got {error}");
            assert_eq!(message, ORPHAN_MESSAGE, "got {error}");
        }
        other => panic!("a parse failure must be Error::Parse; got {other:?}"),
    }
}

/// A parse diagnostic next to a secret literal must not carry the secret:
/// active-core 1.4.0 parser messages name token kinds, keys and type
/// names, never a string literal's content (see the INF-INTEROP-05
/// record for the full survey), so the surfaced message is safe -- and
/// this test pins that the canary never appears in it.
#[test]
fn parse_error_next_to_a_secret_never_carries_the_secret() {
    let source = "[database]\npassword = secret(\"hunter2-canary-interop05\")\n\"orphan\"\n";
    let error = from_active_source(source, "probe.active")
        .expect_err("the orphan string must fail to parse");
    assert_eq!(error.code(), "infinity/parse", "{error}");
    match &error {
        Error::Parse {
            line,
            column,
            message,
        } => {
            assert_eq!(*line, 3, "the error is on line 3; got {error}");
            assert_eq!(*column, 1, "got {error}");
            assert_eq!(message, ORPHAN_MESSAGE, "got {error}");
        }
        other => panic!("a parse failure must be Error::Parse; got {other:?}"),
    }
    assert!(
        !error.to_string().contains(CANARY),
        "the parse error must not carry the secret literal; got {error}"
    );
}

/// An evaluation type error carries the evaluator's message and class.
/// The message is active-core's own rendering, which quotes the
/// operands -- safe here because the bridge refuses secret-bearing
/// modules before the engine runs (see the secret-gate test below).
///
/// The position is 0/0, and that is the honest contract, not a gap in
/// the fix: active-core reports this failure at line 2, column 14 (the
/// `+` in `bad = "text" + 1`, 1-based -- proven by evaluating the parsed
/// `CoreModule` directly), but the bridge drops every source span in
/// lowering -- `InfinityModule` carries no span store, and the
/// `CoreModule` rebuilt by `to_active_core` has an empty `node_spans`
/// map (direct parse: 4 spans; rebuilt: 0) -- so `EvalError::span()` is
/// `None` and there is no position to carry. Real eval positions need
/// spans to survive the bridge, which is a core-model design change
/// (see the INF-INTEROP-05 record); this test pins 0/0 so that change
/// is forced to update it rather than silently changing behaviour.
#[test]
fn eval_type_error_carries_line_column_and_message() {
    let module = from_active_source("[calc]\nbad = \"text\" + 1\n", "probe.active")
        .expect("the probe source must parse");
    let error = evaluate(&module, active_core::Budget::default())
        .expect_err("adding a string and an int must fail evaluation");
    assert_eq!(error.code(), "infinity/evaluation", "{error}");
    assert_eq!(
        error.sub_code(),
        Some("active/T001-type"),
        "the machine-readable class is unchanged by the fix; got {error}"
    );
    match &error {
        Error::Evaluation {
            code,
            line,
            column,
            message,
        } => {
            assert_eq!(*code, "active/T001-type", "got {error}");
            assert_eq!(
                *line, 0,
                "the bridge drops source spans, so no position survives; got {error}"
            );
            assert_eq!(*column, 0, "got {error}");
            assert_eq!(
                message, "type error: unsupported binary op Add on \"text\" and 1",
                "got {error}"
            );
        }
        other => panic!("an evaluation failure must be Error::Evaluation; got {other:?}"),
    }
}

/// The secret gate runs before the engine: a secret-bearing module is
/// refused by `to_active_core` with `infinity/encode`, so no secret
/// material can ever reach the evaluator or its messages. This is the
/// premise the eval-message test above relies on.
#[test]
fn eval_on_a_secret_bearing_module_is_refused_before_evaluation() {
    let module = from_active_source(
        "[database]\npassword = secret(\"hunter2-canary-interop05\")\n",
        "probe.active",
    )
    .expect("the probe source must parse");
    assert!(module.has_secret(), "the fixture must carry a secret");
    let error = evaluate(&module, active_core::Budget::default())
        .expect_err("a secret-bearing module must be refused before evaluation");
    assert_eq!(error.code(), "infinity/encode", "{error}");
    assert_eq!(
        error.to_string(),
        "cannot encode module: the active-core bridge does not export secret material; keep the module in Infinity",
        "the refusal must be the gate's message; got {error}"
    );
    assert!(
        !error.to_string().contains(CANARY),
        "the refusal must not carry the plaintext; got {error}"
    );
}

/// An evaluation failure with no source position reports line 0,
/// column 0 -- the documented "no position" sentinel (parser lines are
/// 1-based, so line 0 can never be a real position). A node-budget
/// failure is global: the accountant trips before any node is blamed.
#[test]
fn eval_error_without_a_position_reports_line_zero() {
    let module =
        from_active_source("port = 8080\n", "probe.active").expect("the probe source must parse");
    let budget = active_core::Budget {
        max_nodes: 1,
        ..active_core::Budget::default()
    };
    let error = evaluate(&module, budget)
        .expect_err("one node of budget must fail evaluation of a larger module");
    assert_eq!(error.code(), "infinity/evaluation", "{error}");
    assert_eq!(
        error.sub_code(),
        Some("active/X001-node-budget"),
        "got {error}"
    );
    match &error {
        Error::Evaluation {
            code,
            line,
            column,
            message,
        } => {
            assert_eq!(*code, "active/X001-node-budget", "got {error}");
            assert_eq!(
                *line, 0,
                "a global budget failure has no position; got {error}"
            );
            assert_eq!(*column, 0, "got {error}");
            assert_eq!(
                message, "evaluation budget exceeded: node budget (limit 1)",
                "got {error}"
            );
        }
        other => panic!("an evaluation failure must be Error::Evaluation; got {other:?}"),
    }
}
