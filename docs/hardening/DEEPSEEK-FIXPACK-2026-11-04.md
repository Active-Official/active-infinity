# DeepSeek fix pack — investigation record (Active Infinity)

Pack: `G:\AUDIT\Audit-Deepseek-Chat-on-Web-11-04-2026\deepseek-fixpack`. The audit
read truncated GitHub views; every verdict is re-established from this tree.

Tree: `a2f33c2` plus the changes recorded here.

| ID | Pack verdict | This tree | Action |
|----|--------------|-----------|--------|
| F-01 | FALSE | **FALSE** | negative tests only |
| F-05 | CONFIRMED | **CONFIRMED** | subtree value-plane walk |

## F-01 — `check_bindings` is not called

- **Call graph**: `Validated::new` (`validate.rs:59`) calls
  `check_reachability` (`:144`), whose first statement is
  `self.check_bindings()?` (`:2298`). The pack's "never called" is an artifact of
  the truncated GitHub view.
- **Escape hatches**: `rg "Validated {"` finds no construction outside `new`.
- **PoC**: `tests/f01_bindings_tests.rs` mutates a real image and drives
  `validate_with`:
  - a duplicate binding name → `infinity/duplicate-binding`
  - an unsorted binding table → `infinity/duplicate-binding`
  - a non-zero reserved word → `infinity/reserved`
  - a zero section count → refused
- **Verdict**: FALSE as stated. No production change; the four tests lock the
  call graph so a future refactor cannot drop the check silently.

## F-05 — `Any` and open tables did not inspect their cone

- **Call sites found**: `schema::matches_type`, reached from
  `Schema::validate_instance` / `validate_bytes`.
- **Existing tests**: none covered a program node nested inside a container.
- **PoC**: `tests/f05_schema_any_tests.rs` — an `Ident` under an `Any` field
  passed validation before the fix; so did one under an open `Table` field and
  one inside an array. After the fix all three are `infinity/schema`, and a pure
  data cone still validates.
- **Verdict**: CONFIRMED. `Any` is documented as "a value: it does not open the
  program plane", and the check only looked at the top node.
- **Patch**: `is_value_subtree` is an iterative, budgeted walk (a hand-built
  module can contain a cycle even though validation refuses one); `Any` and
  `Table { closed: false }` use it.
