# Copilot deep audit marathon — Active Infinity

Program: `C:\Users\Usuario\Downloads\Active-Absolute-Max-Program`, phase M-6,
procedure `COPILOT-DEEP-AUDIT-LOOP.md`. Reviewer: GitHub Copilot CLI routed to the
Muse proxy (`muse-spark-1.3-contributor`, `--reasoning-effort xhigh`), which reads
the repository through its own tool access, so findings carry file:line
references rather than pasted guesses.

Loop per section: prepare context → hostile review → triage every finding against
the code → regression test first → minimal fix → targeted tests + clippy → re-audit
→ CLEAN twice or ADR-accepted residual.

## Status

| ID | Section | Paths | State | Findings (fixed / rejected / open) | Commits |
|----|---------|-------|-------|------------------------------------|---------|
| I-01 | layout / header | `src/layout.rs` | CLEAN (round 2 open items fixed) | 10 fixed, 1 rejected, 0 open | this commit |
| I-02 | validate | `src/validate.rs` | **CLEAN** (round 3: 3 high fixed, 10 triaged) | 24 fixed, 10 rejected, 0 open | this commit |
| I-03 | encode / canonical | `src/encode.rs`, `src/canonical.rs` | **CLEAN** (round 2 fixed two more) | 11 fixed, 3 rejected, 0 open | `aef1efd`, `43b1078` |
| I-04 | decode / view | `src/decode.rs`, `src/view.rs` | CLEAN | 7 fixed, 3 rejected, 0 open | this commit |
| I-05 | IR / units | `src/ir.rs`, `src/unit.rs` | CLEAN | 5 fixed, 2 rejected, 1 deferred | this commit |
| I-06 | stream and delta | `src/stream.rs` | CLEAN | 7 fixed, 2 rejected, 0 open | this commit |
| I-07 | schema class | `src/schema.rs` | CLEAN | 6 fixed, 1 rejected | this commit |
| I-08 | store | `src/store.rs` | **CLEAN** | 7 fixed, 1 rejected | this commit |
| I-09 | compress | `src/compress.rs` | pending | — | — |
| I-10 | signature / proof | `src/signature.rs`, `src/proof.rs` | pending | — | — |
| I-11 | merge | `src/merge.rs` | pending | — | — |
| I-12 | interop / protobuf | `src/interop.rs`, `src/protobuf.rs` | pending | — | — |
| I-13 | error codes | `src/error.rs` | pending | — | — |
| I-14 | FFI | `ffi/**` | pending | — | — |
| I-15 | CLI | `cli/active-infinity-cli/**` | pending | — | — |
| I-16 | fuzz targets | `fuzz/**` | pending | — | — |

## Cross-cutting passes (after the sections)

| Pass | State | Notes |
|---|---|---|
| Concurrency / multi-tenant | pending | — |
| Oracle and secret paths (Display/Debug/Serialize) | pending | — |
| Wire confusion (AINF vs stream vs protobuf) | pending | — |
| Resource bombs (depth, counts, sizes) | pending | — |
| Polyglot encoder golden | pending | — |
| Second pass over changed sections | pending | — |

## Log

Entries are appended per section: date, reviewer path, findings, disposition.

### I-04 decode / zero-copy view — 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | critical | `Validated` derived `Debug`, so `{:?}` printed the image buffer — the secret heap included — as a decimal byte list into any log or panic message | **fixed**: manual `Debug` prints the byte length, the content hash and the node count; `printing_a_view_never_prints_the_secret_heap` (decimal-byte assertion, fails pre-fix) |
| 2 | high | public `buf()` exposes the secret heap | **rejected**: the caller supplied that buffer. The accessor returns the bytes it was given and creates no reach the caller did not already have |
| 3 | high | `with_opts(verify_hash: false)` still reports `content_hash()` | **rejected**: the caller explicitly opted out of hash verification; the value is the header's claim, and the docs say so. A caller that needs a trusted identity uses the default options |
| 4 | high | the `provenance_entries` doc claimed redaction although the view validates structure only | **fixed in docs**: the accessor now says redaction holds for a canonical image (`validate_canonical`) and points non-canonical callers at `interop::provenance_json` |
| 5 | medium | `decode_annotations` mapped an unknown kind onto `AiImmutable` while the full decoder refused it | **fixed**: both paths return `infinity/annotation`; `an_unknown_annotation_kind_is_refused_by_the_accessor` |
| 6 | medium | `InfinityView::annotations` dropped `b`, the constraint expression | **fixed**: it returns `(subject, kind, a, b)`; `an_annotation_reports_its_constraint_expression` |
| 7 | medium | `node_string_id` omitted kind 12, so an `Env` node had no primary string | **fixed**: the env name is the primary string; `an_env_node_reports_its_name_as_the_primary_string` |
| 8 | medium | `NodeView::count()` returned 0 for kinds that point at another node | **fixed**: it reports the children every kind carries; `count_matches_children_for_every_kind` |
| 9 | medium | `decode_provenance` validated twice | **fixed**: one `Validated::new` pass |
| 10 | medium | `dependents()` scans every edge per call and `edges()` materialises the table | **documented**: both are whole-graph queries by contract; a caller that walks them per node is doing O(V·E) work, which the docs now say |
| 11 | low | `decode_validated` re-validated structure with no depth budget after the wire pass had enforced one | **fixed**: it passes the view's `max_nodes` and `max_depth` |
| 12 | low | `children()` hand-rolled four kinds | **rejected**: the four branches are the same traversal `node_children` performs; making them share one function is a refactor with no defect behind it |

Gate: clippy clean; `cargo test --all-features` 248 passed, 0 failed.

### I-05 IR, secrets and units — 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `structurally_eq` never compared `extensions`, although canonicalization sorts and hashes them: two modules compared equal while their bytes differed | **fixed**: extensions are part of equality; `modules_with_different_extensions_are_not_equal` |
| 2 | medium | `children()` allocates a fresh `Vec` on every traversal, and validation walks the graph several times | **deferred with a note**: a `children_into(&mut Vec)` accessor and its use in the hot loops is a performance refactor, scheduled with the cross-cutting performance pass; no correctness effect |
| 3 | medium | `SecretBytes::drop` used `fill(0)`, a store the optimizer may remove | **fixed**: the crate forbids `unsafe`, so it now uses `zeroize` (one small dependency) whose volatile fence cannot be elided |
| 4 | medium | `TypeSpec::name()` joined enum members, so a type carrying a secret copy printed it through a diagnostics string | **fixed**: `Enum(<N values>)`, matching `Debug`; `a_type_name_does_not_echo_its_members` |
| 5 | medium | `validate_structure` omits unit/type/blob/extension coherence while its doc claimed wire parity | **fixed in docs**: the contract is now "the node graph", with the cross-table rules named as the encoder's and the wire validator's job |
| 6 | medium | `ProvKind::from_code(4)` produced a kind the wire reserves and nothing can encode | **fixed**: code 4 has no reader; `the_reserved_provenance_kind_has_no_reader` |
| 7 | low | `has_secret()` only matched a literal `Secret`, so `secret(env.TOKEN)` modules answered false | **fixed**: it matches every secret node (`Secret` and `SecretRef`); `a_secret_ref_module_reports_having_a_secret` |
| 8 | low | `push()` panics at `u32::MAX` nodes | **rejected**: documented, with `try_push` as the fallible form (I-01) |

Gate: clippy clean; `cargo test --all-features` 252 passed and
`--no-default-features` 207 passed, 0 failed.

### I-06 stream and delta — 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | critical | `SetBinding`/`RemoveBinding` wrote the name length as u32 while the decoder and the spec (§4) use u16, so every binding delta was misparsed | **fixed**: one `write_delta_string` writes `u16` with a length check; `binding_deltas_round_trip` |
| 2 | high | `pending_delta_bytes` accumulated across generations, so an honest long-lived stream eventually failed with `infinity/limit` | **fixed**: the budget resets when a generation completes; `an_incremental_generation_resets_its_delta_budget` |
| 3 | high | `push` bumped the sequence and frame counters before processing, so one bad frame wedged the decoder and the retry reported a sequence error | **fixed**: `push` is a wrapper that snapshots the counters and pending deltas, calls `push_inner`, and restores on failure; `a_failed_frame_does_not_consume_its_sequence_number` |
| 4 | high | `merge_fragment` used a wrapping `as u32` add, a panicking `push`, an unchecked map lookup and no node bound | **fixed**: checked total against the u32 space (`infinity/limit`), `try_push`, and a rootless fragment is `infinity/stream-delta`; `a_fragment_without_a_root_is_refused` |
| 5 | high | the delta decoder read a provenance entry count with no `max_prov_entries` check, so a 64 MiB frame could force millions of entries | **fixed**: the ceiling fires before the loop; `a_delta_provenance_block_is_bounded_by_its_entry_ceiling` |
| 6 | medium | `push_delta` packed every op into one frame with no payload ceiling and `as u32` lengths, so the encoder could emit a stream its own decoder refuses | **fixed**: `u32::try_from` for the op count and fragment length, and a payload over `MAX_FRAME_PAYLOAD` is `infinity/too-large` |
| 7 | medium | `Frame::parse` on a 1–3 byte buffer reports `infinity/stream-magic` | **rejected**: the first four bytes identify the format, exactly as the file codec does, and `push_bytes` never calls `parse` without a full header; the contract is now documented on the function |
| 8 | medium | distinct `StreamDelta` messages (`root`/`target`/`binding`…) form a node-existence oracle | **rejected**: a delta is applied by the party that supplied it, against its own module; the message tells that party about its own data |
| 9 | low | a batch could start at section 1, and the accumulated-size check used a wrapping `sum` after appending | **fixed**: the first batch must be section 0, the sum saturates, and the bound is checked before the append; `a_generation_must_start_at_section_zero` |

Gate: clippy clean; `cargo test --all-features` 258 passed, 0 failed.

### I-07 schema class — 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `validate_instance` ignored the declared `min`/`max`/`min_len`/`max_len`/`pattern`/`default`, so a schema that looked restrictive accepted anything | **fixed**: numeric bounds and string lengths are enforced, a default is type-checked, and a pattern (no engine in this crate) is refused instead of ignored; `declared_bounds_are_enforced`, `string_length_bounds_are_enforced`, `a_pattern_constraint_is_refused_instead_of_ignored`, `a_default_of_the_wrong_type_is_refused` |
| 2 | high | `matches_type` accepted program fragments as values (`Ident`/`Interpolate` for `String`, any `Quantity` for `Duration`, `SchemaTable` for `Table`, `SecretRef` for `Secret`, `ContentAddressed` for `Bytes`) | **fixed**: only the value plane matches, and a duration needs a time unit; `only_value_nodes_match_a_declared_type`, `a_duration_accepts_time_units_only` |
| 3 | high | `from_fields` used a panicking `push` and accepted duplicate names, so one spec was silently unchecked | **fixed**: `try_push` and a duplicate-name refusal; `duplicate_field_names_are_refused_at_construction` |
| 4 | medium | `validate_bytes` validated twice, and distinct messages form a field-existence oracle | **fixed for the double pass** (a validating `decode` is the only pass); the messages stay distinct, and the oracle is rejected: the caller supplies both the schema and the instance, so the message describes its own data |
| 5 | medium | a `default` made a missing field pass without checking the default's type; enum members are interned in the public heap | **fixed for the default** (type-checked); enum members are schema names and follow the rule documented in `layout.md` §3.1 |
| 6 | medium | `from_bytes` accepted a schema module carrying `Secret`/`SecretRef`/`Blob` nodes reachable from a default, a covert channel inside the pinned schema hash | **fixed**: such a module is refused with `infinity/schema`; `a_schema_carrying_a_secret_node_is_refused` |
| 7 | low | `content_key` rendered a schema type through `Debug`, which hides enum members, so two different types could share an ordering key | **fixed**: the key renders enum members and the table flag field by field |

Gate: clippy clean; `cargo test --all-features` 267 passed, 0 failed.

### I-01 layout / header — 2026-10-31 (rounds 1 and 2)

Reviewer: Copilot CLI → Muse proxy, `xhigh`, repo tool access.

Round 1 findings and disposition (all regression-tested in
`tests/marathon_layout_tests.rs`; the probe run against the pre-fix tree showed
all four behavioural probes failing, including a debug panic in `align8`):

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `Header::write` never wrote the reserved tail (bytes 200..224), so a written header refused by its own `parse` and inherited whatever the caller's buffer held | **fixed**: the tail is zeroed; `writing_a_header_zeroes_the_reserved_tail` |
| 2 | high | `validate_structure` did not enforce reachability while its doc claimed wire parity | **fixed as a contract**, not by force: reachability is a canonicalization concern (in-place deltas rely on dropping orphans), so the doc now says so and `check_reachable()` is public; `unreachable_nodes_are_reported_and_dropped_by_canonicalization` pins both halves, and `docs/spec/layout.md` §3.1a records it |
| 3 | medium | dialect preimage pinned via string literals, no link to the constants | **fixed**: `NODE_KIND_MAX`, `AUX_TAGS`, `DIALECT_KINDS_TEXT`, `DIALECT_AUX_TAGS_TEXT`, `DIALECT_HASH_GOLDEN`; two tests force a deliberate change; §1.2 documents the byte-exact preimage |
| 4 | medium | `push()` panicked on arena exhaustion | **fixed**: `try_push()` returns `Error::Limit`; `push` documents its panic |
| 5 | medium | `SecretBytes` left its bytes in freed heap | **fixed**: `Drop` overwrites the buffer |
| 6 | medium | spec said secrets never compare equal while module equality blinds them | **fixed in docs**: §3.1 distinguishes payload equality from module blinding |
| 7 | medium | `Limits::check` covered 5 of 20 ceilings | **fixed**: all 22 ceilings, each naming its field |
| 8 | low | `Error::HeaderSize(u8)` truncated the `u16` wire value | **fixed**: field is `u16` |
| 9 | low | `align8` wrapped at `u64::MAX` (panic in debug) | **fixed**: saturating; `align8_saturates_instead_of_wrapping` |
| 10 | low | stale "160-byte" doc; short magic prefix reported as magic | **doc fixed**; error-order part **rejected**: a wrong 4-byte prefix is "not an AINF image" (`infinity/magic`) and a matching prefix that is short is `infinity/header-truncated`, which is what `store` and the CLI branch on |

Round 2 findings and disposition:

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 11 | medium | `read_u32/read_u64` computed `offset + 4/8` unchecked (`usize::MAX` wraps or panics) | **fixed**: `checked_add` → `infinity/truncated`; `a_hostile_offset_is_reported_as_truncated_not_a_wrap` |
| 12 | medium | `Header::write` still panics on a short buffer | **rejected**: documented precondition plus the fallible `try_write`; the assert runs in release too, and `redteam_battery` forbids debug-only security branches. Changing the signature to `&mut [u8; 224]` would push the panic to the caller |
| 13 | medium | provenance hashes and bindings were bounded by `u32::MAX` in `validate_counts` | **fixed**: new `Limits::max_hashes` / `max_bindings`, enforced in the count pass and in the hash walk, with their own ceiling names |
| 14 | low | `hashes` limit borrowed `max_nodes` in the error | **fixed** by 13 |
| 15 | low | dialect preimage widths undocumented | **fixed**: §1.2 now states the widths, order and separators |
| 16 | low | `SectionSpan::bytes` is only valid for fixed-stride sections | **rejected**: the doc says "for a fixed-stride section"; the var-length sections compute their end in `validate.rs::section_end` |

Gate after the section: `cargo clippy --locked --all-targets --all-features
-D warnings` clean; `cargo test --all-features` 218 passed, 0 failed.

### I-02 validate, slice A (layout, counts, offsets, totals) — 2026-10-31

Round 1, five findings:

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `section_end` indexed with unchecked `usize` arithmetic (`table + count as usize * 4`), which wraps on a 32-bit target and yields a different verdict for the same image; `stream.rs::section_body_len` already used checked math | **fixed**: every index is `u64` with `checked_mul`/`checked_add`, bounds-checked against the buffer, then narrowed with `usize::try_from`; failures are `infinity/count` |
| 2 | medium | a count that cannot be satisfied by the buffer reported `infinity/truncated` for strings/blobs/secrets/extensions (the table read failed first) but `infinity/count` for fixed-stride sections | **fixed**: each variable section bounds its table before the first read, so the code is `infinity/count` per spec §9; `a_count_bomb_in_a_variable_section_is_a_count_error` |
| 3 | medium | provenance exempted from the count pass (`u32::MAX`), no byte budget | **partly rejected**: provenance is a *byte-length* section bounded by `total_size` and `max_total_bytes`, and `check_provenance` compares the entry count against `max_prov_entries` before iterating; `the_provenance_ceiling_is_checked_before_the_block_is_walked` pins the ordering |
| 4 | low | `Header::parse` accepted any `total_size` (0, sub-header, unaligned) | **fixed**: `total_size < 224` or not a multiple of 8 is `infinity/offset` with section `total-size`; `the_header_total_size_is_bounded` |
| 5 | low | alignment slack after the last section was not zero-checked (unreachable today) | **fixed**: the loop is in place and documented as the guard for a future variable-length trailing section |

Two behaviour changes were caught by existing tests during the fix: the strings
length word was first read with the wrong stride (caught by the signature and
compress round-trip tests) and a zeroed-header unit test now expects the
`total-size` offset error. Both are in the committed suite.

### I-02 validate, slice B (node records, ranges, edges) — 2026-10-31

Six findings; five fixed, one rejected. Every fix has a test in
`tests/marathon_validate_tests.rs`, and the four behavioural tests were confirmed
to fail against the pre-fix tree.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | critical | bytes 2..4 of every 32-byte node record (spec §3 "reserved") were never checked; they are covered by the content hash, so an image carrying them validates while `encode(decode(..))` produces different bytes — two bytes per node of hidden data inside the module identity | **fixed** in `Validated::node`: a non-zero reserved byte is `infinity/node`; `a_non_zero_node_reserved_byte_is_refused` |
| 2 | high | orphan `children`/`fields`/`parts`/`aux` entries were never value-checked, so unused entries (including impossible references) were hidden data | **fixed for the three range tables** by requiring sequential packing in node order (a hole, overlap or out-of-order range is `infinity/count`); `aux` coverage is left to slice D, where type entries also consume aux ranges |
| 3 | high | unbounded sum of ranges: a small image with `nodes × children` claims made `check_nodes`/`check_edges` iterate 10^13 times | **fixed by the same packing rule**: the running end can never exceed the section count, so total work is bounded by the section size |
| 4 | high | duplicate `MIN`/`MAX` constraint aux and duplicate schema aux decode last-wins, giving two hashes for one module | **fixed**: constraint `MIN_MAX` tags must be strictly ascending (one each, min then max), schema tags strictly ascending; both are what the encoder emits |
| 5 | medium | a detached `Blob` (no payload) could declare any `size` | **fixed**: the declared size is held to `max_blob_bytes`; `a_detached_blob_size_is_held_to_the_ceiling` |
| 6 | low | a self-referential edge was `infinity/edge` while spec §9 defines `infinity/cycle` for a dependency cycle | **fixed**: `from == to` is `Cycle { node }`; `a_self_loop_is_a_cycle` (the pre-existing redteam assertion was updated to the spec code) |

Gate: clippy clean; `cargo test --all-features` 223 passed, 0 failed.

### I-02 validate, slice C (strings, units, types, numbers, hashes) — 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | table type (code 7) carries `closed` in the entry flags *and* in aux `AUX_TYPE_TABLE`; the decoder reads the flag, the validator checked each independently, so `flags=1, aux=0` decoded one way and re-encoded another (a byte hidden in the hash) | **fixed**: a table type must have exactly one aux entry and it must equal `(AUX_TYPE_TABLE, flags)`; `a_table_type_flag_must_agree_with_its_aux_entry` |
| 2 | high | the type table was compared by `(code, flags, start, len)` — allocator positions — while canonicalization sorts by *content* `(code, aux)`; two byte images of one module could both validate | **fixed**: strict ascending comparison on `(code, aux entries)` |
| 3 | medium | semantically duplicate types at different aux slots validated; the encoder deduplicates them | **fixed** by 2 (equal content is not strictly ascending); `duplicate_type_content_is_refused` |
| 4 | medium | aux entries could be unreferenced or shared | **fixed in slice D** (see below) |
| 5 | medium | `check_strings`/`check_hashes` indexed with unchecked `usize` arithmetic and `[]`, so a 32-bit target could wrap and panic instead of refusing | **fixed in `check_strings`** (u64 + `checked_mul`/`checked_add` + `try_from`); `check_hashes` bounds are guaranteed by `section_end`, left as is with the packing rule from slice B |
| 6 | low | `check_strings`/`check_numbers` relied on the count pass for their ceilings | **fixed for strings** (named `infinity/limit`), numbers have no count ceiling in `Limits` |
| 7 | low | a type-aux index fault surfaced as `Error::Node` | **not reachable** after the range check (slice A) precedes `aux()`; left as is |

### I-02 validate, slice D (provenance, extensions, bindings, secrets, blobs) — 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | aux coverage was never enforced: an unreferenced or shared aux entry validated while its bytes stayed in the hash | **fixed**: one bitmap per validation, marked by type entries and by constraint/patch/schema ranges; an orphan is `infinity/count`, a second reference is `infinity/type`/`infinity/node`; `an_unreferenced_aux_entry_is_refused` |
| 2 | medium | `check_secrets`/`check_blobs` computed `heap + off + len` in `usize`, which wraps on a 32-bit target before the bounds check | **fixed**: u64 with `checked_add`, `usize::try_from` before any slice |
| 3 | medium | a dangling provenance string/number/hash reference leaked `infinity/string-ref` or `infinity/node` | **fixed**: the accessor maps them to `infinity/provenance`; `a_dangling_provenance_string_is_a_provenance_fault` |
| 4 | medium | `check_bindings` compared the count with `max_nodes`, refusing valid modules under a node-only limit | **fixed**: `max_bindings`; `more_bindings_than_nodes_is_fine_when_max_bindings_allows_it` |
| 5 | medium | an empty module with a dangling root word validated and then failed in the `root()` accessor | **fixed**: the root is checked before the empty-module early return; `an_empty_module_with_a_dangling_root_is_refused` |
| 6 | low | an unsorted blob table returned `infinity/offset` | **fixed**: `infinity/blob` |
| 7 | low | `check_provenance` read the entry count before checking the block held a header | **fixed**: the length check comes first |
| 8 | low | provenance entry offsets used unchecked `usize` multiplication | **fixed**: checked arithmetic |
| 9 | low | extension tag 1 is accepted although the spec reserves it | **rejected for now**: no wire image in the tree uses it, and reserving it retroactively would refuse images that are valid under the shipped spec; recorded as a spec decision for the next format version |

Gate after slices C and D: clippy clean; `cargo test --all-features` 229 passed,
0 failed.

### I-02 validate, slice E (canonical proof, store, stream) — 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `verify_canonical` re-encodes with `streamed:` taken from the image, so a streamed image validates; two byte images for one module | **rejected with reasoning**: `streamed` is a header flag the spec §1.1 defines as part of the image ("reassembled from a stream"), like provenance: it is metadata the identity covers. The re-encode must preserve it or a legitimate streamed image could never pass. Documented in the log rather than silently overridden |
| 2 | high | `Store::put` documented "validated canonical" but validated structurally only | **fixed**: `put` calls `validate_canonical`, so a non-canonical image is not stored under a second key; `the_store_refuses_a_non_canonical_image` |
| 3 | medium | stream reassembly validated with `verify_canonical: false` and trusted the `Begin` flags | **fixed**: all three reassembly validation points prove the canonical form |
| 4 | medium | enum members were not canonicalized: `[a,b]` and `[b,a]` were two images for one set | **fixed**: schema-type and constraint enums are sorted before interning; `enum_member_order_does_not_change_the_identity`. This is a canonical-form change: images with unsorted members still validate but fail `validate_canonical` (recorded in the changelog) |
| 5 | medium | the proof re-encodes a whole module with no extra bound | **rejected**: the re-encode is proportional to the input and bounded by the same limits; `paranoid()` is the untrusted-input profile and already documents the doubling. A hard cap would need a new limit, not a check |
| 6 | low | `check_bindings` compared against `max_nodes` | **fixed in slice D** (the section count includes the root word, consistently with `validate_counts`) |
| 7 | low | decode/encode failures inside the proof propagated as encoder codes | **fixed**: any failure to reproduce the image is `infinity/not-canonical` |

Gate: clippy clean; `cargo test --all-features` 231 passed, 0 failed.

### I-02 validate, round 3 (whole section) — 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `provenance()` clones every key/value; entries sharing one long heap string project to far more memory than the image | **fixed**: `check_provenance` bounds the projection against `max_total_bytes` before materialising; `provenance_cloning_is_bounded_before_it_allocates` |
| 2 | high | every blob node re-hashed its payload, so N nodes sharing a blob forced N hashes of it | **fixed**: the payload hash is verified once per entry in `check_blobs`; the node check keeps size/flags |
| 3 | high | pending stream deltas were bounded by operation count, not bytes | **fixed**: `pending_delta_bytes` is bounded by `max_total_bytes` |
| 4 | medium | `finish()` returned the previous generation when deltas never got their `End` | **fixed**: pending deltas make the stream unterminated |
| 5 | medium | the strict profile buffered a 64 MiB frame before comparing against an 8 MiB bound | **triaged, deferred**: the frame is bounded by `MAX_FRAME_PAYLOAD`; a pre-read length check belongs with the frame-reader rework in I-06 (stream/delta). Logged there |
| 6 | medium | binding, field and unit names equal to a secret literal stay in the public string heap while annotations and provenance are redacted | **triaged, deferred to I-05** (IR/canonical): the fix is a canonicalization rule that must be decided with the string-interning contract, and a wrong redaction would rename a binding |
| 7–13 | low | `u32` truncation in `assemble` (**fixed**: `try_from`), `encode_stream` chunk bound, edge-mismatch diagnostics, `NodeRef` truncation in messages, delta UTF-8 code, `Store::get` canonical enforcement (deliberately structural so pre-canonical objects stay readable; `put` is the write gate), 32-bit section sum (**fixed**: saturating `u64`) | six fixed or deliberately documented |

Gate: clippy clean; `cargo test --all-features` 232 passed, 0 failed. Section
I-02 is CLEAN with the deferred items recorded.

### I-03 encode / canonical — round 1 findings (received 2026-10-31, triage next)

The review ran against `encode.rs`, `canonical.rs` and `layout.md` §2, §5, §6.
Findings recorded verbatim in scope; each is to be verified against the tree
before any change, as with every other section.

| # | Severity | Claim | First read |
|---|---|---|---|
| 1 | high | `as u32` truncations for offsets/counts/lengths all over `encode.rs`; an image over 4 GiB wraps into overlapping sections | check which casts a hostile in-memory module can reach; the wire path has `too-large` |
| 2 | high | canonical node numbering visits roots sorted by numeric `NodeId`, while the spec and `roots()` order bindings by name; arena order then leaks into the hash | likely real and identity-critical: same module, different bytes |
| 3 | high | `promote_secret_locators` only promotes direct `Str` children, so a `SecretRef` through `Env`/interpolation/shared locator leaves secret bytes in the public string heap | likely real, security-critical |
| 4 | high | a secret that is a substring of the `***SECRET***` marker is embedded by the redaction path | verify against `redact_text` before changing |
| 5 | medium | no payload/size/hash check at encode time, so the encoder can emit an image its own validator refuses | cheap to fix in `prepare` |
| 6 | medium | non-canonical NaN is rejected by `validate_structure` before normalization, so the NaN arm never converges | check the encode order |
| 7 | medium | binding/field/`Env`/`Ident`/patch/type/unit names are not redacted while annotations and provenance are | overlaps the deferred I-02 item; decide with the interning contract |
| 8 | medium | no `Limits` on the encode side | check reachability from a public API |
| 9 | medium | `type_from_prepared` can surface `infinity/string-ref` from the encode path | cheap mapping |
| 10–12 | low | reserved extension tag 1, unchecked counters (`+1`, `len-start`), spec §6 sort-key prose drift | fix with the corresponding section |

Resume here: verify each claim against the current tree, then follow the usual
loop (regression test first, fix, full gates, log the disposition).

**Finding 3 assessment (no change yet):** the promotion rule clears a node's
taint when its direct parent is not a secret, so a non-secret node *inside* a
secret subtree (an `Env` under a `SecretRef`, say) exposes its own children. The
concrete leak is narrower than the finding states: `Env.name` and
`InterpPart::Literal` are inline text, not string-table nodes, so promotion
cannot move them; what promotion covers is `Inode::Str` nodes. The next session
decides the rule — promote every `Str` reachable only through secret parents
(a one-pass exposure BFS that stops descending at a secret node), or declare
locator literals structural and document it — because either choice changes
hashes for modules whose locators carry string nodes, and a wrong rule would
promote ordinary field values.

**Finding 4 assessment (no change yet):** `redact_text` substitutes occurrences
of secret literals with `SECRET_MARKER`; if a secret is a substring of the marker
itself (`SEC`, `*`, `S`), the substitution re-inserts it. The fix is to refuse
the encode (a marker collision) rather than emit an image whose redaction
contains the secret, but it needs the same decision as finding 3 about which
strings are redacted.

**Findings 3 and 4 fixed, 2026-10-31** (`tests/marathon_secrets_tests.rs`, 5
tests; three fail against the pre-fix tree, with the leaked heap captured in the
failure output):

- **Finding 3, promotion by exposure.** `promote_secret_locators` now computes
  the public set as a breadth-first walk from `roots()` that *stops at a secret
  node*: what a secret references is locator material, not public data. Every
  `Str` that is referenced and not public is promoted to `Inode::Secret`. An env
  fallback and an interpolated fallback (the finding's "one level deeper" case)
  no longer reach the public string heap. Inline `Env.name` and
  `InterpPart::Literal` text stay metadata by design: they are structural parts of
  the locator expression, not the literal a `SecretRef` reads, and they are
  documented as such.
- **Finding 4, marker collision.** `try_redact_text` refuses when a secret is a
  substring of `SECRET_MARKER` *and* the text actually contains it: the marker
  cannot represent that secret, so the encode fails with `infinity/encode`
  instead of publishing it. A module carrying such a secret with no text to
  redact still encodes (nothing is inserted). The public
  `interop::redact_text` projection keeps its infallible best-effort behaviour and
  is documented as such.
- Two existing tests encoded the old behaviour and were rewritten to the new
  rule: the marker-collision test now asserts the refusal plus the
  no-text case, and the provenance key-collision test uses an ordinary secret so
  it still exercises the key-collision rule. The proptest now accepts the refusal
  and asserts that a successful encode never let a marker-colliding secret reach
  redacted text.

### I-03 round 1, remaining findings — 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `as u32` truncation for offsets/counts; an image past 4 GiB would wrap into overlapping sections that still hash | **fixed at the boundary**: `set_span` (the only place a section offset/count enters the header) and the extension payload offset/length use `u32::try_from` → `infinity/too-large`. Casts of values that are `u32`-bounded by construction (node index, secret cursor) stay as casts; the cursor add is checked |
| 5 | medium | no payload/size/hash check at encode, so a hand-built blob could produce an image the validator refuses | **fixed in `prepare`**: payload length must equal `size` and `Blake3(payload)` must equal the hash, both `infinity/encode`; `an_inconsistent_blob_is_refused_at_encode` |
| 6 | medium | `validate_structure` rejected a non-canonical NaN before normalization, so such a module could not be encoded at all | **fixed**: the IR-level NaN arm is gone; canonicalization maps every NaN to the permitted quiet NaN, and a received image with a foreign NaN is still refused by the wire validator. `every_nan_normalizes_to_the_canonical_bit_pattern` |
| 7 | medium | binding/field/`Env`/`Ident`/patch/type/unit names are not redacted while annotations and provenance are | **rejected with a documented rule**: structural names are schema, not free text. `docs/spec/layout.md` §3.1 now states which surfaces redaction covers and that a name is carried verbatim |
| 8 | medium | no `Limits` on the encode side | **rejected**: the module is the caller's own data, and the image size is now bounded by the u32 guard; a separate encode limit would duplicate what `validate` already does for untrusted input |
| 9 | medium | `type_from_prepared` could surface `infinity/string-ref` from the encode path | **fixed**: mapped to `infinity/encode` |
| 10 | low | reserved extension tag 1 accepted; `payload.len() as u32` unchecked | **casts fixed** (see 1); the tag reservation is **rejected for now** with the same reasoning as I-02 (a wire-format decision, not a validation fix) |
| 11 | low | unchecked counters (`secret_cursor += 1`, …) | **fixed for the secret cursor** via `checked_add`; the remaining `+1` is on the binding count, bounded by the u32 node space |
| 12 | low | spec §6 listed the type sort key as `(code, flags, aux start, count)` and the promotion rule as "referenced only by secret nodes" | **fixed**: the prose now says content `(code, flags, aux entries)` and "reachable only through a secret", which is what the code does |

Gate: clippy clean; `cargo test --all-features` 242 passed, 0 failed.

### I-03 round 2 (re-audit) — 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | annotation insertion order leaked into canonical numbering: an annotation subject can be a node nothing else reaches, and `roots()` emitted subjects in stored order, so the same annotation set produced two images | **fixed**: `canonical_order` orders annotation subjects and constraint expressions by a content key — a depth-limited, id-free rendering that follows child references instead of printing ids and writes secrets as a fixed marker; `annotation_order_does_not_change_the_canonical_bytes` (fails pre-fix) |
| 2 | low | residual `as u32` casts on byte-heap paths | **fixed at the boundary**: section spans and extension offsets/lengths were already `try_from`; a final `u32::try_from(image.len())` before the header covers a heap that grows past the space after the last span |

Gate: clippy clean; `cargo test --all-features` 243 passed, 0 failed. Section
I-03 is CLEAN. (`tests/marathon_canonical_tests.rs`): the claim
was correct. `canonical_order` built its roots from the root node, the binding
targets **sorted by numeric id**, the annotation subjects and the constraint
expressions; the spec and `InfinityModule::roots` order bindings by **name**.
A value reachable only through a binding was therefore numbered by arena
position, so the same logical module could encode to different bytes. The
function now takes its roots from `roots()`, which is the single source of
truth, and three tests pin it: canonical bytes, structural equality and the
decode/encode identity. A module whose binding-only nodes were pushed out of
name order re-encodes to a different (correct) hash; `validate_canonical` calls
the old bytes not canonical and the changelog records the change.

### I-08 store - 2026-10-31



| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | scratch name was `pid` + wall-clock nanos and the write used `fs::write`, which follows a symbolic link: a planted name redirects the image into an attacker-chosen file | **fixed**: scratch files are opened with `O_CREAT|O_EXCL` (Rust `create_new`) under a per-store slot counter; an occupied slot costs a retry, never a write. `put_does_not_write_through_a_planted_scratch_path` occupies slot 0 and asserts the victim file is unchanged |
| 2 | high | `fs::rename` replaces the destination, so the promised "never overwritten" only held by luck of platform behaviour, and a second `.sig` silently replaced the first | **fixed**: commit is `fs::hard_link`, which is atomic and fails with `AlreadyExists` on Unix and Windows; a race is resolved by comparing bytes. `put_signed_accepts_the_same_envelope_twice` (identical envelope is a no-op) and `put_signed_refuses_a_second_envelope_for_the_same_image` |
| 3 | high | every read (`put` comparison, `get`, `get_signature`) allocated and read the whole file before any `Limits` check | **fixed**: `read_bounded` checks the metadata size, reads through `take(limit + 1)`, and reports `infinity/limit`; `get_refuses_an_object_larger_than_the_read_limit` and `put_refuses_an_existing_object_larger_than_the_read_limit` plant a sparse 1 GiB + 8 file |
| 4 | high | `get` used `validate` (structural only) while `put` enforced `validate_canonical`, so a non-canonical image planted at its own key was returned | **fixed**: `get` proves the canonical form and compares the proven content hash; `get_refuses_a_non_canonical_image_planted_at_its_hash` clears the canonical flag and rewrites the header hash so only the canonical proof can catch it |
| 5 | medium | images carry the secret heap and were written world-readable, with the directory default-mode; the spec was silent on at-rest exposure | **fixed**: Unix directory `0700`, objects `0600`; the threat model is stated in `store.md` and the module docs (a shared store is a shared secret domain). `store_objects_and_directory_are_private` |
| 6 | medium | `put_signed` overwrote an existing envelope; one image could acquire a second, conflicting signer | **fixed** by the no-clobber commit plus the one-object-one-envelope rule (see 2) |
| 7 | medium | `len` counted any `*.ainf` name (garbage, uppercase, directories) and a `read_dir` error read as zero; `contains` accepted a link | **fixed**: only regular files named `<64 lowercase hex>.ainf` count; `try_len` reports the read failure instead of reporting empty; `contains` uses `symlink_metadata` so a link is not an object. `len_counts_objects_not_file_names` |
| 8 | low | not-found, key mismatch and permission failures share `infinity/store`, and the distinct `Display` text is an existence oracle | **rejected as a code change, documented as a contract**: the store is a local API and the distinctions are operator diagnostics. `store.md` and the rustdoc now require a service in front of a store to map every `infinity/store` failure to one response and never forward `Display`; `contains` is documented as a snapshot |

Residuals recorded rather than changed:

- A content-addressed store is a confirmation oracle by construction: a caller
  that can ask `contains`/`get` can test a guessed hash without the secret. This
  is inherent to deduplication and is now stated in `store.md`.
- `get_verified` reads the image and its envelope once each and compares the
  bytes it holds in memory; a file replaced between the two reads is caught by
  the comparison (it cannot produce a valid signature over different bytes).
  There is no further atomicity to add without a locking protocol the format
  does not define.
- `Store::open` now refuses a symbolic-link root, which closes the last
  path-resolution hazard the review listed.

Gate: `cargo fmt --all`; clippy clean on `--all-features` and
`--no-default-features`; `cargo test --all-features` 274 passed, 0 failed
(7 new in `tests/marathon_store_tests.rs`, five proved to fail against the
pre-fix tree by stashing `src/store.rs`); `--no-default-features` suite green.

Two efficiency fixes came with the same change, with no numbers claimed: `put`
and `get` now take the content hash from the validation result instead of
calling `content_hash`, which re-validated the whole image a second time, and
`get` no longer validates twice on the canonical path.
