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
| I-09 | compress | `src/compress.rs`, CLI `dict` | **CLEAN** | 6 fixed, 4 rejected/documented | this commit |
| I-10 | signature / proof | `src/signature.rs`, `src/proof.rs` | **CLEAN** | 6 fixed, 2 rejected/documented | this commit |
| I-11 | merge | `src/merge.rs` | **CLEAN** | 7 fixed, 1 rejected | this commit |
| I-12 | interop / protobuf | `src/interop.rs`, `src/protobuf.rs` | **CLEAN** | 6 fixed, 1 rejected | this commit |
| I-13 | error codes | `src/error.rs` | **CLEAN** | 6 fixed, 2 rejected | this commit |
| I-14 | FFI | `ffi/**` | **CLEAN** | 12 fixed, 3 documented | this commit |
| I-15 | CLI | `cli/active-infinity-cli/**` | **CLEAN** | 13 fixed, 2 documented | this commit |
| I-16 | fuzz targets | `fuzz/**` | **CLEAN** | 11 fixed, 2 documented | this commit |

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

### I-09 compress - 2026-10-31

Reviewer probed the surface directly (level clamping, empty input, dictionary
acceptance, magic confusion) before reporting.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `decompress_with_dictionary` accepts a frame that never used the dictionary, so a caller could mistake "dictionary decode succeeded" for proof of the producer | **rejected as a code change, closed in the contract**: a dictionary is a compression hint in zstd; enforcing a frame dictionary id would change the wire contract and break plain frames. The module docs and `docs/spec/streaming.md` §6 state the rule, and `a_dictionary_is_a_hint_not_a_gate` pins it so nobody "fixes" it into a trust boundary later |
| 2 | high | CLI `dict train` computed `size * 4`, which panics in debug and wraps in release; `--size 2^62` wraps to zero and bypasses the corpus guard, handing zstd an impossible allocation | **fixed**: `checked_mul` with a usage error; `dict_train_refuses_a_size_whose_bound_would_wrap` (pre-fix exit 101, now 2) |
| 3 | medium | CLI `--level` was `usize as i32`, so `2^40` silently became level `0` | **fixed**: `i32::try_from` plus the library's level range, usage error; covered by `dict_apply_refuses_an_impossible_level_and_ceiling` |
| 4 | medium | CLI `read` was an unbounded `read_to_end`, so a multi-GiB path (including `store put --sign`) allocated before any check | **fixed**: every input file is size-checked and read through `take(ceiling + 1)`; `an_input_above_the_ceiling_is_refused_before_it_is_read` |
| 5 | medium | library caps absent: `max_output`, `max_size` and dictionaries pass through to zstd allocations | **partly fixed**: `train_dictionary` refuses a zero ceiling and an empty sample set; `max_output` and the dictionary are documented as caller-chosen allocation ceilings with the codec ceiling as the image value. No arbitrary cap was invented for a parameter the caller owns |
| 6 | medium | compressing secret-bearing images with attacker-influenced neighbours and observable length is a CRIME-style oracle; the security spec was silent | **fixed in docs**: `docs/spec/security.md` §4 records the oracle and directs callers to compress the redacted projection |
| 7 | medium | empty input decoded to empty output, and the CLI wrote an empty file with exit 0 | **fixed**: both decompressors refuse empty input with `infinity/compression`; `empty_input_is_not_a_frame` |
| 8 | medium | CLI `dict apply --decompress` writes plaintext without `validate` | **rejected**: `dict apply` is a byte-level compression helper for arbitrary payloads (its help says hashes stay over uncompressed bytes); validating would break non-image use. `validate` remains a separate command |
| 9 | low | compression levels were silently clamped | **fixed**: `level_range()` exposes the build's zstd range, out-of-range values are `infinity/invalid-argument`; `an_out_of_range_level_is_refused` |
| 10 | low | `docs/spec/streaming.md` had no compression section | **fixed**: §6 states identity over uncompressed bytes, the mandatory output ceiling, empty-input refusal, level range, the dictionary hint rule and the oracle warning |

Residuals: a caller that passes an enormous `max_output` still asks zstd for
that allocation (documented as the caller's ceiling); the CLI read ceiling is
the codec image ceiling plus envelope slack, so a legitimate non-image payload
larger than 1 GiB cannot be passed through `dict apply`.

Gate: clippy clean on both feature sets; Infinity 278 passed all-features /
227 no-default; CLI 15 passed; the three refusal tests fail against the pre-fix
tree (library probe with a documented `level_range` shim, CLI with `main.rs`
stashed).

### I-10 signature and proof - 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `SignedImage::sign`/`verify` used structural `validate` while the store and proof require the canonical form: an envelope could certify bytes no store accepts and no producer reproduces | **fixed**: both prove `validate_canonical`; `sign_refuses_a_non_canonical_image` (signing) and `from_bytes_refuses_a_non_canonical_envelope` (an envelope built by hand over doctored bytes) |
| 2 | high | `from_bytes` copied `bytes[101..]` with no ceiling and `verify` built a second `DOMAIN || image` buffer, so a fabricated ~1 GiB `.sig` forced multi-GiB transient memory | **fixed**: the envelope length is checked against the codec ceiling plus its fixed header before the image is copied (`infinity/limit`); the message buffer remains one allocation by construction. `from_bytes_refuses_an_oversized_envelope_before_copying_it` |
| 3 | high | envelope parse surfaced the inner image code (`infinity/header-truncated`, `infinity/hash-mismatch`, …), and the old test enshrined it, so a monitor watching `infinity/signature` missed rejected envelopes | **fixed**: every image fault during parse/verify is `infinity/signature`; `from_bytes_maps_every_image_fault_to_the_signature_code`, and `put_signed_refuses_a_corrupted_image` was rewritten to the one-code contract |
| 4 | medium | the CLI read input files unbounded before any limit | **fixed in I-09** (one bounded `read` for the whole CLI); recorded here so the finding is not lost |
| 5 | medium | `Proof::from_json` ignored unknown fields, so a smuggled key could ride on a sidecar that verifies | **fixed**: exactly the eleven `active-infinity/proof/1` fields are accepted; `a_sidecar_with_an_unknown_field_is_refused` |
| 6 | medium | `get_verified` compared `signed.image != image` with early-exit `Vec` equality over secret-bearing bytes (a length-dependent timing signal), on top of two unlocked reads | **fixed**: the comparison is gone. `get` proves the image hashes to `hash` and `get_signature` proves the envelope's image does too, so byte equality follows from the content hash. The two-read race stays a residual: a swap is caught by the hash check and fails closed |
| 7 | low | proof rejection messages distinguish which check failed (hash vs metadata vs schema) | **rejected as a code change, documented as a contract**: the distinctions are operator diagnostics. The module docs and `authenticity.md` now require a service that verifies attacker-supplied sidecars to answer with one fixed response and never forward `Display` |
| 8 | low | `dialect_hash`/`size` are JSON numbers; a JavaScript verifier loses precision past 2^53 | **fixed on the parse side**: an integer field may be a decimal string, so a precision-limited producer round-trips exactly. `a_u64_field_may_arrive_as_a_decimal_string`. Emitting strings stays a v2 format decision |

Also fixed while there: `SignedImage`'s derived `Debug` printed the image (the
secret heap included) as decimal bytes; the manual form prints the image length,
the public key and the signature prefix. `the_debug_form_does_not_print_the_image`.
`Store::put_signed` reuses the hash returned by `put` instead of validating the
image a third time.

Residuals: the CLI still parses a signing seed from `--seed` hex and holds it in
argv/heap memory; zeroizing one copy would not remove the others, and a real fix
is a key-handling design (file descriptor, agent socket), not a line of code.
Envelope replication and the absence of a transparency log remain as recorded in
`authenticity.md`.

Gate: clippy clean on both feature sets; Infinity 285 passed all-features / 227
no-default; CLI 15; doc gates 15. Five signature tests and both proof tests fail
against the pre-fix tree (`src/signature.rs` then `src/proof.rs` stashed).

### I-11 merge - 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `import_subtree` cloned the whole right arena and `merge_fragment` appended every node, so k takes grew the arena by k x N with no ceiling | **fixed**: `subtree_fragment` materialises only the reachable cone of the taken root (post-order, shared children once) and the imported total is charged against `MAX_MERGE_NODES`. `the_import_budget_refuses_two_takes_of_a_shared_cone` (fails pre-fix) |
| 2 | high | every comparison cloned and encoded the whole module, so F fields cost O(F x N) despite the node ceiling | **fixed**: cone-only comparison, plus a total visit budget (`MAX_MERGE_WORK`, 16 x `MAX_MERGE_NODES`). Measured on a 60 000-node arena with 1 000 fields: 62.46 s before, 107.4 ms after (release, same machine, temporary harness removed) |
| 3 | medium | dotted paths were unescaped, so a field named `a.b` was indistinguishable from a nested `a.b`, and a field named `<bindings>` from the metadata marker | **fixed**: `escape_field` escapes `\`, `.` and a leading `<`; `a_field_name_with_a_dot_is_escaped_in_the_path`, `a_field_name_named_like_a_metadata_marker_is_escaped` |
| 4 | medium | when the base was a non-table and both sides turned the field into a table, the walk descended and reported `server.port` as `AddAdd` instead of `server` as `ModifyModify` | **fixed**: the walk refuses to descend when the base node is not a table; `a_non_table_base_is_not_descended_into` |
| 5 | medium | metadata ignored the base (a one-sided provenance/extension change always conflicted), and raw text comparison was a secret-equality oracle | **fixed**: bindings, provenance and extensions are base-aware (one-sided changes are adopted), and provenance/annotation text is compared redacted. A non-UTF-8 extension payload next to a secret is a conflict rather than a comparison. `a_binding_added_on_one_side_is_adopted`, `a_provenance_changed_on_one_side_is_adopted`, `a_one_sided_extension_is_adopted`, `a_provenance_changed_differently_on_both_sides_conflicts`, `provenance_text_is_compared_redacted` |
| 6 | medium | annotation comparison zipped stored order (spurious conflict on reorder) and compared intent/constraint text raw | **fixed**: order-insensitive keys, redacted text; `annotations_in_a_different_order_do_not_conflict` |
| 7 | low | `removed.contains` was O(F^2) and conflict paths had no ceiling | **fixed**: `BTreeSet` for removals; total escaped path bytes capped at 1 MiB (`infinity/limit`) |
| 8 | low | a dangling/cyclic input failed late with an inconsistent code, and the "merged root disappeared" case was mapped to a retryable `InvalidArgument` | **fixed**: `validate_structure` runs on all three inputs first (`infinity/node-ref` / `infinity/limit`), and the internal case is `infinity/encode`; `a_dangling_reference_is_refused_before_any_comparison` |

Annotations remain all-or-nothing (a difference is `<annotations>`): an
annotation has no name to merge by, and a set union would let two sides that
each replaced the same annotation keep both. The ADR records the decision.

The metadata vectors changed accordingly: `metadata` is now a clean adoption
with its merged golden, and a new `binding` vector pins the
`conflict:<bindings>:KindMismatch` case.

Gate: 25 merge tests, 9 marathon tests; Infinity 302 all-features / 242
no-default; clippy clean both feature sets.

### I-12 interop and protobuf - 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | critical | `interop::to_active_core` lowered `Inode::Secret` to `CoreValue::Secret(plaintext)`, a full structural-secret export through a public, default-feature API (and the facade glob) | **fixed**: the bridge refuses a secret-bearing module (`infinity/encode`). `active-core` 1.4.0 models a secret as a plain string, so there is no lossless structural form. `the_bridge_refuses_a_secret_bearing_module` (fails pre-fix); the two integration tests that bridged the fixture now use a secret-free copy and assert the refusal |
| 2 | high | a 32-byte secret copied into `Provenance.parent` or `ProvValue::Hash` reached the image verbatim and the projections as raw bytes/hex | **fixed**: the encoder refuses a hash copy, the JSON and `provenance_lines` projections substitute the marker for a matching hash in a hand-built module, and the extension payload copy is refused at encode as well as at projection. `a_provenance_parent_equal_to_a_secret_is_refused_at_encode`, `a_provenance_hash_entry_equal_to_a_secret_is_refused_at_encode`, `an_extension_payload_copying_a_secret_is_refused_at_encode`, `a_provenance_hash_equal_to_a_secret_is_redacted_in_json`, `provenance_lines_redacts_a_hash_equal_to_a_secret` (all fail pre-fix) |
| 3 | high | `provenance_pairs` is a public raw accessor over `ProvEntry` | **rejected**: `InfinityModule::provenance()` already returns the same `&Provenance` with public fields, so making the helper crate-private would not remove the read path. A decoded module's text is already redacted by canonicalization; a hand-built module's provenance is the caller's own data. The rule that matters (a secret copy never reaches an image or a projection) is closed by finding 2 |
| 4 | medium | the extension secret scan was O(secrets x payload) with no budget | **fixed**: one 64 MiB comparison budget for the whole projection (`infinity/limit`) |
| 5 | medium | `to_protobuf` had no byte ceiling; a shared DAG expanded into a tree bounded by nodes, not bytes | **fixed**: `MAX_PROTOBUF_BYTES` (1 GiB), checked after each section and after each value body (`infinity/limit`) |
| 6 | low | `resolves_to_secret` walks were not charged to the projection budget | **fixed**: the taint walk takes the shared `PROJECTION_NODE_BUDGET` counter and returns `infinity/encode` on exhaustion |
| 7 | low | `tests/projection_tests.rs` covered remapping, not projections | **fixed**: renamed to `tests/remap_tests.rs` |

Residual: the Protobuf byte cap bounds the final vector and each section body,
while the node budget (100 000) is the expansion bound; a single value body can
still approach the cap before it is refused. A secret that is a substring of the
marker is refused at encode (I-03), so the marker-substitution path stays a
fixpoint.

Gate: Infinity 302 all-features / 242 no-default, CLI 15, clippy clean both
feature sets, doc gates green.

### I-13 error codes - 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `infinity/evaluation` was returned by `code()` but missing from the spec table and the waiver list; the evaluator's class was hidden in `Display`, forcing message parsing | **fixed**: the code is documented in `layout.md` §9, `Error::sub_code()` returns the class, and the code is waived in the conformance gate as a non-image class. `only_an_evaluation_error_carries_a_sub_code` |
| 2 | high | `is_fatal()` was `!InvalidArgument`, so `Limit`, `Store`, `Encode` and `Evaluation` were reported as corrupt-input faults | **fixed**: an explicit match implements the documented rule (structure/framing/hash/canonical/stream-frame faults are fatal; limit, argument, evaluation, schema, compression, store, signature, proof, encode and stream protocol are not). `the_fatal_classification_matches_its_documented_rule` (fails pre-fix) |
| 3 | medium | a delta string with invalid UTF-8 reported `infinity/utf8`, a string-heap code | **fixed**: `infinity/stream-delta`; `invalid_utf8_in_a_delta_string_is_a_stream_delta` (fails pre-fix) |
| 4 | medium | `From<Utf8Error>` discarded the offset and always reported 0 | **fixed**: `valid_up_to()` is carried |
| 5 | medium | a delta annotation string over the u16 space reported `infinity/too-large` ("4 GiB address space") | **fixed**: `infinity/stream-delta` with a delta-specific message; `an_oversized_delta_annotation_is_a_stream_delta` (fails pre-fix) |
| 6 | low | `Header::try_write` on a short buffer reported `infinity/encode` | **fixed**: `infinity/invalid-argument`; `a_short_header_buffer_is_an_invalid_argument` (fails pre-fix) |
| 7 | low | an unreferenced aux entry reports `infinity/count` | **rejected**: the aux table's declared count and its referenced set disagree, which is a count/coverage fault; the message names the table. A dedicated variant would add a public enum arm for a diagnostic nuance |
| 8 | medium | the code gates were one-directional (25 of 51 codes checked, no uniqueness test) | **fixed**: a unit test enumerates every variant, asserts code uniqueness and that each code appears in `layout.md`; the conformance gate now covers the new codes and the FFI annex |
| 9 | low | a frame checksum reports `infinity/hash-mismatch`, a frame flag fault `infinity/flags` | **rejected with a documentation note**: the streaming spec assigns those codes deliberately so a file and a stream share one vocabulary; the caller knows which layer it is reading |

Gate: 5 integration tests (3 fail pre-fix) plus 3 new unit tests (fatal
classification fails pre-fix); Infinity suite green in both feature sets.

### I-14 FFI - 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `alloc(len)` had no cap, no `try_reserve` and no panic guard: `SIZE_MAX` panicked into C or aborted | **fixed**: 1 GiB cap, `try_reserve_exact`, `catch_unwind` returning NULL with `infinity/limit` / `infinity/panic`. `alloc_refuses_an_impossible_request` |
| 2 | high | `CStr::from_ptr(name)` scanned without a bound: an unterminated name read past the caller's buffer | **fixed**: a byte-wise scan bounded at 4096, `infinity/name-too-long`; `an_unterminated_name_is_refused_without_an_unbounded_scan` (fails pre-fix) |
| 3 | high | `free` reconstructed the `Vec` with the caller's length; a wrong length or a double free was heap UB | **partially fixed as far as a C ABI allows**: `alloc` writes a 16-byte tag (magic + length) ahead of the payload, `free` verifies it and refuses a wrong length (leaking one buffer instead of corrupting the heap), and clears it before freeing. A double free, a foreign pointer or use-after-free remains UB, which the header now states together with the null-after-free rule. `free_checks_the_length_it_is_given` |
| 4 | medium | an output call that succeeded left the previous failure in `last_error` | **fixed**: `infinity/ok` on every output success; `success_reports_ok_after_a_failure` (fails pre-fix) |
| 5 | medium | `last_error` lifetime was described as "until the next failing call", inviting a retained pointer | **fixed in the header and crate docs**: copy immediately, the pointer is released by the next call on the thread |
| 6 | medium | a misaligned `out_len` was dereferenced | **fixed**: `infinity/out-len-misaligned` before any access; `a_misaligned_out_len_is_refused` |
| 7 | medium | `from_active` parsed an unbounded source | **fixed**: 16 MiB ceiling (`infinity/limit`); `an_oversized_source_is_refused_before_parsing` (fails pre-fix) |
| 8 | medium | the FFI had no canonical-proof entry point, so dedup and signature consumers could not ask the question | **fixed**: `active_infinity_validate_canonical` exported and in the header; `validate_canonical_is_stricter_than_validate` |
| 9 | medium | `version()` reported the shim's 0.1.0, not the codec version | **fixed**: `version()` returns the codec version, `ffi_version()` the shim; `version_reports_the_codec_and_the_shim` (fails pre-fix) |
| 10 | medium | FFI-only codes were undocumented | **fixed**: `layout.md` §9.1 lists every shim code and the conformance gate waives them as non-image classes |
| 11 | medium | `alloc` and the error setter were outside the panic guard | **fixed for `alloc`** (catch_unwind); `set_error` still allocates, and an allocation failure aborts the process in stable Rust. Documented as a residual |
| 12 | low | a zero-length output with a null buffer reported `buffer-too-small` | **fixed**: empty output is `0` with `infinity/ok` |
| 13 | low | `(null, 0)` reports `header-truncated`, `(null, 16)` reports `null-input` | **documented, not unified**: an empty buffer really is a truncated image, and a null pointer with a non-zero length really is a caller fault; the two conditions differ |
| 14 | low | `content_hash` has a fixed 32-byte output with no negotiation | **documented** in the header: the ABI fixes the width, and the caller must provide 32 bytes |
| 15 | low | the WASM fill called the host import for an empty buffer with a dangling pointer | **fixed**: empty fill returns without importing |
| 16 | low | the header/EXPORTS tripwire only checked one direction | **fixed**: both directions are compared exactly; `the_header_and_the_export_list_agree_in_both_directions` |

Residuals: the FFI pins the default (non-paranoid) `Limits` and has no
`*_with_limits` variant; a WASM trap or a C++ exception bypasses the `-3`
contract (neither is a Rust panic); stable codes remain an adaptive-probing aid
by design. `set_error` allocation failure aborts.

Gate: 18 FFI tests (the version, success-ok, unterminated-name, oversized-source
and fatal-classification cases fail against the pre-fix shim; the alloc-cap test
cannot be run pre-fix because it allocates a gigabyte). WASM
`wasm32-unknown-unknown` release build green; Infinity suite green.

### I-15 CLI - 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `stream` read `args[2]`, so `stream <file>` always failed | **fixed**: the command parses its own arguments like every other one; `stream_reassembles_a_valid_stream` (fails pre-fix) |
| 2 | high | `--sign SEED_HEX` put the seed on argv, visible to other processes, and the parsed array was never cleared | **fixed**: `--sign-file` and `ACTIVE_INFINITY_SIGN_SEED` are the preferred sources, the parsed `[u8; 32]` is zeroized after signing, and the help/man explain the exposure. `a_signing_seed_can_come_from_a_file` |
| 3 | medium | `bench --iterations` was unbounded (`Vec::with_capacity(N)`) | **fixed**: 1..=1_000_000, otherwise a usage error; `strict_arguments_are_usage_errors` |
| 4 | medium | `fs::read_to_string` for source, proof sidecar and manifest, and `fs::read` for conformance cases, bypassed the input ceiling | **fixed**: each has its own ceiling (16 MiB source, 16 KiB sidecar, 1 MiB manifest, image ceiling for cases) through one bounded reader and a 1 MiB reserve cap |
| 5 | medium | `limits_from` used `as u32` (wrap), ignored malformed pairs and never applied limits to `valid` cases | **fixed**: `try_from`, malformed/unknown entries are errors, and `valid` cases validate and decode under the declared limits |
| 6 | medium | the conformance base was `manifest.parent().parent()`, so a manifest outside `conformance/` lost its cases, and a case path could escape the directory | **fixed**: the base is the manifest's own directory and absolute or `..` case paths are refused; `conformance_uses_the_manifest_directory_as_its_base`, `a_conformance_case_cannot_escape_the_manifest_directory` |
| 7 | medium | `write_output` truncated in place, followed a symlink, had no input==output guard and no private mode | **fixed**: a `create_new` temp in the same directory, `sync_all`, an atomic rename (which replaces a link entry, not its target), 0600 on Unix, and `ensure_distinct`; `an_output_that_names_the_input_is_refused` |
| 8 | medium | `flag_number` and `parse_hash` errors lacked the `usage:` prefix, so a bad value exited 1 | **fixed**: every argument error is `usage:` (exit 2), including a bad number and a bad hash |
| 9 | medium | the default `store get` is integrity-only and the docs did not say so | **fixed**: `store get` prints a note when a stored signature exists but `--verify` was not passed; the man page, README and help make `--verify` explicit. `a_signed_object_is_flagged_when_verification_is_not_requested` |
| 10 | medium | no arity or flag strictness: extra positionals and flags were ignored, and a flag without a value silently defaulted | **fixed**: `check_flags` / `check_positional` on every command and a `split_args` that refuses a missing value, a duplicate flag and an unknown flag; `strict_arguments_are_usage_errors` |
| 11 | low | `split_args` and `arg_value` disagreed (first vs last value, silent defaults) | **fixed**: one parser, duplicate flags refused, values passed through `flags` |
| 12 | low | `read` reserved the declared file size (a sparse 1 GiB file reserved a gigabyte) and truncated on 32-bit | **fixed**: reserve is capped at 1 MiB and the cast is `try_from` |
| 13 | low | the man page said 0.2.0 and omitted `store signature`, `--sign/--verify/--key` and the `--output` flags; exit-status prose was wrong | **fixed**: the man page is current and a test pins the version, the command list and the new flags against the binary |
| 14 | low | conformance I/O and aggregate errors carried no `infinity/...` code | **documented, not changed**: a CLI I/O failure is not a codec failure; the man page now says which exit-1 messages carry a code and which are plain I/O text. A fabricated `infinity/…` code for a missing file would be misclassification |
| 15 | low | `hash`, `decode` and `bench` printed only the code, unlike `validate` | **fixed**: every codec failure prints `code: detail` |

Gate: 23 CLI tests (7 of the new cases fail against the pre-fix binary), CLI
clippy clean.

### I-16 fuzz - 2026-10-31

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `scripts/fuzz_docker.py` omitted `fuzz_compressed_frame`, so the documented Windows/MSVC lane never fuzzed decompression | **fixed**: the target is in `TARGETS`, the script has a `--check` mode, and `tests/fuzz_manifest_tests.rs` fails when the Cargo manifest, the script, either workflow, the README or the corpus index disagree (proved by removing the target) |
| 2 | high | `nightly.yml` duplicated the fuzz campaign with an older 8-target matrix and no artifact upload | **fixed**: the duplicate job is gone; `nightly.yml` keeps only the coverage floor and `fuzz-nightly.yml` is the canonical campaign |
| 3 | high | the PR fuzz job discarded crashing inputs | **fixed**: `ci.yml` uploads `fuzz/artifacts` on failure |
| 4 | high | `fuzz_compressed_frame` scaled its ceiling with the input and asserted nothing | **fixed**: fixed ceilings, a 1 MiB expansion bomb refused at 64 bytes with `infinity/compression`, a large-ceiling round trip, an identity round trip and a zero-ceiling check; 3,000 Docker runs pass |
| 5 | high | `fuzz_canonical_roundtrip` never toggled the build parity, so its order assertion was vacuous | **fixed**: the parity bit is flipped (with an explicit empty-input case) |
| 6 | high | `fuzz_unit_discriminants` discarded the result for valid units | **fixed**: a built-in unit must validate; `UNIT_NAMED` without its aux data must be refused with a stable code |
| 7 | high | `fuzz_graph_cycles` never validated its raw input | **fixed**: every input is passed to `validate` first (Ok decodes and encodes, Err starts with `infinity/`) |
| 8 | medium | `fuzz_stream_reassembly` accepted a corrupted stream that decoded to different bytes and ignored an incremental finish error | **fixed**: the built stream must decode, the split reassembly must finish, and a corrupted stream must be refused or byte-identical |
| 9 | medium | `fuzz_decode_infinity` walked up to 4M view nodes and skipped error-code checks | **fixed**: the walk is bounded at 4096 and every validate failure must carry an `infinity/` code |
| 10 | medium | `common.rs` helpers silently ignore out-of-bounds writes and leaks | **documented**: the helpers are best-effort and every caller re-checks by hashing (`rehash` returns false). A debug-only panic would fire on the partial buffers the harness deliberately constructs |
| 11 | medium | the secret/projection oracle projects an in-memory module | **partially fixed**: the target already re-projects `decode(encode(module))`; the in-memory projection is the stronger case (it runs before wire redaction). The raw `windows == hash` check stays: it asserts the advertised field without re-implementing the protobuf parser |
| 12 | medium | `fuzz_docker.py` aborted the campaign on one timeout, used a `-v` mount that can misparse a Windows path, and forwarded no libFuzzer limits | **fixed**: `TimeoutExpired` records a failure and continues, the mount is `--mount type=bind`, and `-timeout` / `-rss_limit_mb` are passed (`--libfuzzer-timeout`, `--rss-limit-mb`) |
| 13 | low | the fuzz docs said eight targets and 94 seeds; `doc_gate` did not cover them | **fixed**: README, CORPUS and STATUS say nine and 99, and the parity test covers the target lists and that every target has a seed |

Gate: `cargo check --manifest-path fuzz/Cargo.toml` clean; the nine-target Docker
campaign runs without a crash (2,000 runs each, `fuzz_compressed_frame` also at
3,000); `tests/fuzz_manifest_tests.rs` green and proved to fail when a target is
removed from the Docker lane.

### Re-audit loop, round 2 (I-01) and round 4 (I-02) - 2026-10-31

The user requires repeated rounds until no new critical/high/medium remains.
Each round re-reads the current tree, verifies the prior fixes and hunts deep
nested defects.

**I-01 round 2** (3 medium, 3 low):

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | medium | `Header::write` panics on a short buffer | **rejected**: it is the documented panicking form of `try_write` (the same contract as slice indexing); a caller sizing from untrusted input uses `try_write`, which returns `infinity/invalid-argument` |
| 2 | medium | `Section` had implicit discriminants while `span()` indexes by `as usize`; a future reorder would silently remap sections | **fixed**: explicit `= 0..=16` and a compile-time assertion that `Section::ALL[i] as usize == i`; `the_wire_section_order_matches_its_discriminants` |
| 3 | medium | the provenance block had no byte ceiling (`max_prov_entries` bounds entries, not the section) | **fixed**: `Limits::max_prov_bytes` (64 KiB default, 16 KiB strict), checked before the block is walked and in the section-count table; a block over it is a non-fatal `infinity/limit`; `a_provenance_block_over_its_byte_ceiling_is_a_limit` |
| 4 | low | `read_u32`/`read_u64` reported a wrapped offset as `Truncated { needed: u64::MAX }` | **fixed**: `infinity/offset` with the offending offset; the test that pinned the old code was updated |
| 5 | low | the spec said `UNIT_MAX_BUILTIN` is 8; the code hashes 66 | **fixed in the spec** (`currently 66`) |
| 6 | low | `Meta::has_annotations` checks the count, `has_provenance` the flag | **rejected as a false alarm**: `Validated::new` already rejects a flag/count disagreement in both directions (`validate.rs:79-115`), so the two are equivalent for a validated image |

**I-02 round 4** (2 high, 2 medium, 1 low):

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | an empty materialised blob skipped the payload hash (`if len != 0`) | **fixed**: the node arm requires `Blake3("")` for a zero-size payload with the payload flag; `an_empty_materialised_blob_with_a_wrong_hash_is_refused` (fails pre-fix) |
| 2 | high | enum members were not required to be in canonical (text) order: an image validated and then re-encoded to different bytes | **fixed**: consecutive members must be non-decreasing by text; `unsorted_enum_members_are_refused` (fails pre-fix) |
| 3 | medium | a `MIN`/`MAX` pair checked tag order but not values | **fixed**: resolve both bounds and refuse `min > max`; `a_reversed_min_max_constraint_is_refused` (fails pre-fix) |
| 4 | medium | strings/blobs/secrets/types/units/numbers/hashes have no reference-coverage bitmap, so an unreferenced but sorted entry validates and only `validate_canonical` rejects it | **rejected as a documented level split**: `validate` proves structural validity; `validate_canonical` proves the bytes are the canonical encoding (decode + re-encode equality), which catches every orphan. Duplicating the canonical proof in `validate` would double the work on the hot path for no additional guarantee. The `validate` doc now says so |
| 5 | low | the provenance pre-check multiplied `count * PROV_ENTRY_SIZE` unchecked | **fixed**: `checked_mul`/`checked_add` in both the pre-check and the entry walk |

Gate: 316 all-features, clippy clean both feature sets; the four new behavioural
tests fail against the pre-fix tree.

### Re-audit loop, round 3 (I-03) and round 2 (I-04) - 2026-10-31

**I-03 round 3** (3 high, 5 medium):

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | secret-only promotion covered `Str` but not `Ident`, so a secret value used as a locator name stayed in the public string heap | **rejected as a design conflict**: an `Ident` inside `SecretRef` is the *name* of the secret, not its value. Structural labels are schema and are carried verbatim (layout §3.1, the same rule that keeps field and binding names readable); promoting the locator to a literal would change what the locator means. A caller that puts a secret value into a label has published it as a name |
| 2 | high | `content_key` rendered a constraint through `Debug`, which redacts enum members to a count and a pattern to a constant: two different constraints shared an ordering key, and the tie-break used the arena id | **fixed**: the renderer writes every constraint variant explicitly (sorted enum members, pattern/custom text, ordered bounds); `pattern_text_does_not_change_the_canonical_bytes` (fails pre-fix) |
| 3 | high | the schema-field enum key used insertion order while the encoder sorts members, so member order could change the subject numbering | **fixed**: `normalize_type` and the constraint normalizer sort enum members, and the key sorts too; `enum_member_order_does_not_change_the_canonical_bytes` (fails pre-fix) |
| 4 | medium | the key truncated at 4 KiB/32 levels with `~`, so prefix collisions fell back to id order; a huge string was cloned per subject | **fixed**: the renderer is exact up to 1 MiB and depth 256 and returns `infinity/limit` past either budget, so it never falls back to ids and never copies a huge value into a second buffer. The truncation branch is gone |
| 5 | medium | transient secret copies (`secret_literals`, `Prepared.secrets`) are ordinary `String`/`Vec<u8>` and are not zeroized | **accepted as a residual for now**: zeroizing every transient copy needs `Zeroizing` through `Prepared` and the encoder, and the copies live for the duration of one `encode` call. `SecretBytes` (the durable owner) zeroizes; a core dump during an encode can still contain the transient buffers. Recorded here so the next release can widen the zeroization pass |
| 6 | medium | redaction scanned `secrets x text x 8 passes` with no budget | **fixed**: a 64 MiB scan budget; the fallible encoder returns `infinity/limit`, the infallible projection redacts the whole value. `an_unbounded_redaction_scan_is_refused` (fails pre-fix) |
| 7 | medium | ~20 unchecked `as u32` conversions could allocate gigabytes before the final `TooLarge`; `EXT_DIR_SIZE * len` was unchecked | **fixed for the allocation path**: an estimate over nodes/payloads/strings rejects an image that cannot fit the u32 space before the encoder allocates, and the extension directory uses `checked_mul`. Remaining casts are counts already bounded by a u32 field |
| 8 | medium | `remap_node` and `remap_node_in_place` had a wildcard arm, so a new child-bearing `Inode` would silently keep old ids | **fixed**: every leaf variant is listed explicitly (plus path-only patch ops); a new child-bearing variant now fails to compile |

**I-04 round 2** (1 high, 3 medium, 2 low):

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `decode_annotations` rejected the `AiImmutable` kind while the validator and the full decoder accepted it | **fixed**: the accessor mirrors `decode_validated`; `the_cheap_annotation_reader_accepts_the_immutable_flag` (fails pre-fix) |
| 2 | medium | `NodeView::count()` was documented as matching `children()` but is a mixed-entry count for interpolation, constraint and patch records | **fixed in the contract**: the doc now says "upper bound" and the test asserts `children.len() <= count` for every kind |
| 3 | medium | `with_opts(verify_hash: false)` reports an unverified header hash with no way to tell | **fixed**: `Validated::hash_verified()` and `InfinityView::hash_verified()`; `content_hash()` documents the condition. `hash_verification_is_reported_for_the_view` |
| 4 | medium | unchecked `x..x+y` ranges in decode/view (unreachable after validation today) | **partly fixed**: the provenance/aux loops use checked arithmetic where a u32 index could wrap; the remaining slices are bounded by the validator's section ends and are covered by the section's invariant tests. A future validator regression is a debug-build panic, not a silent accept |
| 5 | low | the cheap readers hardcode default limits | **documented**: the accessors state that they validate with `Limits::default()`; a caller with a strict budget uses `decode_with`/`InfinityView::with_opts` |
| 6 | low | `dependents()` allocates the full edge list | **documented as a cost**: the view is a diagnostic surface; the validator's own edge scratch is capped at 1<<20. A bounded iterator is a future additive API |

Gate: 321 all-features, clippy clean both feature sets; five new behavioural
tests, four proved to fail against the pre-fix tree.

### Re-audit loop, round 2 (I-05) and round 2 (I-06) - 2026-10-31

**I-05 round 2** (2 high, 4 medium, 1 low):

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `validate_structure` bounded the node count but not a single node's vector width (array elements, table fields, interpolation parts, enum members) | **fixed**: a pre-pass bounds every width at 1<<24 (the default `max_children`/`max_fields`/`max_parts`); `a_node_wider_than_the_ceiling_is_refused_before_it_is_walked` (fails pre-fix) |
| 2 | high | `structurally_eq` blinds secrets while the content hash commits to them, so a hash comparison reveals secret equality | **rejected as the documented content-commitment property**: the hash is a function of the image, and the image carries the secret heap in the clear (confidentiality at rest is a non-goal: `security.md`). Anyone able to compute/compare the hash already holds the bytes. `structurally_eq` is the anti-oracle equality; the hash is not an equality operator |
| 3 | medium | `UnitTag::Named("")` encoded to an image the validator refuses | **fixed**: `validate_structure` refuses an empty named unit (`infinity/encode`); `an_empty_named_unit_is_refused_at_encode` (fails pre-fix) |
| 4 | medium | `string_bytes()` counted only node strings, omitting bindings, annotation text and provenance | **fixed**: it now covers every text the canonical heap interns, with a doc note that interning deduplicates; `string_bytes_counts_bindings_annotations_and_provenance` (fails pre-fix) |
| 5 | medium | `saturating_add/sub` on fan-in hid overflow | **covered by finding 1**: the width and node ceilings bound fan-in to 1<<24, far below u32 |
| 6 | medium | annotation `expr` edges were missing from `edges()`/`dependency_map()`, so graph queries saw an incomplete dependency set | **fixed**: both include the expression → subject edge and document that it is not a structural edge for acyclicity (the wire edge table is unchanged); `an_annotation_expression_is_a_dependency_edge` (fails pre-fix) |
| 7 | low | `Debug` cloned the whole module and redacted every field, an unbounded cost in a log path | **fixed**: a module over 65 536 nodes or 1 MiB of text prints a count summary instead; `debug_of_a_large_module_prints_a_summary` (fails pre-fix) |

**I-06 round 2** (8 medium, 1 low):

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | medium | `Frame::parse` reported a complete header with a short payload as `stream-frame-len` instead of `truncated` | **fixed**: `infinity/truncated`, which `push_bytes` uses to wait; `a_split_frame_is_truncated_not_over_limit` (fails pre-fix) |
| 2 | medium | an incremental `End` cleared the pending deltas before proving the generation, so a bad retry applied zero ops | **fixed**: the clear happens after validation; `a_failed_incremental_end_keeps_its_pending_deltas` (fails pre-fix) |
| 3 | medium | `SetAnnotation` never checked a constraint expression's node | **fixed**: `infinity/stream-delta`; `a_dangling_annotation_expression_is_a_stream_delta` (fails pre-fix) |
| 4 | medium | `merge_fragment` pushed while remapping, leaving partial appends after a failure | **fixed**: two-phase remap into a temporary vec, then push; the arena is also capped at the default node ceiling (`stream arena nodes`) |
| 5 | medium | a `chunk` that cannot fit a Batch payload produced a stream the decoder refuses | **fixed**: `infinity/invalid-argument`; `a_chunk_that_cannot_fit_a_frame_is_refused` (fails pre-fix) |
| 6 | medium | the merged arena was bounded only by u32::MAX, so a stream of tiny fragments could grow it without limit | **fixed** by the same arena ceiling in finding 4 |
| 7 | medium | the delta `AiImmutable` flag decoded any non-zero byte | **fixed**: 0/1 only, `infinity/stream-delta`; `a_delta_immutable_flag_of_two_is_refused` (fails pre-fix) |
| 8 | low | `Frame::to_bytes` cast the payload length with `as u32` | **fixed**: `Frame::new` and `to_bytes` assert the `MAX_FRAME_PAYLOAD` contract (documented panic on a caller bug) instead of writing a corrupt length |
| 9 | low | a newer minor generation reported `VersionMajor` | **fixed**: a matching major with a newer minor is `infinity/version-minor`; `a_newer_minor_generation_is_a_minor_version_error` (fails pre-fix) |

While fixing #2 the re-audit uncovered a real decoder bug the review had not
listed: `push_bytes` left a semantically refused frame in its buffer, so a
caller retrying with corrected bytes replayed the bad frame first. The buffer is
now drained on a semantic error (the semantic state is already rolled back); the
pending-delta test pins the retry path.

Gate: 332 all-features, clippy clean both feature sets; 11 new behavioural
tests, all proved to fail against the pre-fix tree.
