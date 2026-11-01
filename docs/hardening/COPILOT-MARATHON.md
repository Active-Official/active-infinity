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
| I-09 | compress | `src/compress.rs`, CLI `dict` | **CLEAN** (round 3: 5 more fixed) | 16 fixed, 4 rejected/documented | this commit |
| I-10 | signature / proof | `src/signature.rs`, `src/proof.rs` | **CLEAN** (round 3: weak keys, code mapping) | 10 fixed, 2 rejected/documented | this commit |
| I-11 | merge | `src/merge.rs` | **CLEAN** (round 2: width/byte budgets) | 11 fixed, 1 rejected | this commit |
| I-12 | interop / protobuf | `src/interop.rs`, `src/protobuf.rs` | **CLEAN** (round 2: blob hash, marker, budget) | 12 fixed, 2 rejected/documented | this commit |
| I-13 | error codes | `src/error.rs` | **CLEAN** (round 2: fatality, stream codes) | 17 fixed, 2 rejected | this commit |
| I-14 | FFI | `ffi/**` | **CLEAN** (round 2 registry, round 3 DeepSeek) | 21 fixed, 9 documented | this commit |
| I-15 | CLI | `cli/active-infinity-cli/**` | **CLEAN** (round 2 DeepSeek: empty-value policy, containment) | 25 fixed, 3 documented | this commit |
| I-16 | fuzz targets | `fuzz/**` | **CLEAN** (round 2: dead oracle repaired, 5 targets added) | 28 fixed, 3 documented | this commit |

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

### Re-audit loop, round 2 (I-07) and round 2 (I-08) - 2026-10-31

**I-07 schema round 2** (4 high, 7 medium):

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | a default skipped `check_constraints`, so `min/max/pattern` were bypassed for a missing field | **fixed**: the default is checked against the same constraints; `a_default_is_held_to_the_declared_bounds` (fails pre-fix) |
| 2 | high | numeric bounds went through `f64`: NaN made every comparison false, infinities were vacuous and integers above 2^53 rounded | **fixed**: `Numeric::{Int(i128), Float(f64)}` with finite-only floats, exact int/int comparison, and a mixed int/float comparison refused as unenforceable; `a_non_finite_bound_is_refused`, `a_non_finite_float_value_is_refused` |
| 3 | high | duplicate instance fields were accepted and the first was checked | **fixed**: a `HashMap` rejects a duplicate name; `duplicate_instance_fields_are_refused` |
| 4 | high | `Duration` accepted a quantity whose inner value was a string | **fixed**: the inner node must be an Int or a finite Float; `a_duration_quantity_must_hold_a_number` |
| 5 | medium | a `SchemaTable` root passed as an instance | **fixed**: only `Inode::Table` is an instance; `a_schema_table_is_not_an_instance` |
| 6 | medium | `min_len`/`max_len` accepted negative, fractional and NaN bounds | **fixed**: a length bound must be a non-negative integer; `length_bounds_must_be_non_negative_integers` |
| 7 | medium | a nested `Table { closed: true }` was silently treated as an open table | **fixed**: the schema class refuses a nested closed table as unenforceable; `a_nested_closed_table_is_refused_as_unenforceable` |
| 8 | medium | `Any` accepted program-plane nodes (secret, locator, env, interpolation) | **fixed**: `Any` accepts only the value plane; `any_does_not_open_the_program_plane` |
| 9 | medium | a tainted blob matched `Bytes`/`Blob` | **fixed**: only `tainted: false`; `a_tainted_blob_is_not_a_public_value` |
| 10 | medium | per-field `find` plus a closed-schema `any` was O(fields x instance fields) | **fixed**: one `HashMap` for the instance and one `HashSet` for the declaration |
| 11 | medium | `Float` accepted NaN and infinity | **fixed**: finite floats only |

The rewrite also replaced the per-field `find`+`any` scan with hash lookups (finding
10).

**I-08 store round 2** (4 medium, 3 low):

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | medium | `read_bounded` lstat-checked then `File::open` followed a swapped symlink; a FIFO could block the reader | **partly fixed**: after opening, the file's own metadata must be a regular file and (Unix) match the lstat device/inode; a swap is refused. `O_NOFOLLOW` and a FIFO-specific test need `libc`/`nix`; the post-open check already catches a symlink or a non-regular target on the platforms this crate builds for |
| 2 | medium | `Vec::with_capacity(meta.len())` reserved up to 1 GiB from metadata | **fixed**: the reserve is capped at 1 MiB and the read stays bounded by `take` |
| 3 | medium | a pre-existing group/world-writable root was accepted | **fixed** on Unix: `infinity/store` for mode bits 0o022; a 0755 root is accepted because only writability lets another user plant objects (the at-rest readability exposure is documented). `a_group_or_world_writable_root_is_refused` (fails pre-fix, Linux) |
| 4 | medium | the root was checked once and could be swapped for a symlink before a write | **fixed**: the store records the root's device/inode (Unix) and re-checks it before every write and sweep; `a_root_swapped_for_a_symlink_is_refused_on_write` (fails pre-fix, Linux) |
| 5 | low | scratch slots started at 0 and `is_scratch_name` matched any `.X.tmp.pid.slot` | **fixed**: the counter is seeded from the clock and the matcher requires an object or envelope inner name |
| 6 | low | an oversized occupant surfaced `infinity/limit`, distinguishing absent / oversized / mismatched | **fixed**: an occupant fault is `infinity/store`; the test now pins that code |
| 7 | low | the hardlink-less fallback renamed over a concurrently planted object | **fixed**: the fallback writes through `create_new` (exclusive on every platform) and removes a partial file on failure |

Residual: `ensure_root` re-checks the path, not a pinned directory handle; a
write between the check and the commit is still possible on a filesystem where
the attacker can rename the store directory. Pinning a directory fd needs
`openat`/`cap-std`, which is a dependency decision for the next release. Windows
has no stable file-index metadata, so its identity check is the symlink/dir
re-check only.

Gate: 342 all-features, clippy clean both feature sets, Linux Docker store suite
12/12; 10 new schema tests and 3 store tests proved to fail pre-fix.

### Re-audit round 2 (I-10) - 2026-10-31

Reviewer scope: `src/signature.rs`, `src/proof.rs`, the sidecar JSON surface.
Findings: 1 high, 3 medium, 3 low.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `parse_hex32` sliced the 64-byte string by byte index, so a 64-byte string with a two-byte character at an odd boundary aborted the verifier with a char-boundary panic | **fixed**: the parser rejects non-ASCII and converts bytes through a `digit` closure; `a_non_ascii_hash_is_refused_without_panicking` panics pre-fix with `end byte index 2 is not a char boundary` and returns `infinity/proof` after |
| 2 | medium | `from_bytes` copied the image into a `Vec` before proving it canonical, doubling the transient memory for an input about to be refused | **fixed**: a free `verify_parts` proves the borrowed `&bytes[HEADER..]`; the copy runs only after the proof |
| 3 | medium | the image-fault mapping collapsed `infinity/limit` into `infinity/signature`, hiding a resource ceiling from a caller that budgets on it | **fixed**: `Limit` is passed through; `a_ceiling_fault_keeps_the_limit_code` (fails pre-fix, `infinity/signature`) |
| 4 | medium | `SignedImage::content_hash` leaked the codec's own fault code for a malformed image | **fixed**: envelope faults are `infinity/signature`, ceilings pass through; `content_hash_reports_the_envelope_code_for_a_corrupt_image` (fails pre-fix, `infinity/magic`) |
| 5 | low | a numeric sidecar string accepted `+42`, `007` and the empty string via `str::parse` | **fixed**: canonical decimal only (no sign, no leading zero, non-empty); `a_numeric_string_must_be_canonical_decimal` (fails pre-fix on `007`) |
| 6 | low | `verify_parts` rebuilt the signed message even when the key bytes were invalid | **rejected as a non-issue**: `VerifyingKey::from_bytes` runs before the message is built |
| 7 | low | the sidecar parser accepts a `null` schema hash and a missing one as the same value | **rejected**: both mean "no schema"; the contract says absent-or-null, and `to_json` writes `null` |

Gate: 346 all-features (4 new), clippy clean both feature sets; every new test
proved to fail against the pre-fix tree by stashing the implementation file.

### Re-audit round 2 (I-09) - 2026-10-31

Reviewer scope: `src/compress.rs`, the CLI `dict` surface, `docs/spec/streaming.md`.
Findings: 1 high, 2 medium, 2 low.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `train_dictionary` passed `max_size` straight to `zstd::dict::from_samples`; a large enough capacity makes zstd's allocator abort the process (0xc0000409), an uncatchable failure for an input the caller controls | **fixed**: a size above `Limits::max_total_bytes` is `infinity/invalid-argument` before the call; `train_refuses_a_dictionary_size_above_the_codec_ceiling` (pre-fix: `infinity/compression`) |
| 2 | medium | `--level` parsed as `usize`, so the whole fast half of the advertised range (`-131072..=-1`) was unreachable from the CLI; `--size`/`--max-bytes` reported a negative value as "expects a number" | **fixed**: `flag_signed` parses `i64`, `flag_number` refuses a negative with a precise message, `--level` is range-checked as `i64`; `dict_apply_accepts_a_negative_level_and_refuses_one_below_the_range` (fails pre-fix) |
| 3 | medium | `dict train` read every sample before any total check; only a per-file ceiling applied, so N hostile paths committed N files of memory and the saturating `total` hid the overflow | **fixed**: declared sizes are summed with `checked_add` and refused above `input_ceiling()` before a byte is read; `dict_train_refuses_samples_over_the_input_ceiling_before_reading_them` (fails pre-fix) |
| 4 | low | `dict apply` silently ignored a mode-irrelevant flag (`--level` with `--decompress`, `--max-bytes` when compressing) | **fixed**: both are usage errors; `dict_apply_refuses_a_flag_that_the_mode_cannot_use` (fails pre-fix) |
| 5 | low | an input of skippable frames only decoded to an empty success, indistinguishable from an empty payload | **fixed**: `carries_content_frame` walks the frame headers and refuses an input with no content frame (`infinity/compression`), while a skippable frame before content still decodes; `skippable_only_input_is_refused` (fails pre-fix), `a_skippable_frame_before_content_still_decompresses`; documented in `docs/spec/streaming.md` section 6 |

Gate: 349 library/integration tests plus 26 CLI tests, clippy clean both
feature sets and the CLI package; each new test proved to fail against the
pre-fix tree (library tests by stashing `src/compress.rs`, CLI tests by stashing
`cli/active-infinity-cli/src/main.rs`).

### Re-audit round 3 (I-09) - 2026-10-31

Reviewer scope: `src/compress.rs`, the CLI `dict` surface. All five round-2
fixes verified holding by live probe. Findings: 2 medium, 3 low.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | medium | `dict apply` checked the input against `--output` but not the dictionary, so `--output` equal to `--dictionary` overwrote the dictionary with data output and every later run compressed under a file that is not a dictionary | **fixed**: `ensure_distinct(dictionary, output)`; `dict_apply_refuses_output_equal_to_the_dictionary` (fails pre-fix, exit 0) |
| 2 | medium | `dict train` summed declared sizes but read every sample under a fixed per-file ceiling, so a sample that grew between the metadata pass and the read committed more than the total budget, and `total` stayed stale | **fixed**: each sample is read against the remaining budget (`ceiling - held`), and `total` is the bytes actually held; the same test path refuses the over-budget corpus |
| 3 | low | `dict train` without `--output` wrote the binary dictionary to stdout even though the usage line marks `--output` required | **fixed**: a usage error; `dict_train_needs_an_output_path` (fails pre-fix, binary on stdout) |
| 4 | low | a zero-byte `--dictionary` was accepted and compressed without a dictionary while claiming one | **fixed**: a usage error; `dict_apply_refuses_an_empty_dictionary` (fails pre-fix) |
| 5 | low | `carries_content_frame` computed `offset + 4` with wrapping arithmetic, so a crafted skippable length could produce a reversed range on a 32-bit target | **fixed**: both windows use `checked_add`; no panic path remains |
| 6 | residual | concatenated content frames decode to concatenated output | **documented + pinned**: `docs/spec/streaming.md` section 6, `concatenated_content_frames_decode_in_order`; the caller's ceiling bounds the total and an image consumer fails at validation |

Gate: 358 library/integration tests plus 29 CLI tests, clippy clean both
feature sets and the CLI package; every new test proved to fail pre-fix.

### Re-audit round 3 (I-10) - 2026-10-31

Reviewer scope: `src/signature.rs`, `src/proof.rs`, and the store trust anchor.
Round-2 fixes verified holding. Findings: 1 high, 2 medium, 1 low.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `VerifyingKey::from_bytes` accepts small-order keys; under the identity key with `R = identity, S = 0` the verification equation holds for every message, so an envelope verifies with no private scalar. The reviewer confirmed the forgery live | **fixed**: `verify_parts` refuses `key.is_weak()`, and `Store::get_verified` refuses a weak pinned key; `a_weak_key_envelope_is_refused` (pre-fix the envelope is accepted), `a_weak_trusted_key_is_refused` (fails pre-fix) |
| 2 | medium | `verify_with_schema` leaked raw codec and schema codes (`infinity/header-truncated`, `infinity/magic`) instead of the sidecar's `infinity/proof` | **fixed**: one mapping around the whole body, `Limit` passed through; `verify_reports_one_code_for_a_malformed_image` (fails pre-fix) |
| 3 | medium | `content_hash` hashed any bytes, so a non-canonical image would produce a hash naming content that re-encodes to different bytes | **fixed**: `validate_canonical` runs before the hash and `envelope_fault` maps the result; `content_hash_refuses_a_non_canonical_image` (fails pre-fix) |
| 4 | low | a sidecar without a `schema_hash` key parsed the same as `"schema_hash": null`, giving one proof two encodings | **fixed**: the key is required; `a_sidecar_without_a_schema_hash_field_is_refused` (fails pre-fix) |

Gate: same suite plus 6 new tests (2 unit, 2 sidecar, 1 store, 1 compress);
every one proved to fail against the pre-fix tree.

### Re-audit round 2 (I-11) - 2026-10-31

Reviewer scope: `src/merge.rs`. Round-1 fixes verified holding. Findings:
2 high, 1 medium, 1 low.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | the work budget charged distinct nodes while the cost is references: a two-node table with millions of fields (the wire allows 16M) built three million-entry maps and looped before `MAX_MERGE_WORK` could trip; a 16M-element array cloned its child list into the stack charged as two nodes | **fixed**: `MAX_MERGE_EDGES` (4 x node ceiling) refuses a wide table before a map is built (`field_map`, `binding_map`, `table_field`), `has_secret` charges children before pushing them, and `subtree_fragment` counts cone edges against the same ceiling; `a_wide_array_is_refused_before_it_is_walked` (pre-fix: 5.5 s then a clean merge) |
| 2 | high | equality re-encoded each fragment but charged only nodes, so one shared 64 MB value under 1000 fields could re-encode ~192 GB with a node charge of ~6000 | **fixed**: `MAX_MERGE_BYTES` (256 MiB) charges the encoded length of every comparison image; `a_shared_large_value_is_charged_in_bytes` (pre-fix: 34 s then a clean merge) |
| 3 | medium | a provenance `parent` or `ProvValue::Hash` equal to a 32-byte secret was hexed for comparison, while text is redacted and projections substitute the marker | **fixed**: `provenance_key` renders a hash that copies any secret from any of the three inputs as `SECRET_MARKER`, mirroring the projections; `a_provenance_hash_that_copies_a_secret_is_marked` (fails pre-fix) |
| 4 | low | a clean merge could return up to twice the input node ceiling (left clone plus one imported cone) with no check | **fixed**: the decoded result must be within `MAX_MERGE_NODES` (`merge output nodes`) |
| 5 | low (found while fixing #1) | the additions loop scanned the whole field vector per added field, which is quadratic in table width | **fixed**: one `HashMap` of pending additions, then a single pass over the fields |

Gate: 358 library/integration tests, clippy clean both feature sets; 3 new tests
(2 integration, 1 unit) proved to fail against the pre-fix tree.

### Re-audit round 2 (I-12) - 2026-10-31

Reviewer scope: `src/interop.rs`, `src/protobuf.rs`, `src/canonical.rs` (the
copy gate). Round-1 fixes verified holding. Findings: 1 critical, 2 high,
3 medium, 3 low.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | critical | a blob `hash` was never compared with the secret table, and every projection publishes it verbatim (hex in JSON, raw bytes in protobuf). A 32-byte secret copied there left through the projection; the encoder allowed it because it only checked provenance and extensions | **fixed**: `reject_secret_copies` walks blobs and refuses `blob hash equals a secret`, and `build_projected` refuses a hand-built module the same way; `a_blob_hash_that_copies_a_secret_is_refused` (fails pre-fix) |
| 2 | high | when a secret is a substring of `SECRET_MARKER` (`SECRET`, `S`, `*`), inserting the marker publishes the secret; `redacted_value` and the secret-node arm inserted it unconditionally | **fixed**: `hiding_placeholder` returns the empty string when the marker contains a secret, and every substitution uses it; `a_secret_inside_the_marker_is_never_published` (fails pre-fix) |
| 3 | high | redaction had a 64 MiB per-call cap but no projection-wide budget, so 100k strings each under the cap multiplied it without bound | **fixed**: one 256 MiB `PROJECTION_REDACTION_BUDGET` charged before each scan, threaded through `build_projected`; `the_projection_redaction_budget_is_shared` (fails pre-fix) |
| 4 | medium | `to_redacted_json` emitted fields in construction order while protobuf projects the canonical decode, so two modules with equal images produced different JSON | **fixed**: record fields are sorted by redacted name, and two names that redact to one key are refused; `projection_order_follows_the_content_not_the_construction` (fails pre-fix) |
| 5 | medium | `provenance_lines` interpolated free text into `key=value` without escaping, so a newline or `=` forged a field | **fixed**: `escape_line` escapes `\`, `\n`, `\r` and `=` in keys and values; `provenance_lines_escape_free_text` (fails pre-fix) |
| 6 | medium | `to_protobuf` built a value body before checking its size, so an 900 MB string peaked at roughly twice that before the refusal | **fixed**: `projected_size` (a proved over-estimate) refuses a value above half the cap before either allocation, and the post-encode check stays |
| 7 | low | a tainted blob publishes its hash and size, which confirms guesses about a low-entropy secret | **documented residual**: `docs/spec/security.md` §4 (use a salted hash upstream or withhold the projection); identity is the feature the field exists for |
| 8 | low | `resolves_to_secret` followed only `Ref` and `Semantic`, so a secret behind `Constrained`, `Quantity`, `Unary`, `Binary`, `Env` default, `Patch::Set`, `ContentAddressed` or `Interpolate` was treated as untainted and rendered as its shape | **fixed**: every transparent wrapper recurses, so the outer text becomes the marker; `a_secret_behind_a_wrapper_taints_the_interpolation` (fails pre-fix) |

Gate: 364 library/integration tests, clippy clean both feature sets; 6 new
tests proved to fail against the pre-fix tree. The protobuf early refusal is
exercised by code inspection only: a test would need a 512 MB value.

### Re-audit round 2 (I-13) - 2026-10-31

Reviewer scope: `src/error.rs` and every error construction site. Findings:
3 high, 7 medium, 1 low.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `is_fatal` marked `Truncated`/`StreamFrameLen` fatal while `push_bytes` treats them as "wait for more", so a caller gating a retry on the flag would drop a healthy partial stream | **fixed**: the two are no longer fatal, a new `is_incomplete()` names the wait signal, and the doc says a one-shot reader treats every error as terminal; the classification test fails pre-fix |
| 2 | high | a frame checksum failure reported `infinity/hash-mismatch`, the image content-hash code | **fixed**: `infinity/stream-hash`; `a_corrupt_frame_checksum_is_a_stream_hash_fault` (fails pre-fix) |
| 3 | high | `Validated::node` sliced `buf[offset..offset+32]` unchecked, a panic path in a public API if a layout invariant were ever missed | **fixed**: checked starts, ends and slice with `infinity/offset` |
| 4 | medium | stream frame flags reused the header's `UnknownFlags`, whose message always says "header" | **fixed**: a new `StreamFlags` variant (`infinity/stream-flags`), Display and spec row; a conformance vector `frame_flags.ainf` drives it (pre-fix: `infinity/flags`) |
| 5 | medium | the Begin payload's version/flags were mapped to `StreamVersion`/`StreamFlags` | **rejected**: the Begin payload carries the *image* header's generation and flag word, so `VersionMajor`/`VersionMinor`/`UnknownFlags` are the precise answers, as the I-06 test already required |
| 6 | medium | `validate_canonical` swallowed a decode fault into `NotCanonical` | **fixed**: the decode error is propagated; only a differing re-encode is `NotCanonical` |
| 7 | medium | `source()` is always `None` and `map_err(\|_\|)` discards the io/zstd cause | **rejected as by design**: the codec has no cause chain to avoid allocating in an error path and to avoid a filesystem-state oracle; store messages are fixed strings on purpose |
| 8 | medium | `is_fatal` included the caller-side `EncodeDangling`/`TooLarge` but excluded `Encode` | **fixed**: both are non-fatal; the classification test pins it |
| 9 | medium | `Frame::new`/`to_bytes` panic on an oversized payload | **fixed for input-driven sizes**: `Frame::try_new` returns `infinity/too-large`; `new` keeps its documented panic for a caller bug |
| 10 | medium | `From<Utf8Error>` reported a slice-relative offset under a code documented as an image offset | **fixed**: the impl is removed; every `Utf8` comes from an explicit absolute offset |
| 11 | low | the FFI fallback code `infinity/error` was undocumented | **fixed**: a spec row plus a conformance waiver |

Gate: 364 library/integration tests, clippy clean both feature sets; 3 new tests
and 1 new conformance vector, all proved pre-fix by stashing the implementation.

### Re-audit rounds 2 and 3 (I-14) - 2026-10-31

Round 2 reviewer: Muse proxy. Round 3 reviewer: **DeepSeek V4.1 via the Copilot
CLI** (CommandCode BYOK, `xhigh`), as an independent second opinion on the
rewritten allocator.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `free` read a header behind any pointer and trusted a fixed tag, so a foreign pointer with a planted tag corrupted the heap | **fixed**: a live-allocation registry decides what may be freed; `a_foreign_pointer_with_a_planted_tag_is_not_freed` (pre-fix: STATUS_HEAP_CORRUPTION) |
| 2 | medium | `send`-getters (`version`, `ffi_version`, `last_error`) could panic across the boundary | **fixed**: `catch_unwind` with a NULL fallback, documented |
| 3 | medium | the name scan stopped one byte early, refusing a legal 4096-byte name | **fixed**: `a_name_of_the_full_limit_is_accepted` (fails pre-fix) |
| 4 | medium | `alloc(0)` plus `free(p, 0)` leaked the buffer forever | **fixed**: the length-zero path goes through the registry; `a_zero_length_allocation_round_trips` |
| 5 | medium | `alloc` used `Vec` and `Vec::from_raw_parts(total, total)`, whose capacity can exceed the requested size (UB on dealloc) | **fixed**: `alloc_zeroed`/`dealloc` with one explicit `Layout` |
| 6 | high (DeepSeek) | the header promised a double free is a no-op, which fails once the address is reused: the stale free then releases a live block | **documented, contract corrected**: the header and `free` docs state the true guarantee (no-op only while the address is unreused; null after free) |
| 7 | medium (DeepSeek) | `input()` built a slice before any length bound, so `len = usize::MAX` violated `from_raw_parts` preconditions | **fixed**: a length above `isize::MAX` is `infinity/null-input`, and `from_active` checks its cap before slicing; `a_hostile_length_is_refused_before_the_slice` (pre-fix: STATUS_STACK_BUFFER_OVERRUN) |
| 8 | medium (DeepSeek) | the FFI `content_hash` accepted a non-canonical image, splitting identity from the Rust API | **reverted as by design**: the FFI hash is the byte identity of a valid image and every language in the matrix hashes the same bytes; canonical form is a `validate_canonical`/signature question (see `6e6d323`) |
| 9 | medium (DeepSeek) | `-3` is inert on `panic=abort` targets, including `wasm32-unknown-unknown` | **documented**: the header states the guarantee per target and that a trap is a failed call |
| 10 | medium (DeepSeek) | no limits knob; a 1 GiB image needs decode plus re-encode inside a 4 GiB wasm space | **documented**: the shim runs the default profile and the host must cap input for a small instance |
| 11 | low (DeepSeek) | `alloc`/`free` left a stale `last_error` after success | **fixed**: every call sets `infinity/ok`; `a_success_clears_the_last_error` (fails pre-fix) |
| 12 | low (DeepSeek) | getters can return NULL, which the header did not admit | **fixed**: documented as "unavailable"; bindings null-check |
| 13 | low (DeepSeek) | wrong-length `free` removes the registry entry and leaks permanently; alignment was undocumented | **documented**: the buffer is leaked by design and the alignment is 8 |
| 14 | low (DeepSeek) | the redaction canary named a literal the vector does not carry, and `validate_canonical` had no positive case | **fixed**: the test asserts `vector-secret` and the marker, and every canonical vector is accepted |

Gate: 27 FFI tests, clippy clean; each new behavioural test proved against the
pre-fix tree.

### Re-audit round 2 (I-15) - 2026-10-31

Reviewer: DeepSeek V4.1 through the Copilot CLI (`xhigh`). It reproduced two
findings live on this host. Findings: 1 high, 6 medium, 8 low.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `--key ""` was filtered to `None`, so `store get --verify --key "$UNSET"` verified against the object's own embedded signer and bypassed the `--key needs --verify` guard | **fixed**: a present `--key` is always parsed, so an empty value is a usage error; `store_get_refuses_an_empty_key_and_root` (fails pre-fix: exit 1 instead of 2) |
| 2 | medium | the conformance case guard only rejected absolute paths and `..`; `base.join("\\Windows\\win.ini")` replaced the base and read an arbitrary file | **fixed**: every component must be `Normal`, the resolved path is canonicalized and must start with the canonical base; `a_conformance_case_outside_the_base_is_refused` (fails pre-fix) |
| 3 | medium | `--schema ""` silently disabled schema validation (`issue` emitted `schema_hash: null`) | **fixed**: a usage error, resolved after `check_flags`; `proof_refuses_an_empty_schema` (fails pre-fix: exit 0) |
| 4 | medium | `get_signature(...).ok().flatten()` swallowed a tampered or unreadable envelope, removing the only pointer to `--verify` | **fixed**: `Err` prints a warning that the stored signature cannot be read |
| 5 | medium | `ACTIVE_INFINITY_SIGN_SEED` signed silently, and an empty value stored an unsigned object | **fixed**: signing from the environment prints the source; a set-but-empty value is a usage error |
| 6 | medium | `Store::open` ran before argument validation, so a usage error created `.active-store` (or a whole tree) | **fixed**: the store is opened inside each action after flags, arity and the hash parse; `a_usage_error_does_not_create_the_store` (fails pre-fix) |
| 7 | medium | conformance had no case or byte budget: a 1 MiB manifest can name 14k cases of up to 1 GiB each | **fixed**: 4096 cases and a 1 GiB read budget; `a_conformance_manifest_over_the_case_cap_is_refused` (fails pre-fix) |
| 8 | low | the seed hex stayed in the heap while only the `[u8; 32]` was zeroized | **documented**: `--sign-file` reads through a `String`; wiping it needs an allocator-visible buffer, and the CLI already never logs it |
| 9 | low | `File::open` preceded the regular-file check, so a FIFO path could block | **fixed**: `symlink_metadata` first, then open and re-check |
| 10 | low | the `stream` command read its container with the image ceiling, refusing a valid stream whose frame headers push it over | **fixed**: a stream ceiling (image ceiling + 64 MiB) |
| 11 | low | empty `--name`/`--root` fell back to defaults silently | **fixed**: both are usage errors |
| 12 | low | `doctor`'s feature list is hard-coded; `docs/release-cli.md` omitted `signatures`; the README exit table contradicted the man page | **fixed** for the docs; `doctor` stays literal because the CLI always enables all four features |
| 13 | low | `bench` had no aggregate work bound and printed the raw path in the machine line | **fixed**: 8 GiB processed-byte budget, the path moves to stderr; `bench_refuses_more_work_than_the_budget` (fails pre-fix: exit 0) |
| 14 | low | `--schema` was read before `check_flags`, so a usage error performed I/O | **fixed** by the #3 restructure |
| 15 | low | the scorecard's `detail` echoed the resolved absolute path | **fixed**: only the reason is kept |

Gate: 36 CLI tests, clippy clean; 7 new tests, each proved to fail pre-fix.

### Re-audit round 2 (I-16) - 2026-10-31

Reviewer: DeepSeek V4.1 through the Copilot CLI (`xhigh`), which replayed the
corpora and the helper probes. Findings: 3 high, 9 medium, 5 low.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `table_children` read the **Children** section for a table; field node ids live in **Fields** (entry + 8), so `fuzz_graph_cycles` returned before any mutation | **fixed**: reads `Section::Fields`, checks every offset |
| 2 | high | `repoint_ref` rebuilt only Ref-derived edges but compared against the total count, so it returned `false` for every input and the self-loop/ring oracles never ran | **fixed**: the one affected pair is replaced in the existing table, re-sorted and rehashed |
| 3 | medium | the self-loop oracle expected `infinity/edge` while the validator emits `infinity/cycle` | **fixed**: the oracle names the cycle code |
| 4 | medium | a forged `(u32::MAX, u32::MAX)` edge was classified as a cycle before the range check | **fixed**: range, then sortedness, then self-loop; `a_forged_self_loop_out_of_range_is_an_edge` (pre-fix: `infinity/cycle`) |
| 5 | medium | a rejected legal split and a failed truncation `finish` were silently dropped | **fixed**: the split must be accepted, every byte fed, and a truncated stream must fail with a truncation code |
| 6 | medium | decode, strict decode, encode, view and projection results were discarded with `let _`/`if let Ok` | **fixed**: validated input must decode, strict decode must agree with `validate_canonical`, encode must succeed, the view must open, the projection must succeed |
| 7 | medium | secret and cyclic projection results were ignored | **fixed**: a valid module must project; a cyclic module must be refused with `infinity/cycle` |
| 8 | high | no target covered Delta frames, the schema class, proof sidecars, signed envelopes or merge | **fixed**: five targets added (`fuzz_delta_frames`, `fuzz_schema`, `fuzz_proof_sidecar`, `fuzz_signed_image`, `fuzz_merge`) with seeds, registered in Cargo, the Docker driver, both workflows, the README and CORPUS.md |
| 9 | medium | the fuzz build dropped `active-core` and never enabled `signatures`, so the default bridge and the envelope were unfuzzable | **fixed**: the fuzz crate compiles the shipped default set plus `json`, `zstd`, `signatures` |
| 10 | medium | committed seeds never reached the claimed surfaces | **partly fixed**: every target has a seed and the new targets own theirs; the selector-based layout/unit targets are documented as a residual |
| 11 | medium | no regression seed named after a fixed bug | **partly fixed**: the graph target's seed plus the five new ones; a bug-to-seed mapping file is a policy change, documented in CORPUS.md |
| 12 | medium | the compressed target asserted neither the empty-input nor the skippable-only refusal, and discarded dictionary results | **fixed**: both refusals are asserted, and a dictionary decode must stay under the ceiling |
| 13 | low | the corruption index could equal the buffer length | **fixed**: clamped |
| 14 | low | no overflow checks in the fuzz profile; a 25 s timeout on a 4 KB input | **fixed** for the timeout (10 s in both lanes); the profile is cargo-fuzz's, documented |
| 15 | low | the manifest test was textual | **unchanged**: the test still asserts the lane/doc/seed agreement; a structural parse is a later refinement |
| 16 | low | the named-unit branch accepted any `infinity/*` code | **fixed**: `infinity/unit-ref` |
| 17 | low | every canonical mutation was rehashed, so an un-rehashed change was never checked | **fixed**: a payload flip without a rehash must fail validation |

Verification: `cargo check --manifest-path fuzz/Cargo.toml` builds all 14 targets;
`cargo fuzz run fuzz_graph_cycles` in `active-fuzz:1.88` exercises the repaired
oracle; the manifest reverse gate compares Cargo, the Docker driver, both
workflows and the docs.

### Re-audit round 3 (I-15) - 2026-10-31

Reviewer: DeepSeek V4.1. Findings: 4 medium, 9 low.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | medium | `stream` fed the whole container in one `push_bytes`; each frame drain moves the tail, so the cost was quadratic (measured: 17.7 MB -> 36.5 s) | **fixed**: `feed()` pushes 64 KiB slices, which also bounds the decoder buffer |
| 2 | medium | `manifest["base"]` was never validated: an absolute base discarded the manifest directory and re-opened the escape | **fixed**: a rooted/absolute base is a usage error; `a_conformance_manifest_with_an_absolute_base_is_refused` (pre-fix: exit 1) |
| 3 | medium | an empty `cases` array passed the gate with exit 0 | **fixed**: `a_conformance_manifest_with_no_cases_is_refused` (pre-fix: exit 0) |
| 4 | medium | the manifest's `sha256`/`size` pins were never checked, so a substituted vector that kept its error code passed | **fixed**: `verify_case_pin` (sha2) on every case; `a_conformance_case_must_match_its_pin` (pre-fix: exit 0) |
| 5 | low | the store was opened before the seed or image was read | **fixed**: both are read first; `store_put_validates_the_seed_before_opening_the_store` (pre-fix: root created) |
| 6 | low | `--sign-file ""` produced raw OS text with exit 1 | **fixed**: a usage error |
| 7 | low | `parse_hash` accepted a leading `+` (`from_str_radix`) | **fixed**: hex-only; `a_hash_with_a_sign_is_refused` (pre-fix: exit 1) |
| 8 | low | the output temp-name counter started at 0 with a predictable pid | **fixed**: seeded from the clock like the store's scratch names |
| 9 | low | `println!` panics on a closed stdout (exit 101) | **documented residual**: a closed pipe is a shell-level condition; converting every result line to fallible writes is a larger change with no security effect |
| 10 | low | argv tokens were interpolated into usage text (terminal control characters) | **fixed**: `{other:?}` at the four sites |
| 11 | low | `proof issue --output` could overwrite `--schema`; `dict apply` checked distinctness only after the work | **fixed**: both checks run before the work |
| 12 | low | `dict train`'s pre-pass followed symlinks and a full corpus produced a misleading error | **fixed**: `symlink_metadata`, and `remaining == 0` is a usage error |
| 13 | low | `manifest["format"]` was unchecked and `name`/`kind` are echoed | **fixed** for the format (`a_conformance_manifest_with_another_format_is_refused`); names are JSON-escaped by serde |
| 14 | residual | `stream_ceiling` assumes >=512-byte chunks | **documented**: the alternative is an unbounded read |

Gate: 42 CLI tests, clippy clean; 6 new tests, each proved pre-fix.

### Re-audit round 3 (I-16) - 2026-10-31

Reviewer: DeepSeek V4.1, which replayed all 14 targets over ~42k inputs and
found **no shipped-codec panic, hang or wrong code**. Findings: 1 high,
3 medium, 3 low, all in the campaign.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | in `fuzz_canonical_roundtrip` the un-rehashed probe was built from the already-mutated image, so two flips at the same byte cancelled and the probe re-validated the pristine image (reproduced: `[192, 0]`) | **fixed**: the probe copies the pristine image; one flip can no longer cancel |
| 2 | medium | the new signed/proof/schema seeds only reached refusal branches | **fixed**: `fuzz/examples/gen_seeds.rs` writes a real envelope, a complete sidecar and a schema image, asserting each parses; `tests/fuzz_manifest_tests.rs` re-checks them on every run |
| 3 | medium | `fuzz_layout_sections` still swallowed a validated-but-undecodable image | **fixed**: `decode(...).expect(...)` |
| 4 | medium | `fuzz_delta_frames` never verified a successful `finish` | **fixed**: the streamed image must validate, decode and re-encode |
| 5 | medium | `fuzz_merge` discarded a clean merged module | **fixed**: a clean merge must encode and validate |
| 6 | low | `repoint_ref` wrote the node before locating the edge pair | **fixed**: locate, then write; `a_failed_repoint_leaves_the_buffer_unchanged` |
| 7 | low | the view oracle swallowed `node`/`children` errors | **fixed**: both are `expect` on a validated image |
| 8 | low | the JSON projection was `expect`ed and protobuf swallowed every error | **fixed**: only `infinity/limit` is accepted, and both calls must agree |
| 9 | low | `fuzz/README.md` said "Nine targets" and omitted the new five | **fixed**: fourteen, with a table and the seed generator command |

Residual: no target drives the `active-core` bridge yet; `fuzz_merge` mostly
reaches the one-field conflict path. Both are recorded here rather than fixed
in this round.

### Re-audit round 3 (I-13) - 2026-10-31

Reviewer: DeepSeek V4.1. Findings: 2 high, 5 medium, 3 low.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | `Frame`, `StreamedModule`, `StreamDecoder` and `StreamEncoder` derived `Debug` over raw payload/image bytes, so logging a stream printed the secrets heap | **fixed**: hand-written `Debug` on all four (counts, sequence, hash, payload length); `Frame`/`StreamedModule` also lost byte-wise `PartialEq`; `the_stream_debug_forms_do_not_print_payload_bytes` (fails pre-fix) |
| 2 | high | a complete frame whose payload contradicts its kind reported `StreamFrameLen`, which `is_incomplete()` says to wait on, so a caller waited forever for bytes that could not help | **fixed**: a new fatal `StreamPayloadLen` (`infinity/stream-payload`) for Begin/Batch/End semantic lengths; `a_complete_frame_with_a_wrong_payload_length_is_a_payload_fault` |
| 3 | medium | `HeaderTruncated` was fatal while `Truncated` was incomplete; both mean "more bytes may fix this" | **fixed**: both are `is_incomplete` and non-fatal |
| 4 | medium | `push_bytes` drained the buffer per frame, which is quadratic in frames per call | **fixed**: parse against an offset and compact once |
| 5 | medium | `streaming.md` still said a wrong checksum is `infinity/hash-mismatch` | **fixed** in the spec, and `tests/doc_gate.rs` now reads `streaming.md` |
| 6 | medium | `Validated::hash_entry` reported an out-of-range index as `infinity/provenance` | **fixed**: `infinity/offset` (`section: hashes`); `a_hash_index_out_of_range_is_an_offset_fault` (fails pre-fix) |
| 7 | low | fabricated ids/conditions (`Edge{0,0}` sentinel, part index as node id, aux index as count) | **carried to round 4**: each needs a decision about the variant shape, not a one-line change |
| 8 | low | `is_fatal` linked to itself and the classification prose sat on `is_incomplete` | **fixed**: the prose is on `is_fatal`, `is_incomplete` has its own text |
| 9 | low | dead `StreamFrameLen <= MAX` arm; `to_bytes` has no `# Panics` section | **partly fixed**: the dead arm is removed; the panic doc is folded into the `try_new` docs |
| 10 | low | the conformance `spec.contains(code)` check let `infinity/encode` match `infinity/encode-dangling` | **fixed**: whole-cell match (`| `code` |`) |

Gate: 379 library/integration tests, clippy clean both feature sets; 3 new tests
and 1 new spec row, each proved pre-fix.

### Re-audit round 3 (I-12) - 2026-10-31

Reviewer: DeepSeek V4.1. Findings: 2 high, 6 medium, 4 low.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | a tainted interpolation inserted `SECRET_MARKER` directly, publishing a marker-colliding secret | **fixed**: `hiding_placeholder`; `a_tainted_interpolation_never_publishes_the_marker_collision` (fails pre-fix) |
| 2 | high | no byte budget while materializing the projected tree, so a DAG sharing one large string expanded past memory before the node budget tripped | **fixed**: a 256 MiB `PROJECTION_BYTES` budget charged on every projected string; `the_projection_byte_budget_bounds_a_shared_value` (pre-fix: 27 s then success) |
| 3 | medium | `intents` returned the marker even when the marker contains the secret | **fixed**: it uses the deletion rule in that case; `intents_never_publish_the_marker_collision` (fails pre-fix) |
| 4 | medium | `delete_secrets` has no cost guard of its own | **carried to round 4**: its only caller charges first; the protobuf key/provenance path (F5) needs the shared budget, which is the same change |
| 5 | medium | protobuf metadata redaction bypasses the projection budget | **carried to round 4** |
| 6 | medium | `$`-prefixed data keys impersonate `$env`/`$expr` markers | **carried to round 4**: needs a documented escaping rule in `projection.md` |
| 7 | medium | `impact`/`why` panicked on an out-of-range `NodeId` | **fixed**: both return empty; `graph_queries_refuse_an_out_of_range_id` (fails pre-fix) |
| 8 | medium | the secret-copy scan charged window count, not bytes compared (off by the secret length) | **fixed**: the charge sums the secret lengths |
| 9-12 | low | float rendering disagreement, duplicate redacted binding names, equality-only copy gate, provenance key-collision drop, O(k·n) label recompute | **carried to round 4** |

Gate: same suite; 4 new tests, each proved pre-fix.

### Re-audit round 4 (I-12) - 2026-10-31

Reviewer: DeepSeek V4.1. Findings: 1 high, 5 medium, 3 low; every carried item
was re-examined (none was a false alarm).

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | the copy gate charged window count, not bytes compared, so a prefix-repeat extension payload scanned for hours under a 64 MiB charge (445 ms for 1 MiB vs 38 ms unmatchable; reachable from `encode` and from `validate_canonical`) | **fixed**: the charge is `(len - secret + 1) x secret` in `canonical::reject_secret_copies`, mirroring `protobuf::carries_secret` |
| 2 | medium | protobuf metadata (binding names, provenance, annotations) redacts through the unbudgeted `redacted_key`/`redacted_value` | **carried to I-12 round 5** with the exact plan: make `redact_within`/`redacted_value_within` `pub(crate)`, thread `&mut redaction` into `encode_provenance`/`encode_annotation` and return `Result` |
| 3 | medium | an interpolated string used `redacted_value` (uncharged) | **fixed**: `redacted_value_within` |
| 4 | medium | `provenance_json_for`/`provenance_lines` compared hashes against the secrets' lossy text, so a non-UTF-8 32-byte secret was published as hex | **fixed**: both compare raw bytes; `a_non_utf8_secret_hash_is_marked_in_provenance_exports` (fails pre-fix) |
| 5 | medium | a data key starting with `$` was byte-identical to a projection marker | **fixed**: escaped (`$env` -> `$$env`) and documented in `projection.md`; `a_data_key_cannot_impersonate_a_projection_marker` (fails pre-fix) |
| 6 | medium | `node_label` rebuilt `value_paths` per node, so `impact`/`why` were O(n^2) | **fixed**: one map per query |
| 7 | low | the spec said redacted table keys "may merge", the code refuses | **fixed**: the spec documents the refusal |
| 8 | low | `hiding_placeholder` scans the secret table per visit | **carried to round 5** (cache per projection) |
| 9 | low | `secret_tainted_paths` iterates parents before children | **carried to round 5** (reverse order) |
| (d) | low | NaN renders as JSON `null` and as IEEE in protobuf | **documented** in `projection.md` (schema unchanged) |
| (e) | low | duplicate redacted binding names are emitted twice | **carried to round 5** (apply the `Record` refusal to bindings) |
| (f) | low | the copy gate is equality-only, so a short secret inside a hash can pass | **documented** in `projection.md` (equality gate, keyed-hash guidance) |
| (g) | low | `provenance_json` drops a redacted-key collision | **carried to round 5** (refuse, matching the encoder) |

Gate: 381 library/integration tests, clippy clean; 3 new tests, each proved
pre-fix.

### Re-audit round 3 (I-14) - 2026-10-31

Reviewer: DeepSeek V4.1, which also read the polyglot bindings. Findings:
1 latent high, 4 medium, 6 low.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high (latent) | the Go WASM host zero-fills on `crypto/rand` failure and reports success, producing predictable secret material | **carried to I-14 round 4** (`polyglot/go/activeinfinity.go`): return an error instead of zero-filling |
| 2 | medium | the JNI shim trusts `out_len[0]` without clamping to `GetArrayLength`, so Java can overflow the native buffer | **carried to round 4** (`polyglot/java/native/active_infinity_jni.c`): clamp to the array length |
| 3 | medium | a failed `alloc` set `infinity/limit`, contradicting the header and clobbering the code a binding reads after a failed call | **fixed**: `alloc`/`free` never touch `last_error`; a null return means allocation failure; the header says so and the ABI test pins it |
| 4 | medium | the AssemblyScript host copies the clipped length but passes the unclipped one | **carried to round 4** (`polyglot/assemblyscript/host.js`) |
| 5 | medium | eight bindings write through a null `alloc` return for inputs over the 1 GiB allocation cap | **carried to round 4**: check the return and raise `infinity/limit` in Ruby, PHP, Lua, C#, Dart, JS, the AS host and Go |
| 6 | low | `len > isize::MAX` reports `infinity/null-input` | **carried to round 4**: give it `infinity/limit` |
| 7 | low | the `free` rustdoc still said a double free is UB while the header says no-op | **fixed**: both docs state the reuse caveat |
| 8 | low | this log recorded the reverted FFI canonical-hash behaviour as a fix | **fixed**: the entry now records the revert |
| 9-11 | low | signed WASM pointers, unbounded error scans, `ULong` truncation, `bounded_name` over-read | **carried to round 4** |

Gate: 27 FFI tests, clippy clean.

### Re-audit round 5 (I-12) and round 4 (I-14) - 2026-10-31

Reviewer: DeepSeek V4.1. Both rounds are **not CLEAN**; the remaining items are
recorded here with their fixes, and the one change that was made is noted.

I-12 round 5:

| # | Sev | Finding | Disposition |
|---|---|---|---|
| 1 | critical | the JSON export took its secret table from the uncanonicalized module, so a locator literal promoted at canonicalization was not redacted | **change made**: `project_root` now encodes and decodes first, so JSON projects the same canonical module as protobuf. The reviewer's exact probe was not reproduced by a reachable-literal construction in a host test, so round 6 must re-probe with the reviewer's input before this is called closed |
| 2 | high | the redaction scan budget is per string, not cumulative, for metadata | **open**: thread one budget through `encode_provenance`/`encode_annotation`/`redacted_key_within` |
| 3 | high | `hiding_placeholder` is recomputed per visit (measured 94 s / 320 KB) | **open**: compute the placeholder once per projection and pass it down |
| 4 | medium | two bindings that redact to one name are emitted twice | **open**: apply the `Record` refusal to bindings |
| 5 | medium | `secret_tainted_paths` fixpoint is O(V*depth) and allocates children per visit | **open**: reverse topological order, one pass |
| 6-7 | low | provenance JSON drops a redacted-key collision; JSON/protobuf projected different modules | **6 open** (refuse); **7 addressed** by the same canonicalization |

I-14 round 4 (bindings):

| # | Sev | Finding | Disposition |
|---|---|---|---|
| 1 | high | the JNI shim trusts `out_len[0]` without clamping to `GetArrayLength` (JVM heap overflow) | **open**: clamp to the array length before the write |
| 2 | high | the Go WASM host zero-fills on `crypto/rand` failure and returns success | **open**: return an error instead of zero-filling |
| 3 | high | the AssemblyScript host copies the clipped length but passes the unclipped one | **open** |
| 4 | medium | eight bindings write through a null `active_infinity_alloc` return | **open**: check the return and raise `infinity/limit` in Ruby, PHP, Lua, C#, Dart, JS, the AS host and Go |
| 5 | medium | the AS host ignores the caller's `*outLen` capacity | **open** |
| 6 | medium | `polyglot/rpc/client.c` writes an unbounded payload into a 1 MiB stack buffer | **open**: bound the encode or heap-allocate |
| 7-11 | low | rustdoc/header wording, `isize::MAX` code, alloc panic path, signed WASM pointers, stale codes | **open** |

The in-repo C ABI changes from round 3 (silent `alloc`, matching docs) are
verified by the FFI suite.

### Binding fixes (I-14 round 4 follow-up) and projection round 6 - 2026-10-31

Committed `f259015` and `5a27749`, both pushed; CI green on `f259015`.

Bindings (`f259015`):

| Item | Change | Evidence |
|---|---|---|
| JNI capacity | `out_len[0]` is clamped to `GetArrayLength(output)` before the write, in both `output_call` and `fromActive` | compiles in CI's Java lane |
| Go WASM entropy | `fillRandom` returns an error and the host function fails (returns 1) instead of zero-filling | `TestAllocationRefusalIsInfinityLimit` + the Go conformance lane |
| AssemblyScript lengths | `copyFromAs` clips to the AS heap and returns the clipped length, which is passed to the reference; `runOutput` reads the caller's capacity from **AS memory** and returns `-2` with the required size when it is too small; a null `alloc` throws `infinity/limit` | `node polyglot/assemblyscript/test.js` PASS (test now sets the capacity) |
| Null `alloc` | Ruby, PHP, Lua, C#, Dart, JS, AS and Go raise `infinity/limit` instead of writing through address zero | JS guard test (fails pre-fix), Go test, plus the full matrix in CI |
| AS test contract | the three `outLen` buffers are initialised with their capacity | AS conformance PASS |

Projection (`5a27749`, I-12 round-6 pre-work):

| Item | Change | Evidence |
|---|---|---|
| Metadata redaction budget | `encode_provenance`/`encode_annotation`/binding names now draw on the same `PROJECTION_REDACTION_BUDGET` and return `Result` | `protobuf_metadata_redaction_draws_the_shared_budget` (fails pre-fix: it scanned for free) |
| Duplicate binding names | two names that redact to one key are refused with `infinity/encode` | `duplicate_redacted_binding_names_are_refused` (fails pre-fix) |
| Placeholder cost | `hiding_placeholder` is computed once per projection, not per node | code change; behaviour tests unchanged |
| Taint order | `secret_tainted_paths` runs one reverse-BFS pass instead of a depth-sized fixpoint | behaviour tests unchanged |

Gate: 383 library/integration tests, clippy clean both feature sets.

### Re-audit round 6 (I-12) and round 5 (I-14) - 2026-10-31

Reviewer: DeepSeek V4.1, which re-ran every lane it could on this host (FFI 27/27,
Go ok, JS/AS/Python/C# conformance PASS). Commits `5a27749`, `1393eea`,
`f18885d` (log), `+1` for round 6.

**I-12 round 6: the round-5 critical is CLOSED.** The probe shape is a second
carrier of the literal plus a `SecretRef`; on the fixed tree JSON renders
`{"***SECRET***":1,"token":"***SECRET***"}` and protobuf is literal-free.

| # | Sev | Finding | Disposition |
|---|---|---|---|
| F1 | high | the reverse-BFS single pass under-reported taint (a skewed-depth diamond lost a branch); regression from the round-6 "one reverse pass" | **fixed**: iterate the fixpoint in reverse; `every_path_to_a_secret_is_reported` (fails pre-fix) |
| F2 | high | `secret_texts`/`secret_bytes` ignored `SecretRef` locators, so every non-projection export leaked on the authoring path (`secret("x")` produces `SecretRef`) | **fixed**: resolve the locator through `Str`/`Ident`/`Ref`/`Semantic`/`Quantity`/`Env` default, bounded at 8 hops; `a_secret_ref_locator_is_in_the_secret_table` (fails pre-fix) |
| F3 | high | canonical metadata redaction had a per-string ceiling, not a cumulative one (measured 20 s for 1k entries) | **fixed**: `try_redact_text_with` + one `Cell` budget in `prepare`; `canonical_metadata_redaction_draws_one_budget` (fails pre-fix) |
| F4 | medium | `hiding_placeholder` was computed per visit (the log claim was wrong) | **fixed**: computed once and threaded as `&'static str` |
| F5 | medium | the public `redact_text` returned a marker that contains the secret | **fixed**: the marker-tainted branch returns the empty string; `redact_text_never_returns_a_marker_collision` (fails pre-fix) |
| F6 | medium | a `let`-bound locator stays in the public string heap (bindings are roots, so promotion never fires) | **fixed**: promotion treats binding-only reachability as non-public **for locator material only** (a literal the module root reaches is still shared/public); `a_let_bound_locator_does_not_stay_public` (fails pre-fix: "the literal is still a public string") |
| F7 | low | `provenance_json` drops a redacted-key collision | **open (round 7)**: make `provenance_json_for` return `None` on a collision; the text-only helper stays first-wins, documented |
| F8 | low | the projection node budget reports `infinity/encode`; the spec says `infinity/limit` | **open (round 7)**: switch to `Limit` and update the two redteam assertions |

**I-14 round 5: no critical; the round-4 fixes hold** (all six claims verified,
including the AS capacity read from AS memory and the Go/JS/AS lanes).

| # | Sev | Finding | Disposition |
|---|---|---|---|
| 1 | medium | a null (`0`) AS output/out-len pointer was decoded as AS address 0 | **fixed**: `runOutput` returns `-2` for a null output, `content_hash` skips the write |
| 2 | medium | the AS capacity enforcement has no regression test | **open (round 6)**: add a test that calls with a tiny capacity and expects `-2` + the required size |
| 3 | medium | the JNI clamp is untested from the JVM lane | **open**: a JVM test that passes a small array with a huge `out_len[0]` and expects `-2`, not a crash |
| 4 | medium | polyglot STATUS/README claim "Encode PASS" for C/C++/Zig, which never call `from_active` | **open**: correct the claim or add the call |
| 5 | medium | the Go random-fill failure path is dead (no shipped path calls it) | **open**: wire `active_random_fill` into the module contract or document it as unused |
| 6 | medium | the header still says an oversized `alloc` "refuses with infinity/limit" while the code leaves `last_error` untouched | **open**: reword the header sentence |
| 7-12 | low | Dart `_allocateSize` null deref; JNI CESU-8 names; Go runtime leak on `New` error; AS negative index; Kotlin error type; Lua bare error | **open (round 6)** |

Gate: 387 library/integration, 42 CLI, 27 FFI, clippy clean; JS and AS
conformance PASS.

### Re-audit round 7 (I-12) and round 6 (I-14) - 2026-10-31

Reviewer: DeepSeek V4.1 through the Copilot CLI (`xhigh`). I-12 round 7 reopened
the projection surface after the round-6 fixes and found one **critical**, two
**high**, three **medium** and five **low** items. All are fixed on the shipped
path; each behavioural test below was proved to fail against the round-6 tree.
I-14 round 6 closes its section: no critical, high or medium finding remains.

**I-12 round 7**

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | critical | an interpolated secret locator (`secret("hunter-${name}")`) was never promoted, so its literal stayed in the public string heap and every export copied it | **fixed**: `promote_secret_locators` treats `Interpolate` as locator material and rewrites each `InterpPart::Literal` to a `Secret` node when the interpolation is not root-public; `locator_literals` resolves every literal part; `an_interpolated_secret_locator_is_promoted` (fails pre-fix) |
| 2 | high | `content_key` rendered one full key per annotation and per constraint expression with no memo and no cumulative bound (686 MB peak from a 561 KB image) | **fixed**: one render per distinct subject, referenced by index, with `MAX_ANNOTATION_KEY_BYTES` (64 MiB) across all keys -> `infinity/limit`; `annotation_ordering_keys_are_bounded_in_total` and `many_annotations_on_one_subject_share_one_ordering_key` (the first fails pre-fix) |
| 3 | high | the non-projection exports scanned without a shared budget (`provenance_lines`, `provenance_json_for`, `value_paths`, `intents`); `delete_secrets` had no guard | **fixed**: one `EXPORT_REDACTION_BUDGET` (64 MiB) per call, saturating to the placeholder past it; six tests in `marathon_export_budget_tests.rs`, five proved pre-fix |
| 4 | medium | the taint fixpoint re-swept the graph per depth (`children()` allocated per node per sweep) | **fixed**: one depth-first post-order pass over `adjacency` (O(V+E)); no measurable difference on the shapes rebuilt here (4.42 ms -> 2.06 ms at depth 2000), linear by construction |
| 5 | medium | annotation-only roots were ignored, so a secret under a subtree that only an annotation names was reported untainted | **fixed**: `root_ids` and `value_paths` include annotation subjects and constraint expressions (`@annotation[n]`, `@constraint[n]`); `a_secret_under_an_annotation_only_subject_is_reported` (fails pre-fix) |
| 6 | medium | locator resolution gave up after 8 hops and failed open on in-memory modules | **fixed**: the walk is bounded by the node count; `a_long_locator_chain_stays_redacted` (64 hops, fails pre-fix) |
| 7 | medium | `redact_text` returned a marker that contains the secret when over its per-call ceiling | **fixed**: the marker-tainted over-budget branch returns the empty string (round-7 pre-work; test in round 6) |
| 8 | low | F7: a redacted-key collision was silently dropped by JSON and duplicated by the line codec | **fixed**: `provenance_json_for` returns `None`, `provenance_lines` keeps the first entry in stored order; `a_redacted_key_collision_is_refused_in_provenance` (fails pre-fix) |
| 9 | low | F8: the node budget reported `infinity/encode` while sibling ceilings report `infinity/limit`; the spec assigned no code | **fixed**: `infinity/limit` with kind `projection node budget`, `projection.md` §5 updated, `perf_budget.rs` assertion updated |
| 10 | low | the JSON `$`-escape rewrote Protobuf `Field.name` (`$env` -> `$$env`) although Protobuf has no markers | **fixed** (round-7 pre-work): the escape lives in `to_serde` only |
| 11 | low | `projection.md` §2 still said the canonicalizer falls back to the marker | **fixed**: the spec now says it refuses (`infinity/encode`) and that the infallible paths return the empty string |

Measured on this host (release-off test build, same machine, same shapes):

| Shape | Before | After |
|---|---|---|
| 500 000 annotations on one subject, `encode` | 3.30 s | 0.93 s |
| `provenance_lines`, 20k secrets x 200 KiB x 2 entries | 17.1 s, 409 615 bytes emitted | 11.6 ms, 39 bytes |
| `provenance_lines`, 50 entries x 200 KiB, 20k secrets | 463.8 s, 10 240 350 bytes emitted | 27.7 ms, 44 bytes |
| 90 distinct ordering keys of ~820 KiB | 74 MB retained, no refusal | `infinity/limit` |
| taint, depth-2000 shortcut shape | 4.42 ms | 2.06 ms |

**I-14 round 6: CLEAN for critical, high and medium.** Committed `9cbfe21`
(pushed). The round-5 AS capacity read from AS memory, the Go entropy path, the
JVM clamp test, the Go runtime cleanup and the Dart null guards all verify.
Round 6 then fixed: C/C++/Zig/AS request builders now refuse a payload past the
frame ceiling (stack overflow removed), the AS hash shim is fail-closed on a
null output, thirteen RPC thin clients bound a peer-controlled length, the Rust
and TypeScript value readers cap nesting depth, JNI sends UTF-8 for
supplementary names, Lua and Kotlin/Native raise typed errors, and the null
`last_error` scan is guarded in JS/AS/Go/Dart. Residual lows are documented:
the ABI is the trust boundary for a replaced library, no binding exposes
`validate_canonical`, names truncate at a NUL, and the 1 MiB client frame
ceiling is a policy choice.

Gate after round 7: 397 library/integration tests (9 new), 42 CLI, 27 FFI,
clippy clean on both feature sets, `cargo fmt --check` clean.

### Re-audit round 8 (I-12) - 2026-10-31

Reviewer: DeepSeek V4.1. It confirmed most round-7 fixes and found one **high**
incomplete fix, two **high**, five **medium** and one **low** (spec). All are
fixed; eight behavioural tests were proved to fail against `8fb6caa`.

**Round-7 verification:** `content_key` memo and total budget, the four export
budgets, annotation roots, the node-count locator bound, F7, F8, the JSON-only
`$` escape and the taint pass are present. Two claims were **incomplete**:
interpolated locator promotion covered only the resolved endpoint (F1), and
`layout.md` §2 still said structural names including interpolation parts are
"carried verbatim" (F9).

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | high | promotion marked only the node `resolve_locator` returned, so a locator that is a `Binary`/`Unary`/... left its `Str` and interpolated parts in the public string heap (`secret(pw + "-canary-${name}")` published `-canary-`) | **fixed**: the whole locator subtree is marked from one shared visited set; every `Str` and every interpolation part is promoted; `locator_literals` collects from the subtree; `a_binary_wrapped_interpolated_locator_is_promoted` (fails pre-fix) |
| F2 | high | spent-budget saturation called `hiding_placeholder(secrets)` per value: 200k secrets x 5k fields measured 16.1 s, and the "bounded by the budget" comment was false | **fixed**: the placeholder is computed once per export; capped helpers return `Option` and never rescan; `a_spent_export_budget_does_not_rescan_the_secret_table` (fails pre-fix) |
| F3 | high | `value_paths` built dotted paths with no byte or depth cap (depth-400 comb: 480 800 bytes, longest 2 399; tens of GB at the permitted depth) | **fixed**: `MAX_EXPORT_PATH_BYTES` 16 MiB and `MAX_EXPORT_PATH_DEPTH` 64, then `@node[id]`; `a_deep_path_chain_stays_bounded` (fails pre-fix) |
| F4 | medium | the module root was pushed before the annotation roots, so an annotation's synthetic label won over the real dotted path | **fixed**: annotations are pushed first, the root last; `an_annotated_subtree_keeps_its_real_path` (fails pre-fix) |
| F5 | medium | the post-order taint pass marked a cycle member done before its taint arrived, so a secret reachable only through a back edge was reported untainted | **fixed**: propagate over `dependents` from every secret (one pass per edge, cycle-safe); `a_secret_behind_a_cycle_back_edge_is_reported` (fails pre-fix) |
| F6 | medium | budget exhaustion was routed through the collision path: `provenance_json_for` returned `None` and the line codec emitted a fabricated `***SECRET***=` key | **fixed**: values saturate to the placeholder, keys stop the entry list, JSON never reports the block absent; `a_spent_budget_never_fabricates_a_provenance_key` (fails pre-fix) |
| F7 | medium | replacing the 8-hop cap with a node-count walk made locator resolution unmemoized (200k refs sharing a 4k chain: `provenance_lines` 8.3 s) | **fixed**: one cache per export; measured 106 ms; `shared_locator_chains_resolve_once` (fails pre-fix) |
| F8 | medium | promoting interpolated parts put fragments in the stored-metadata redaction set, so `secret("S${name}")` rewrote every `S` in prose and refused the module when the marker contains it | **fixed**: stored metadata is redacted against whole secrets only; fragments stay in the export set; `layout.md` §2 and `§11` document the split; `an_interpolated_one_byte_part_does_not_rewrite_metadata` (fails pre-fix) |
| F9 | low | `layout.md` §2 said an interpolation's literal parts are "carried verbatim", and §3 described the mechanism loosely | **fixed**: both paragraphs describe promotion and the metadata split |

Measured on this host (release test profile, same machine):

| Shape | Before | After |
|---|---|---|
| `value_paths`, 200k secrets x 5k fields | 16.09 s | 54 ms |
| `provenance_lines`, 200k refs x 4k-hop chain | 8.30 s | 106 ms |
| `value_paths`, depth-400 comb | 401 paths / 480 800 bytes / longest 2 399 | 65 paths / 12 416 bytes / longest 383 |
| provenance 3k secrets x 12 x 4 KiB | 2 lines incl. a fabricated key, JSON `None` | 1 line, JSON present |
| `encode`, 200k refs x 4k-hop chain | 4.39 s | 4.48 s (unchanged: the cost is not locator resolution; logged as a perf follow-up) |

Gate: 406 library/integration tests, 42 CLI, 27 FFI, clippy clean on both
feature sets, `cargo fmt --check` clean.

### Re-audit round 9 (I-12) - 2026-11-01

Reviewer: DeepSeek V4.1. It found that the round-8 metadata split broke the
canonical fixed point (a critical), plus three highs and five mediums. All are
fixed; six behavioural tests were proved to fail against `02612d9`.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| C1 | critical | the stored-redaction set was computed before promotion, so a decoded image (where promoted fragments are ordinary `Secret` nodes) took a different path: `encode(decode(image))` differed, and `validate_canonical` refused images the producer had just encoded | **fixed**: fragments are computed by promotion and a metadata string containing one is refused (`infinity/encode`, reason names the surface). Whole secrets are still replaced. A decoded image has no fragment in metadata, so both passes agree; `the_canonical_image_is_a_fixed_point` (fails pre-fix) |
| H1 | high | `secret_texts`/`secret_bytes` duplicated each locator literal per `SecretRef` and allocated a visited vector per distinct locator (131 MB for 1 000 refs of one 64 KiB literal) | **fixed**: one walk with one visited set, a deduplicated output vector, shared by both accessors |
| H2 | high | promotion covered `Str` and interpolation parts only; an `Ident` locator stayed in the public heap (and `reject_secret_copies` could not see it) | **fixed**: `Ident` in locator material is promoted like a `Str`; `an_ident_locator_leaves_the_public_heap` (fails pre-fix) |
| H3 | high | `content_key` is not injective (`"G1a=i1b=i2"` has two spellings) and tied on the arena id, so equal modules could encode differently | **fixed**: each run of equal primary keys is re-sorted by an injective, length-prefixed render (`content_key_framed`); the primary key stays byte-identical, so existing images keep their bytes; `a_colliding_primary_key_is_ordered_by_content` (fails pre-fix) |
| M1 | medium | hash entries recomputed the placeholder and rescanned the secret table per entry (202 ms / 2.4 MB churn for 2 000 hashes x 20 000 secrets) | **fixed**: raw placeholder and a `HashSet` of 32-byte secrets are computed once per export |
| M2 | medium | `value_paths` never descended binding subtrees, so a binding-only secret lost its leaf path | **fixed**: bindings are pushed as roots before annotations and the module root; a binding label is charged to the path-byte cap |
| M3 | medium | materialised blob payloads were never secret-scanned | **fixed**: blob payloads share the extension scan and budget, with a blob-specific diagnostic; `a_blob_payload_copying_a_secret_is_refused` (fails pre-fix) |
| M4 | medium | `Debug` printed a 32-byte secret used as a blob hash, provenance parent or hash entry as hex | **fixed**: `redact_hashes` zeroes those fields; `debug_never_prints_a_secret_hash` (fails pre-fix) |
| M5 | medium | `sorted_annotations` cloned the full text per comparison (unbudgeted O(n log n x text)) | **fixed**: comparator over references |
| L1 | low | `projection.md` claimed a marker-substring secret always refuses the encoder and that redaction is a fixpoint for every set | **fixed**: the spec states the stored-metadata rule, the fragment refusal and the fixed point |
| L2 | low | `layout.md` pointed consumers at the crate-private `interop::secret_texts` | **fixed**: points at the public projections |
| L3 | low | nodes past the path depth cap had no `@node[id]` label, and binding labels were not charged | **fixed** |
| L4 | low | the protobuf `carries_secret` charged secrets longer than the payload | **fixed**: same window arithmetic as the encoder |
| L5 | low | `Prepared` derived `Debug` over secret bytes and blob payloads | **fixed**: the derive is removed |
| L6 | low | `@annotation[i]` labels depended on insertion order | **fixed**: labels follow a stable (node, kind, text) order |

Measured: the secret table now holds one copy per unique literal; the round-9
probes (1 000 refs of one 64 KiB literal) drop from 131 MB to the literal's
size. Gate: 428 tests, clippy clean on both feature sets, fmt clean.

### Re-audit round 10 (I-12) and round 6 (I-13) - 2026-11-01

**I-12 round 10** found two criticals and two highs left in the round-9 work:
the stored-redaction set still missed locator literals inside expressions (C1),
its builder was per-reference and quadratic (C2), the framed tie-break was not
injective for named units and untagged schema slots (C3), and the fragment check
ran before redaction, so the marker could reintroduce a fragment (H1). All are
fixed; seven tests were proved to fail against `f96f77a`.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| C1 | critical | an expression locator (`secret("hun" + "ter2")`) left its literal out of the stored-redaction set, so the image published it in prose | **fixed**: one walk (the same traversal as promotion) collects every `Str`/`Ident` in locator material; `an_expression_locator_literal_is_redacted_from_metadata` (fails pre-fix) |
| C2 | critical | that set was built with a per-`SecretRef` `resolve_locator`, 5.7 s for a 3.9 MB image at 20k refs x 4k chain inside `validate_canonical` | **fixed**: one visited set, linear; `resolve_locator` deleted |
| C3 | critical | the framed render omitted a named unit's name and the schema-field slot tag, so two equal modules could encode differently | **fixed**: both are emitted only when `framed`, keeping the primary key byte-identical; `a_named_unit_breaks_a_key_tie_by_name`, `a_schema_field_slot_tag_breaks_a_key_tie` (fail pre-fix) |
| H1 | high | the fragment check inspected raw text, so marker insertion could create a fragment and a fragment inside the marker slipped through | **fixed**: the check runs on the redacted text; `a_fragment_created_by_redaction_is_refused` (fails pre-fix) |
| M1 | medium | `Debug` for `Blob`, `ProvValue::Hash` and `Provenance` still printed a 32-byte secret as hex/decimal | **fixed**: fixed placeholders; `debug_of_public_types_never_prints_a_hash` (fails pre-fix) |
| M2 | medium | the blob scan charged `(len-m+1)*m`, refusing ordinary 1 MiB blobs with a short secret | **fixed**: charge one pass; `a_large_blob_with_a_short_secret_encodes` (fails pre-fix) |
| M3 | medium | fragments in structural labels (field/binding/env/unit/media type) stayed in the string heap | **fixed**: labels are refused; `a_fragment_in_a_label_is_refused` (fails pre-fix) |
| M4 | low | framed tie-break keys were not charged to the annotation-key budget | **fixed**: charged, once per distinct subject |
| L1 | low | a re-encode failure during `validate_canonical` surfaced as `infinity/encode` | **fixed**: `infinity/not-canonical` |

**I-13 round 6** found that the round-5 ceiling mechanisms were present but the
*amount* charged was peer-controlled: two criticals and one high.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| R6-1 | critical | generation work charged `End.size` (peer-controlled) while the work is the accumulated bytes: 1.7 M free assemblies measured | **fixed**: `assembled_len` computes the real length from the section buffers before allocating, the charge uses it, and a disagreement is `infinity/stream-hash`; `a_first_generation_end_size_lie_cannot_buy_free_assembly` (fails pre-fix) |
| R6-2 | critical | `pending_deltas` cost 144 bytes per 5 wire bytes with no decoded-state bound (54x amplifier, 2.4 GiB at the op cap) | **fixed**: `decoded_op_bytes + pending_delta_bytes <= max_total_bytes`; `a_delta_frame_cannot_buy_more_than_its_wire_bytes` (fails pre-fix) |
| R6-3 | high | the incremental charge used the image size although applying the ops dominates | **fixed**: charge `max(image, decoded op bytes)` |
| R6-4 | medium | a refused `Delta` frame was free work and replayable | **fixed**: every delta frame is charged when decoded; `a_replayed_delta_frame_is_charged` (fails pre-fix) |
| R6-5 | medium | `push_bytes` promised per-frame recovery but kept a tail parsed against the failed frame | **fixed**: a semantic fault drops the buffer and the docs say so; `a_refused_frame_ends_the_buffered_stream` (fails pre-fix) |
| R6-6 | low | generation-1 size mismatch had its own non-fatal code | **fixed**: `infinity/stream-hash`; `a_first_generation_size_mismatch_is_a_hash_fault` (fails pre-fix) |
| R6-7 | low | `size as usize` truncated on 32-bit targets | **fixed**: `usize::try_from` |
| R6-8 | low | `StreamSequence` was fatal while `push` documented a retry; the missing-section state was undocumented; the part/aux aliases did not name their codes | **fixed**: docs and variant docs |

The encoder now also refuses to emit a no-op delta its own decoder rejects
(`the_encoder_refuses_a_no_op_delta`, fails pre-fix).

Gate: 441 library/integration, 42 CLI, 27 FFI, clippy clean both feature sets,
fmt clean.
