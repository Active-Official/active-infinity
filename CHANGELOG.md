# Changelog - Active Infinity

## Unreleased

### Changed (hash-affecting — re-encode required)

- **The dialect is versioned; the format is now 1.1 (INF-03, BND-F1, R2-VER-03).**
  `dialect_hash()` no longer covers `FORMAT_MINOR`: it covers the format major,
  a new explicit `DIALECT_VERSION` (currently 1) and the canonical-form rules
  (`DIALECT_CANONICAL_TEXT`). A reader at 1.1 accepts 1.0 images — the 1.0
  dialect (`0x7782_d0ea_5e28_b75d`) stays accepted in `validate` and in the
  stream Begin handler — so the first minor bump no longer bricks every stored
  image: before this fix a 1.1 decoder refused every 1.0 image with
  `infinity/dialect`, because the minor-acceptance branch could never succeed.
  The 1.1 dialect is `0x23f9_4360_a471_a63e`. A 1.0 image is structurally valid
  but not canonical under 1.1: migrate by decoding leniently
  (`DecodeOpts { verify_canonical: false, .. }`), re-encoding, and storing the
  1.1 image, which has a new content hash. A signed (enveloped) 1.0 image
  cannot be migrated by re-encoding alone: the signature covers the 1.0
  bytes, so re-encoding invalidates it -- re-sign the 1.1 image instead
  (NF-INF03-03: the checked-in fuzz seed `fuzz/corpus/fuzz_signed_image/
  valid-envelope` was orphaned exactly this way and had to be regenerated
  with `fuzz/examples/gen_seeds.rs`). Any future hash-affecting
  canonical-form change must bump `DIALECT_VERSION` (and `FORMAT_MINOR` with
  it), never ship in a patch release.

- **Canonical form**: enum members (in a schema type and in an `Enum`
  constraint) are sorted before interning, so two modules that differ only in
  member order encode to the same bytes and share one content hash. Images
  produced before this change with unsorted members still validate leniently
  but fail `validate_canonical`; re-encode them to migrate.

- **Canonical form**: annotation subjects and constraint expressions are numbered
  in *content* order (a depth-limited, id-free rendering of the subtree) instead
  of the order `annotate` was called, so the call order can no longer change the
  bytes. Hash-affecting only for modules whose annotation-only subjects were
  added out of content order.

- **Canonical form**: node numbering orders bindings by name. Ordering the binding
  roots by numeric node id let arena construction order leak into the image, so
  two modules with the same content could hash differently. A module whose
  binding-only nodes were pushed in an order other than their names re-encodes
  to a different (correct) hash; `validate_canonical` reports the old bytes as
  not canonical.

### Fixed

- **Store commits are atomic on filesystems without hard links (XPL-INF-05 /
  INF-L10).** `commit()` fell back to writing the object directly at its
  final name when hard links were unavailable (exFAT/FAT32, some network
  shares), so a concurrent reader could observe a partial object. The
  fallback now renames the scratch file — which already holds the complete,
  synced bytes — into place, guarded by the same existence check. The
  code's own doc comment already described a rename fallback; the code did
  not do it. On Unix a plant landing between the existence check and the
  rename is still replaced by the rename; that can only substitute bytes
  this store verified for the hash, and readers validate whatever they
  find. On Windows the rename itself refuses an existing destination.

- **A swapped store root is refused on Windows (XPL-INF-03).** `Store::open`
  pinned the root directory by (device, inode) only on Unix; on Windows the
  check was skipped, so an open store silently split its objects across two
  directories when the root was replaced. A Windows file-index identity is
  not available on stable Rust (`MetadataExt::file_index` /
  `volume_serial_number` are nightly-only behind `windows_by_handle`, and
  the crate forbids `unsafe` code), so the store now pins its root with a
  per-directory token file (`.active-store-pin`) created at open and
  re-checked on every write. A whole-directory copy carries the token along,
  so a copied root is still not detected — a real file-index pin needs a
  minimal `unsafe` carve-out or the stabilization of `windows_by_handle`.

- **`--sign-file` refuses unverifiable seed files on non-Unix (INF-CLI-02 / XPL-INF-04).**
  The seed-file permission check (`mode & 0o077`) was `#[cfg(unix)]`-only,
  so on Windows a world-readable signing seed was silently accepted and
  used to sign — and a default-created file on Windows is already readable
  by every local user. The CLI now refuses `--sign-file` on platforms
  where the check cannot be performed unless `--allow-insecure-seed` is
  passed, which warns on stderr that the seed may be readable by other
  users. A Windows DACL check was considered and rejected: Rust's std
  exposes no ACL API, and this codebase forbids unsafe code, so no safe
  in-process check exists. The Unix mode check is unchanged. Not
  hash-affecting.

- **Stream Delta `PutNode` fragments are charged for their decoded payload bytes (INF-05).**
  The decoder's decoded-bytes charge for a fragment was `node_count x
  (size_of::<Inode>() + 32) + table_entries x 40`, which counts nodes and
  table fields but not string/blob/secret payload bytes: a fragment whose
  image is ~150 KiB but decodes to ~128 MiB (one 64 KiB string shared by
  2000 `Str` nodes) was charged only 272,136, so a decoder with an 8 MiB
  total budget accepted it. The charge now adds the fragment's decoded
  payload bytes, counted per reference (`InfinityModule::
  decoded_payload_bytes`) — the same per-use accounting the INF-01
  decoded-bytes budget enforces, since decode clones each payload per
  referencing node. The fragment above now charges ~131 MB and is refused
  under a strict budget, while it still decodes under the default 1 GiB
  budget. Not hash-affecting.

- **Encode refuses unreachable nodes instead of silently dropping them (INF-04).**
  `encode()` (and `encode_with` / `encode_into` / `encode_many` /
  `encode_hashed`) now fails closed with `infinity/node` (reason
  `unreachable node`) when a module holds a node no root reaches — including
  an unreachable `Secret` — instead of dropping it and returning `Ok` with
  different content. The in-memory and wire rules now agree: the wire
  validator always refused unreachable nodes. Only the explicit opt-in
  `EncodeOpts { drop_unreachable: true, .. }` drops them: the stream-delta
  re-encodes (a delta leaves the replaced subtree orphaned on purpose) and
  the merge canonicalize step (it keeps only the selected subtree). Callers
  that build modules with scratch nodes must remove them or opt in.
  `structurally_eq` (hence `PartialEq`) also sees an extra unreachable node:
  two modules with different raw node counts are never equal. The *content*
  of unreachable nodes is still not compared — no canonical numbering exists
  for a node no root reaches — so same-count modules with different
  unreachable content still compare equal; call `check_reachable` first when
  that matters. Not hash-affecting: a fully reachable module encodes to
  exactly the same bytes as before.

- **Schemas are canonicalized on load (INF-SCHEMA-05).** `Schema::from_bytes`
  now decodes leniently, re-encodes, and decodes strictly, so the stored
  module is always the canonical form: `module()` never exposes slack, an
  unflagged image, or dropped unreachable nodes as if canonical, and
  `to_bytes()` always equals the canonical encoding. A non-canonical schema
  image still loads (it is normalized, not refused); the secret/blob
  refusal still runs on the as-decoded module.

- **Canonical form is proven by default (INF-02, INF-CLI-01, NF-W5-01).**
  `DecodeOpts::default()` now sets `verify_canonical: true`, so `decode`,
  `validate`, `decode_provenance`, `decode_annotations` and `content_hash`
  refuse a structurally valid image that is not exactly the canonical encoding
  of its own content (`infinity/not-canonical`) instead of silently accepting
  it and re-addressing it on re-encode. This also fixes the CLI `validate`,
  `decode` and `bench validate` commands, which use the default options.
  Trusted or migration paths that must accept slack opt out explicitly with
  `DecodeOpts { verify_canonical: false, .. }`; the conformance suite's
  non-canonical vectors do exactly that. `DecodeOpts::paranoid()` is
  unchanged (canonical proof plus strict limits).

- **Decode amplification is bounded (INF-01, R2-INF-DEC-01).** `decode_validated`
  now refuses an image whose materialised form would exceed the new
  `Limits::max_decoded_bytes` (default 256 MiB, `Limits::strict()` 1 MiB),
  charging every cloned byte per use before any cloning happens: shared
  strings, blob payloads, secrets, named units, table field names,
  interpolated literals, constraint/patch/schema strings, annotation strings,
  binding names, extension payloads and provenance strings — including
  type-enum members, charged once per `SchemaField` that names the type, so
  the interned type table can no longer hide fan-out from the budget. A
  246 KiB image that decoded to 268 MB (1091x) is now refused with
  `infinity/limit`; `validate()` and the zero-copy `view` path are
  unaffected.

- **`Any` and an open `Table` keep their whole cone on the value plane.** The
  schema walk accepted an array or table without looking inside, so an `Ident`
  (or any other program node) nested under an `Any` field passed validation even
  though the type is documented as a value that does not open the program plane.
  The walk is iterative and budgeted, so a hand-built cyclic arena is refused
  rather than walked forever (DeepSeek F-05).

- **Validation** (`validate.rs`): node reserved bytes must be zero; the
  `children`/`fields`/`parts` tables must be packed sequentially in node order;
  every aux entry must be referenced exactly once; a table type's flag must agree
  with its aux entry; the type table is ordered by content; constraint and
  schema aux tags must be strictly ascending; a self-referential edge is
  `infinity/cycle`; count faults in variable sections are `infinity/count`;
  `total_size` is bounded at parse; secret/blob/provenance arithmetic is checked;
  bindings use `max_bindings`; a streamed or reassembled image is proved
  canonical.
- **Equality**: `InfinityModule` equality compares extension blocks, which
  canonicalization sorts and hashes; two modules with different extensions are no
  longer equal.
- **Secrets**: `SecretBytes` zeroes its buffer with `zeroize` on drop (a volatile
  write the optimizer cannot elide), `has_secret()` recognises `SecretRef`, and
  `TypeSpec::name()` no longer echoes enum members.
- **CLI** (`active-infinity-cli`): `stream` now takes its path (it read the
  wrong argument and always failed); every command rejects unknown flags, extra
  positionals and flags without a value; the signing seed can come from
  `--sign-file` or `ACTIVE_INFINITY_SIGN_SEED` and the parsed array is zeroized;
  Active source, proof sidecars and the conformance manifest are read under
  their own ceilings; output files are written through a same-directory temp and
  an atomic rename (0600 on Unix) and an output naming an input is refused; the
  conformance base is the manifest's own directory and a case path that escapes
  it is refused; limits are parsed with `try_from` and reject malformed or
  unknown entries; `bench --iterations` is capped; `store get` prints a note when
  a stored signature exists but `--verify` was not requested; the man page and
  CLI README match the surface and carry the CLI version.
- **Fuzz**: a parity test keeps `fuzz/Cargo.toml`, `scripts/fuzz_docker.py`,
  both workflows, the fuzz README and the corpus index on the same nine targets
  (the Docker lane had silently dropped `fuzz_compressed_frame`). The
  compressed-frame target now proves a fixed ceiling (a 1 MiB bomb refused at 64
  bytes), the canonical-order target actually toggles the build parity, a valid
  unit must validate, the graph target validates its raw input, a corrupted
  stream must be refused or unchanged, and the decode target bounds its view
  walk. The duplicate nightly fuzz lane is gone, the CI fuzz job uploads
  crashing inputs, and both lanes pass `-timeout` / `-rss_limit_mb`.
- **Errors** (`error.rs`, `stream.rs`, `layout.rs`): `infinity/evaluation` is a
  documented code with `Error::sub_code()` exposing the evaluator's class
  (`S001`, `T001`, ...) without parsing the message; `is_fatal()` now matches its
  documented rule (a `limit`, `evaluation`, `schema`, `compression`, `store`,
  `signature`, `proof`, `encode` or `stream-delta/state` failure does not mean
  the bytes are corrupt). A delta string over the u16 length space and invalid
  UTF-8 in a delta string report `infinity/stream-delta` (they used to report
  `infinity/too-large` and `infinity/utf8`, codes of a different layer), and
  `From<Utf8Error>` carries `valid_up_to` instead of a hardcoded zero.
  `Header::try_write` on a short buffer is `infinity/invalid-argument`. A unit
  test pins code uniqueness and that every variant's code appears in
  `docs/spec/layout.md`; the spec now has a C ABI code annex.
- **FFI** (`ffi/active-infinity-ffi`): `alloc` caps a request at 1 GiB, returns
  NULL on an impossible size and catches a panic; every buffer carries a tag so
  `free` with the wrong length is a no-op instead of a heap corruption; the
  module name is scanned to a 4096-byte bound instead of `CStr::from_ptr`
  (an unterminated name used to read past the buffer); Active source is capped
  at 16 MiB; `validate_canonical` is exported; `version()` reports the codec
  version and `ffi_version()` the shim; a misaligned `out_len` is refused with
  `infinity/out-len-misaligned`; success sets `infinity/ok` on every output
  path; the WASM random fill never calls the host for an empty buffer; the
  header/EXPORTS tripwire checks both directions.
- **Interop / projections** (`interop.rs`, `protobuf.rs`): the `active-core`
  bridge refuses a secret-bearing module instead of lowering `Inode::Secret` to
  a plain `CoreValue::Secret` string (a full plaintext export that bypassed
  ADR-0010). A provenance `parent` or hash entry equal to a 32-byte secret is
  refused at encode and rendered as the marker by the JSON and `provenance_lines`
  projections of a hand-built module; an extension payload containing a secret
  literal is refused at encode too (the Protobuf check existed, the stored image
  was the gap). The secret-taint walk now charges the shared projection node
  budget, the extension secret scan is capped at 64 MiB of comparisons, and the
  Protobuf projection is capped at 1 GiB (`infinity/limit`).
- **Merge** (`merge.rs`): a subtree comparison materialises only the reachable
  cone of that subtree instead of cloning and encoding the whole module per
  comparison (measured on a 60 000-node arena with 1 000 fields: 62.5 s to
  107 ms, release, same machine). A right-hand import copies the cone only, and
  the imported total, the total node visits (`MAX_MERGE_WORK`) and the
  conflict-path bytes (1 MiB) are all bounded with `infinity/limit`. Inputs are
  structure-validated first, so a dangling reference, cycle or excessive depth
  is `infinity/node-ref` / `infinity/limit` instead of a late, inconsistent
  failure. Conflicts are reported with escaped paths, so a field named `a.b`
  renders `a\.b` and cannot be confused with a nested `a.b` or a `<bindings>`
  marker. Bindings, provenance and extensions are base-aware (a one-sided change
  is adopted; a differing change on both sides is a conflict), metadata text is
  compared redacted, annotations compare order-insensitively, and a base that is
  not a table is no longer misreported as a nested `AddAdd`.
- **Signature** (`signature.rs`): `SignedImage::sign` and `verify` prove the
  canonical form, so an envelope can no longer certify bytes that re-encode
  differently. Parsing an envelope is bounded at the codec ceiling plus the fixed
  header (`infinity/limit`) before the image is copied, and every image fault is
  reported as `infinity/signature` so one monitored code covers every rejected
  envelope. `Debug` prints the envelope's metadata and never the image (the
  derived form printed the secret heap as decimal bytes).
  `Store::get_verified` no longer byte-compares the image against the envelope:
  both sides are pinned to the same content hash, and the comparison added a
  length-dependent timing signal over secret-bearing bytes.
- **Proof**: `Proof::from_json` accepts exactly the fields of
  `active-infinity/proof/1` and refuses anything else, and an integer field may
  arrive as a decimal string so a verifier whose numbers are f64 (JavaScript)
  round-trips `dialect_hash` without losing precision.
- **Compression** (`compress.rs`): an empty input is refused instead of decoding
  to empty bytes; a level outside the build's zstd range is
  `infinity/invalid-argument` instead of being silently clamped; dictionary
  training refuses a zero ceiling or an empty sample set. The module docs and
  `docs/spec/streaming.md` §6 pin the output ceiling, the dictionary-is-a-hint
  rule (a plain frame decompresses with any dictionary) and the CRIME-style
  length warning now recorded in `docs/spec/security.md`.
- **CLI**: every input file is read under a size ceiling (the codec's image
  ceiling plus envelope slack) before allocation; `dict train --size` uses a
  checked bound instead of a wrapping multiply; `dict apply --level` is narrowed
  with `try_from` and range-checked (a large value used to truncate to `0`), and
  `--max-bytes` must be between 1 and the codec ceiling.
- **Store**: `Store::put` now enforces the canonical form it documents instead of
  accepting any structurally valid image.
- **Store** (`store.rs`): reads are bounded by the codec ceiling *before*
  allocation (`infinity/limit`), so a hand-planted oversized object cannot be
  pulled into memory; `get` proves the canonical form instead of accepting any
  structurally valid image that happens to hash to its name; object and
  signature paths must be regular files (a symbolic link is refused); commits use
  a hard link, which is atomic and never replaces an existing object on any
  platform (the old rename replaced it on Unix *and* Windows); temp files are
  created with `O_EXCL` under a per-store counter so a planted name cannot
  redirect a write; a second, different envelope for one image is refused while
  re-storing the identical envelope is a no-op; on Unix the store directory is
  `0700` and objects are `0600`; `Store::open` refuses a symlinked or non-directory
  root; `len` counts `<64 lowercase hex>.ainf` regular files only instead of any
  `*.ainf` name; stale scratch files are swept after a day.
- **Secrets**: the promotion rule now treats a secret node as a barrier, so a
  string reachable only through a secret — the fallback of `secret(env.X ?: …)`,
  an interpolated literal — moves to the secret heap instead of the public string
  heap, even when a non-secret node (`Env`, `Interpolate`) sits between it and the
  secret. Hash-affecting for such modules.
- **Secrets**: a secret that is a substring of `***SECRET***` (`S`, `SEC`, `*`)
  can no longer be redacted — inserting the marker would publish it. An encode
  that would redact text in that situation now fails with `infinity/encode`
  instead of writing the secret into the image; a module with such a secret and
  no text to redact still encodes.

### Added

- `Store::try_len` reports a store directory that cannot be read instead of
  counting it as empty.
- `canonical::remap_node` is public. Projecting a module into a smaller arena
  (a subgraph, a pruned view) is a real consumer operation, and the reference
  rewrite is exhaustive over `Inode`; duplicating it outside the codec is how a
  projection ends up with a dangling reference. `restrict`-style callers in
  Active RPC switch to it with the next dependency bump.

### Changed

- `ir::hash_hex` writes two characters per byte into one buffer instead of
  calling `format!` per byte: 4.1 µs to 126 ns per 32-byte digest on the
  benchmark host, one allocation instead of 32. Output is byte-identical
  (lowercase hex) and `parse_hash_hex` round-trips unchanged.

## 2.4.0 - 2026-11-03

### Added

- **`interop::Redactor`**: a handle for one module's secret literals that
  rewrites a derived module (a cone, a restricted subtree, an evaluation copy)
  until no text carries a secret. It covers every surface the codec interns —
  string, identifier, `Env` name, table and schema field names, interpolated
  literals, blob media type, deprecation notes, enum members and constraint
  pattern/custom text, patch paths, annotations, provenance and binding names —
  and refuses a redaction that would collapse two names onto one key.
- **`interop::redact_module` / `interop::redact_image`**: the same rule applied
  to a whole module or image. This is the projection rule applied to the bytes:
  a plain `Str` that copies a secret literal is redacted too, because the codec
  has no way to tell a copy from data.
- **`infinity/stream-checksum`**: a frame checksum fault now has its own code;
  `infinity/stream-hash` is reserved for an `End`-frame module-hash mismatch.
- **`MAX_PROTOBUF_WORK`**: the protobuf projection charges every nested copy and
  refuses past 64 MiB of copying (`infinity/limit`), so a deep chain over a
  large shared string is a refusal instead of a 15-second stall.

### Fixed

- **Canonical form**: two roots that render identically (equal integers, two
  secrets, identical constraint expressions) were ordered by arena id, so the
  same logical module built in another order produced other bytes and another
  hash. The tie-break now orders them by the redacted annotation multiset
  attached to the root and by a digest of each secret in the subtree.
- **Validation**: a secret entry must be named by exactly one node, in node
  order; an aliased entry and an unreferenced trailing entry are
  `infinity/secret-entry` instead of covert bytes `decode` never reports.
- **Merge**: a conflict path (a field name) is redacted against every secret in
  the three inputs before it reaches the report.
- **Graph labels**: two nodes that would receive the same redacted path now take
  an id label instead, so `why`/`impact` no longer silently drop one.
- **Store**: an over-sized planted object and an absent one answer the same
  code, `infinity/store`.
- **Bridge**: lowering an arbitrary `CoreModule` refuses a reference cycle
  (`infinity/cycle`) and a chain past 256 levels (`infinity/limit`) instead of
  recursing until the stack aborts.
- **Projection depth**: capped at 256 (was 1024) so the recursive projection
  walk cannot abort the process on a legal module.

## 2.4.1 - 2026-11-03

### Fixed

- **Canonical form**: the tie-break signature added in 2.4.0 rendered a
  constraint's expression by node id, which the encode remaps, so an image with
  several identical constraint subjects was not a fixed point. The expression is
  rendered by content now.
## 2.4.2 - 2026-11-03

### Fixed

- **Redaction**: a custom unit name (`Quantity { unit: Named }`) is text and is
  redacted; a derived module whose binary surface (provenance parent, a hash
  entry, an extension, a blob payload or hash) copies a secret is refused, and
  a parent or hash entry that copies one is dropped.
- **Redaction labels**: a name (identifier, `Env` name, field, binding, unit,
  media type) replaces the occurrence it contains, as the projections do; only
  data text collapses whole. Two names that differ outside a secret stay
  distinct.
- **Canonical form**: the tie-break signature length-prefixes every part, so an
  annotation text containing the join separators can no longer collide with a
  different annotation set and fall back to arena order.
- **Canonical form**: the secret-digest walk is charged against the annotation
  key budget.
- **Bridge**: a deeply nested literal is refused with `infinity/limit` instead of
  aborting the stack.
- **Value paths**: a binding label is charged against the export cap and never
  shares another node's label.
- **Merge**: annotation, provenance and extension keys share one cumulative
  redaction budget.
- **Codes**: `StreamChecksum` is preserved through the delta path; every fault a
  planted object raises in `Store::get` is `infinity/store`.

**Re-addressing note (INF-03).** 2.4.0, 2.4.1 and 2.4.2 — all shipped
2026-11-03 — each made a hash-affecting canonical-form change (the tie-break
signature, its fixed-point render, the length-prefixed parts) while the format
stayed 1.0 and the dialect hash covered no canonical-form rule, so the same
logical module hashes differently across the three patch releases with no
version signal. Format 1.1 (see Unreleased) versions the dialect
(`DIALECT_VERSION`, covered by the dialect hash), so a hash-affecting
canonical-form change can no longer ship in a patch release.

## CLI 0.3.1 - 2026-10-31

- `version` (also `--version`, `-V`) prints the CLI and library versions, and
  the command appears in `help`.

## 2.3.0 - 2026-10-31

Maturity release for the Active Maturity Program: proof sidecars and the
three-way merge land on top of the 2.2.0 polyglot matrix. The AINF wire format
is unchanged.

### Added

- **Optional proof sidecars** (ADR-0014): `active_infinity::proof::Proof` records
  the content hash, size, node/edge/secret counts, dialect and an optional
  companion-schema hash, and verifies them against the canonical image
  (`infinity/proof` on any mismatch). JSON sidecars round-trip, and
  `active-infinity-cli proof issue|verify` writes and checks them.
- **Three-way module merge** (ADR-0015): `active_infinity::merge` merges two
  modules against their base field by field, returns a canonical module when
  every change is compatible, and reports typed conflicts (`AddAdd`,
  `ModifyModify`, `DeleteModify`, `KindMismatch`) otherwise.

## 2.2.0 - 2026-10-31

Additive release from the Active Maturity Program. The `AINF` wire format is
still 1.0 and canonical bytes are unchanged.

### Added

- **Optional zstd compression** (`zstd`, `compress`): plain, dictionary and
  dictionary training, with a mandatory output ceiling on decompression. The
  content hash stays over the uncompressed canonical bytes.
- **Detached Ed25519 signature envelope** (`signatures`) and the
  **content-addressed store** (`Store`): dedupe, hash-addressed get, integrity
  check on read.
- **Versioned conformance pack** (`conformance/manifest.json`) and
  `conformance run` with a JSON scorecard.
- **C ABI** (`ffi/active-infinity-ffi`, ABI 1) and a WASM build with exactly one
  host import; used by the polyglot bindings.
- **Polyglot matrix**: C, C++, Python, Go, JavaScript, TypeScript, Java,
  Kotlin/JVM, Scala, C#, Swift, Zig, Ruby, PHP, Dart, Kotlin/Native,
  AssemblyScript, Lua and shell, all validated against the shared manifest,
  with thin ARP1 RPC clients for every runtime.
- **`active-infinity-cli` 0.2.0**: `dict train/apply`, `bench`, an
  example-rich `help`, stable exit codes and end-to-end tests.

### Performance

- In-place canonical remap and batch encode; measured competitor tables in
  `docs/spec/performance.md`.

### Security

- zstd-safe 8.2.0 (RUSTSEC-2026-0395..0406) and rkyv 0.8.18
  (RUSTSEC-2026-0235) replace the affected versions.

## 2.1.0 - 2026-10-28

Hardening release. No wire-format change; `AINF` is still 1.0.

### Security

- **Projection memory is bounded across the whole projection.** The node budget
  is threaded through the root and every binding, so many bindings aliasing one
  DAG cannot multiply the old per-tree allowance. Over-budget projections fail
  with `infinity/encode`.
- **Debug, Display and DeltaOp no longer export free text.** `Inode`,
  annotations, provenance, `InterpPart`, `Constraint`, `TypeSpec`, `PatchOp`,
  `SchemaFieldSpec`, `UnitTag` and `DeltaOp` print lengths or markers. A caller
  formatting a node outside module context cannot leak a secret copy.
- **Stream deltas honour only the caller's `Limits`.** A widened `max_aux` is no
  longer refused by a default-limits pre-check.
- **Section length arithmetic is checked on 32-bit and 64-bit.** `section_body_len`
  uses checked `u64` math and returns `infinity/too-large` instead of wrapping.
- **`Header::try_write`** returns an error for a short buffer; `write` keeps a
  documented panic contract.

### Added

- `PROJECTION_NODE_BUDGET` (100,000 materialised nodes per projection).
- `Header::try_write`.
- `examples/streaming.rs`: frame reassembly with chunk boundaries that do not
  match frames.
- `scripts/sbom.py`, `scripts/check_32bit.sh`, `scripts/coverage_gate.py`,
  `scripts/verify_tag.sh`, and the nightly fuzz/coverage workflow.

### Changed

- `Debug` for the types above prints sizes/markers for text fields. This changes
  human-readable output, not data or the wire format.

### Verification

- 120 tests (both feature sets), red-team battery (16 cases), six negative
  controls, Docker fuzz (8 targets), i686 lane, benchmark matrix with recorded
  numbers, and the rustdoc-JSON API-surface gate.

## 2.0.7 — 2026-10-27

Test-and-documentation release; no API or wire change.

- **The allowlist test now has teeth.** Its trap binding was attached to an
  untainted node, so the redacted label never reached the helper's output and the
  test would have passed even if label redaction regressed to identity. The trap
  is bound to the secret node, the test asserts that the binding label is present
  in the cone, and a probe that replaces `redacted_key` with identity makes the
  test fail with `binding hunter2-secret`.
- **ADR-0010 names the right types**: `InfinityModule::has_secret` and
  `Inode::is_secret`, not `Inode::has_secret`.

## 2.0.6 — 2026-10-27

Hardening release for the secret-surface gate; no API or wire change.

- **The semantic gate fails closed on schema drift.** It pins the rustdoc
  `format_version`, requires a non-empty item index and the crate root, requires
  `inner`/`visibility` on every item, and fails when the number of recognised
  functions drops below a sanity threshold. A nightly that renames a JSON key now
  breaks the gate loudly instead of printing "clean" (four synthetic probes:
  wrong format, empty index, alias laundering, unresolvable alias).
- **Alias laundering is closed.** `pub use innocent as secret_x` used to be
  shape-checked against the *target's* name. The public name is what a caller
  sees, so the check now runs against the alias, and an unresolvable target under
  a secret-named alias is refused rather than guessed.
- **The allowlist is validated behaviorally.** A new test builds a module whose
  binding name contains a secret copy and asserts that `secret_tainted_paths`
  returns only redacted labels, so the one allowlisted entry cannot rot into a
  leak.
- **The tripwire refuses aliased re-exports with a secret name** (it cannot
  resolve targets textually, so it fails closed), matching the semantic gate.
- **ADR-0010 is accurate**: four crate-private helpers plus `Validated::secret`
  (not "three"), the real list of public secret-related items, the alias and
  glob-re-export rules, the schema-drift guards, the scope limits (associated
  items, fields, variants, macros) and the name-scoped residual risk.

## 2.0.5 — 2026-10-27

Tooling release; no API or wire change.

- **The semantic gate resolves crate-local type aliases.** It looked for the
  alias target under the wrong rustdoc key, so a module that introduced
  `pub type Bytes = Vec<u8>` and `pub fn secret_x() -> Bytes` would have passed.
  It now follows `inner.type_alias.type`, so the resolved return type is checked
  through any number of aliases. Proven by a probe that injects exactly that pair:
  the gate fails with `public secret_alias returns raw ['u8']`, then the probe is
  reverted.

## 2.0.4 — 2026-10-27

The secret-surface check is now semantic. No API or wire change.

- **New authoritative gate: `scripts/api_surface.py` over rustdoc JSON.** It walks
  the *resolved* public API — free functions, inherent and trait methods, and
  re-exports — and fails when a public item is blacklisted, is a glob re-export,
  or has a name mentioning secrets and a return type that resolves to raw text or
  bytes (`String`, `str`, `char`, `u8`, in any container). A new CI job
  (`api-surface`, nightly) runs it. The reviewer had live-proved seven ways past
  the old text scan; a compiler-backed check does not care how a declaration is
  spelled.
- **The textual test is now explicitly a tripwire**, not the guarantee. It still
  runs under plain `cargo test`, and it now also handles `extern "C"`, `&str` /
  `char` returns, attributes before `pub fn`, glob re-exports, a trailing `->`
  and a `->` inside a body. ADR-0010 states which layer is authoritative and why.
- Probes that each fail the relevant gate and are then reverted: injected
  free function, method on `Validated`, one-line body, array-length parameter,
  split return type, `const unsafe`, `extern "C"`, `&str` return, attribute
  prefix, glob re-export, `->` at end of line, `->` in body, and a trait method
  (caught by the semantic gate).

## 2.0.3 — 2026-10-27

Test release; no API or wire change. Three guard bypasses found by verification
are closed, each proven by an injected accessor that now fails the suite.

- **Array lengths in parameters no longer confuse the return-type check.** The
  scan read the text after the last `)`, so `pub fn secret_x(x: [u8; 32]) ->
  Vec<u8>` looked like a function returning `[u8; 32]`; it now reads only after
  the last `->`.
- **A return type on its own line is joined to the declaration**, so
  `pub fn secret_x(...)` followed by `-> Vec<u8>` on the next line is caught.
- **Modifiers are stripped in any order**, including `pub const unsafe fn`.
- ADR-0010 is updated to describe exactly these rules.

## 2.0.2 — 2026-10-27

Test-and-documentation release; no API or wire change.

- **The API-surface guard also catches one-line bodies.** `returns_raw_text`
  used the last `)` of the whole line, so
  `pub fn secret_x() -> Vec<u8> { Vec::new() }` hid its return type behind the
  body's parentheses. The signature is now cut at `{`/`;` first, and the case is
  covered by a probe that fails the suite when injected.
- **ADR-0010 matches the guard**: it now documents the blacklist, the shape rule,
  the line-joining and body truncation, the justified allowlist with its
  staleness check, and the residual risk (a deliberately obfuscated name). It
  also spells out why `buf()`, `section()`, `encode()` and the redaction helpers
  are not leaks: they return the caller's own bytes or redacted text.

## 2.0.1 — 2026-10-27

**Security fix. 2.0.0 is yanked: it still shipped one public secret accessor.**

- **`Validated::secret` is crate-internal.** The zero-copy validator exposed
  `pub fn secret(&self, id) -> Result<&[u8]>`, which returned raw secret bytes
  from a validated image; its own doc said "crate-internal" while the signature
  said otherwise. The decoder is the only caller, so it is now `pub(crate)`.
  This is the last public path to secret plaintext.
- **The API-surface guard now scans every file under `src/`**, follows multi-line
  signatures, treats `pub const fn` / `pub unsafe fn` / `pub async fn` like
  `pub fn`, and applies a *shape* rule on top of the name blacklist: a public
  function whose name mentions secrets and whose return type is `String`,
  `Vec<String>`, `Vec<u8>`, `Vec<Vec<u8>>` or `&[u8]` is a leak unless allowlisted
  with a written reason. `secret_tainted_paths` is the one allowlisted entry (it
  returns redacted labels, never bytes), and a test fails if an allowlist entry
  goes stale.
- **`View::provenance_entries` is documented as a raw accessor** (the stored form
  is already redacted; the doc now says so, matching `interop::provenance_pairs`).

The guard was validated adversarially: injecting `pub fn secret_values` (a
blacklisted name), `pub fn secret_names` (a new name with a raw return) and
`pub fn secret_raw` inside `impl Validated` (a method) each made the suite fail,
and the injected code was reverted.

## 2.0.0 — 2026-10-27

**Breaking: the plaintext secret accessors are gone.** The AINF wire format is
unchanged (still format 1.0), and every image written by 1.x remains valid.

Adversarial verification pointed out that three public helpers handed out secret
material, which defeats the structural-secret design:

| Removed from the public API | Why |
|---|---|
| `interop::secret_texts` | returned every secret as plaintext `Vec<String>` |
| `interop::secret_bytes` | returned the exact secret bytes (added in 1.2.5) |
| `interop::secret_literals` (JSON feature) | re-exported the same plaintext |

They are now `pub(crate)` and exist only for the redaction machinery inside the
crate. There is **no replacement that reads a secret**: use
`to_redacted_json` / `to_protobuf` for output, and `SECRET_MARKER` to recognize a
redacted value. This is a deliberate one-way door.

- `tests/api_surface.rs` is a static policy check: it fails if any
  `pub fn secret_*` accessor or a `pub use` of one reappears, and it pins
  `SECRET_MARKER` as the only public secret constant.
- The Protobuf test that used to call `secret_texts` now asserts the guarantee
  through the shipped projections instead: the literal appears in neither the
  Protobuf bytes nor the JSON document, and the marker does.
- `tests/protobuf_tests.rs` imports only the marker from `interop`.

CI, the clean-clone gates and the release checklist are unchanged; the published
artifact surface shrank, which is why this is a major version.

## 1.2.6 — 2026-10-27

Test-strength release; no code change.

- The non-UTF-8 secret regression test now asserts the exact failure code
  (`infinity/encode`) and the reason for the **embedded** copy as well as the
  direct one, so the committed test proves what `REVIEWS.md` claims it proves
  rather than accepting any error.

## 1.2.5 — 2026-10-27

Fixes from adversarial verification. No wire-format change.

- **A non-UTF-8 secret cannot leak through an extension payload.** The extension
  check compared the payload against the *lossy text* form of each secret, so a
  `SecretBytes::new(vec![0xff, 0xfe, 0x00])` copy never matched and the
  projection emitted it. The check now compares raw secret bytes
  (`interop::secret_bytes`), with a regression test covering a direct copy and one
  embedded after a prefix.
- **The documentation gate fails on rustdoc warnings.** An ambiguous intra-doc
  link (`crate::validate`, both a module and a function) produced a rustdoc
  warning that the previous `cargo doc` step accepted. The link now targets the
  function, and both repositories run `cargo doc` with `RUSTDOCFLAGS=-D warnings`.

## 1.2.4 — 2026-10-27

Fourth review pass; no wire-format change. The verification round after these
fixes reported no new findings.

- **`intents()` matches the stored form.** It applies the same occurrence
  replacement the canonicalizer uses, so an in-memory module and its decoded
  image give the same answer. The projections' data-text rule (whole-value
  marker) is unchanged and now documented separately from the image's prose rule.
- **Identifier nodes follow the label rule.** `Inode::Ident` redacts by
  occurrence like every other name; string values keep the whole-value rule.
- **`provenance_pairs` is documented as a raw accessor**, so a caller knows to use
  `provenance_json`/`provenance_lines` for output that leaves the process.
- **Redaction edge cases are tested explicitly**: a secret equal to the marker, a
  secret that contains it, overlapping secrets, empty entries and no secrets; the
  property generator now reaches uppercase secrets, including `SECRET` and
  marker-containing ones.
- **The spec states where a provenance key collision is reported**: the encoder
  refuses it (`infinity/encode`) because the resulting image would carry
  duplicate keys, which a reader rejects (`infinity/provenance`).

## 1.2.3 — 2026-10-27

Third review pass. No wire-format change. Two of these are regressions introduced
by 1.2.2 and are the reason 1.2.2 is yanked.

- **Redaction is a fixpoint for every secret, including one that contains the
  marker.** A replacement can join the text around it into a new secret
  (`"hid" + marker + "den"`), so the pass now repeats until the text is clean and
  falls back to the marker, with matches applied longest-first so the result is
  independent of the secret table's order. Property-tested over random secrets
  and texts.
- **An empty module is valid again.** `InfinityModule::check_depth` returned
  `infinity/cycle` for a module with no nodes; it now returns `Ok`, and
  `check_depth(0)` still runs the cycle check.
- **Agent-facing labels are redacted.** `value_paths` and `node_label` returned
  raw binding and field names, so a name containing a secret copy could reach a
  log or a model. Keys are now redacted like every other label.
- **Provenance key collisions are refused, not silently merged.** When redaction
  maps two keys onto one, the encoder reports `infinity/encode`
  (`provenance keys collide after redaction`) instead of dropping an entry; an
  image with duplicate provenance keys was never valid.
- **Projections agree on duplicate provenance keys** (first entry wins) for a
  hand-built module that never went through the encoder.
- **Labels and data text follow one documented rule**: data text that contains a
  secret becomes the marker, labels have each occurrence replaced. Unit names and
  environment names are labels; `docs/spec/projection.md` states the rule and the
  reason structural names are not rewritten in the image.
- **Cycle reports agree** between the depth and acyclicity sweeps (lowest node
  that could not be ordered).

## 1.2.2 — 2026-10-27

Second review pass over the 1.2.1 fixes. No wire-format change; the fixes make
redaction a true fixpoint and close the last copy path.

- **Redaction is a fixpoint for every secret.** The 1.2.1 rule only avoided
  injecting the marker when a *matching* secret was itself part of the marker; a
  second secret could still introduce it later, so a 1–3-byte secret such as `S`
  changed the text on every pass. The rule is now decided once per text: if any
  secret occurs inside `***SECRET***`, a text that needs redaction collapses to
  the marker. `interop::redact_text` and the canonicalizer share one
  implementation, and `SECRET_MARKER` has one definition.
- **Provenance keys are redacted.** `redact_provenance` rewrote values but not
  keys, so a copy embedded in a provenance key stayed in the string heap. Keys are
  now redacted like values, and entries that collapse onto the same key are
  deduplicated (provenance is a map), so the encoder cannot emit duplicate keys.
- **Projection value and key rules are consistent.** Value positions
  (`intents`, provenance producer/model/tool/text entries, Protobuf text fields)
  use the whole-value marker; key positions use occurrence replacement. The spec
  says the same, and `docs/spec/projection.md` now also states that structural
  names (field, binding, env, identifier names, media types) are *not* rewritten
  in the image — they are identity — while projections redact them and may merge
  two keys.
- **`InfinityModule::check_depth(0)` still checks cycles.** Zero means "no depth
  ceiling", not "skip validation"; a direct caller no longer gets `Ok` for a
  cyclic module.
- **Documentation matches the code.** `infinity/cycle` is documented as "a node
  on a cycle or depending on one" (the Kahn sweep reports the lowest such node),
  and the same wording appears in the error message.

## 1.2.1 — 2026-10-27

Independent review of the 1.2.0 candidate found eight issues; all are fixed here.
No wire-format change: every previously valid image stays valid, and every
previously canonical image stays canonical.

- **The Protobuf projection is canonical.** It is built from the canonical module
  (the decode of its own image), so logically equal modules — same AINF bytes and
  hash — project to identical bytes, and bindings, annotations and extensions come
  out in canonical order. Before, a table built with fields in a different order
  produced a different projection.
- **A projection cannot copy a secret through an opaque payload.** `to_protobuf`
  refuses an extension whose payload contains a secret literal instead of emitting
  it (`infinity/encode`, reason `extension payload carries secret material`).
- **Validation is linear in edges, not quadratic.** Acyclicity and depth use a
  Kahn topological sweep, with one child-list derivation per node; a wide table no
  longer turns validation quadratic.
- **Extension payloads must be packed.** Each payload now has to start exactly at
  `align8(previous end)` and the padding between payloads must be zero, so a
  directory cannot hide slack. New conformance vector `bad_extension_gap`.
- **One canonical proof.** `DecodeOpts::verify_canonical` now proves canonicality
  unconditionally, exactly like `validate_canonical` (which no longer encodes
  twice). An unflagged image fails the proof, because the canonical encoding of
  its content carries the flag.
- **One redaction rule.** `redact_text` (annotations, provenance, intents) no
  longer has a four-byte threshold, matching the projections: a one- or two-byte
  secret is replaced wherever it appears.
- **Taint follows references.** An interpolation whose expression is a `Ref` (or
  `Semantic` wrapper) around a secret redacts the whole string instead of
  rendering `"prefix ${}"`.
- **Tests and fuzzing cover the projections.** The independent Protobuf reader now
  checks ascending field numbers and minimal varints; new tests cover
  `i64::MIN`/`i64::MAX`, NaN, `-0.0`, empty text, canonical-envelope equality,
  secret-bearing extensions and short secrets; the decoder fuzz target exercises
  both projections and asserts the projection is deterministic.

CI also tests the locked graph with `--locked`, builds every target and feature on
the declared MSRV (1.85) with and without default features, verifies the package
tarball, and fuzzes on pushes as well as pull requests.

## 1.2.0 — 2026-10-27

No wire-format change: images written by 1.1.x remain valid and canonical. This
release adds a binary interop projection, first-class extension blocks, and a
conformance suite that covers every byte-reachable failure class in the
specification.

- **Protobuf projection.** `to_protobuf` renders a module as Protobuf wire
  format for consumers in other languages: root value, bindings, annotations,
  provenance, extensions, and the canonical image's Blake3 hash and size. The
  encoding is deterministic and redacted, uses no new dependency, and is
  documented in `docs/spec/projection.md` and ADR-0009. An independent reader in
  `tests/protobuf_tests.rs` checks the bytes.
- **One redacted tree for both projections.** `interop::Projected` is built once
  and rendered to JSON or Protobuf, so the two projections cannot disagree about
  what is safe to expose. `to_redacted_json` output is unchanged.
- **Extension blocks are first-class in the API.** `InfinityModule::add_extension`,
  `extensions` and `set_extensions` carry application-defined `(tag, payload)`
  blocks; encoding sorts them by tag and refuses duplicates, decoding returns
  them, and the validator checks the directory, payload order and the section's
  end.
- **Acyclicity is its own validation step.** A cycle is reported as
  `infinity/cycle` after reachability instead of surfacing as a depth failure,
  so a peer can tell "too deep" from "cyclic". The check is iterative.
- **Duplicate table fields name their node.** A repeated field key reports
  `infinity/duplicate-field { node }`; an unsorted key still reports
  `infinity/node`.
- **Conformance vectors cover the specification.** 34 invalid images and 9
  invalid streams, one per byte-reachable failure class, plus a
  specification-to-vector test: a new error code fails the suite until it has a
  vector or an explicit, justified waiver.

## 1.1.3 — 2026-10-27

- **Begin respects the caller's ceilings.** The declared stream size is compared
  with the decoder's own max_total_bytes, not the defaults.
- **Text projections redact keys and intent text.** provenance_lines redacts
  entry keys and intents() redacts intent text against the module's secret
  literals, matching the JSON projection. New helpers: `secret_texts` and `redact_text`.

## 1.1.2 — 2026-10-27

- **Delta fragments honour the caller's limits.** A Delta fragment is decoded
  and validated under StreamDecoder's Limits, so a strict consumer cannot be
  handed a larger module through a delta than through a generation.
- **Projection redaction covers metadata.** Table keys, unit names, environment
  names, blob media types and every provenance text field are redacted against
  the module's secret literals, not only values; provenance_json takes the
  secret table and provenance_json_for(module) supplies it.

## 1.1.1 — 2026-10-27

Security and correctness fixes from the independent review. No wire-format
change: images written by 1.1.0 remain valid and canonical.

- **Streaming bounds.** A stream may no longer accumulate more section bytes than
  the size declared by `Begin` (or `Limits::max_total_bytes`), and pending delta
  operations are capped by `Limits::max_aux`. Both report `infinity/limit`. A run
  of batches could previously exhaust memory before `End`.
- **Stream decoder limits.** `StreamDecoder::with_limits` lets a caller apply its
  own `Limits` to the reassembled image; the decoder no longer silently uses the
  defaults.
- **Truncated `finish()`.** `StreamDecoder::finish` no longer indexes past a
  partial frame; it reports `infinity/truncated`.
- **Depth over every root.** The depth ceiling is measured from every root
  (module root, bindings, annotation subjects), not just node 0, so a second
  shallow root cannot hide a deep chain.
- **Total-byte and string-heap ceilings** are enforced before decoding.
- **Provenance is a map.** `set_provenance` keeps the last value per key, so the
  encoder can never emit duplicate keys that validation rejects. Reserved entry
  kinds (4+) are refused instead of decoded as a different kind.
- **Projection guards.** Redacted JSON refuses cyclic/dangling modules and bounds
  recursion depth; `value_paths` is cycle-safe.
- **Retired `DeltaOp::PushNode`.** The variant produced unreachable nodes and was
  dropped after canonicalization; tag 2 is refused. Use `PutNode`/`SetBinding`.

## 1.1.0 — 2026-10-27

First production release: canonical `AINF` codec, fail-closed validator,
zero-copy views, streaming frames and deltas, `active-core` bridge, agent graph
queries, redacted JSON projection, conformance vectors, fuzz target.

