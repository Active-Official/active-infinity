# Changelog — Active Infinity

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
