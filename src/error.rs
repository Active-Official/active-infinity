//! Stable, machine-readable error surface.
//!
//! Every failure mode of the codec, validator, view and stream layers maps
//! to exactly one variant here, and every variant carries a permanent
//! `code()` string. Agents branch on codes, never on messages: the code
//! namespace is part of the wire contract (`docs/spec/layout.md` §9) and
//! codes are never reused or renumbered.
//!
//! Failure is always *closed*: a buffer that cannot be fully validated is
//! rejected before any caller sees a node, a string, a blob or a view.

use std::fmt;

/// Result alias for every fallible operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A codec, validation or streaming failure.
///
/// Variant documentation states the condition; field names are stable API.
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    // ---- framing and header -------------------------------------------
    /// Input does not start with the `AINF` magic.
    Magic,
    /// Unsupported major format version.
    VersionMajor(u16),
    /// Unsupported minor format version (readers never guess forward).
    VersionMinor(u16),
    /// Header is shorter than the fixed 224-byte header.
    HeaderTruncated,
    /// Header `header_size` field is not the supported fixed size.
    HeaderSize(u16),
    /// Header flags set bits this reader does not understand.
    UnknownFlags(u16),
    /// A reserved header or record field was non-zero.
    ReservedNonZero { section: &'static str, offset: u64 },
    /// A section offset or byte range is out of bounds, misaligned,
    /// overlapping, or not in canonical ascending order.
    Offset { section: &'static str, offset: u64 },
    /// The buffer is longer or shorter than the sections it declares.
    Truncated { needed: u64, found: u64 },
    /// The buffer declares trailing bytes after the final section.
    TrailingBytes { at: u64 },
    /// A count field cannot be satisfied by the remaining bytes, or
    /// exceeds the configured limits.
    Count { field: &'static str, value: u64 },
    /// Non-zero padding byte (canonical images pad with zero only).
    Padding { offset: u64 },
    /// Stored content hash does not match the recomputed hash.
    HashMismatch,
    /// The declared dialect hash is not the dialect this reader implements.
    DialectMismatch(u64),
    /// A buffer self-declares canonical form but re-encoding differs.
    NotCanonical,

    // ---- structure -----------------------------------------------------
    /// A string id is out of range.
    StringRef(u32),
    /// A node id is out of range.
    NodeRef(u32),
    /// A node record violates the per-kind contract.
    Node { id: u32, reason: &'static str },
    /// String heap bytes are not valid UTF-8.
    Utf8 { offset: u64 },
    /// A unit discriminant is not one this reader implements.
    UnknownUnit(u32),
    /// A quantity or type reference is out of range.
    UnitRef(u32),
    /// A type-table entry is malformed.
    Type { id: u32, reason: &'static str },
    /// An edge endpoint is out of range or an edge is self-referential.
    Edge { from: u32, to: u32 },
    /// The stored edge table does not match the references in the node table.
    ///
    /// Distinct from [`Error::Edge`], which names one bad pair: a set mismatch
    /// has no pair to name, and reporting `0 -> 0` collided with a genuine
    /// self-loop report. Shares the `infinity/edge` code.
    EdgeSet,
    /// A part-table entry carries an unknown tag.
    ///
    /// Node validation reports the referencing node first; this variant is the
    /// fallback for a part record no node names.
    Part { index: u32, reason: &'static str },
    /// An aux entry is not referenced by any type or node.
    AuxUnreferenced { index: u32 },
    /// An annotation record is malformed.
    Annotation { id: u32, reason: &'static str },
    /// The provenance block is malformed.
    Provenance(&'static str),
    /// An extension block is malformed or overlaps another block.
    Extension { tag: u64, reason: &'static str },
    /// A blob entry is malformed.
    Blob { id: u32, reason: &'static str },
    /// A secret-table entry is malformed.
    SecretEntry(u32),
    /// A table field name repeats.
    DuplicateField { node: u32 },
    /// A binding name repeats.
    DuplicateBinding,
    /// A node is on a dependency cycle, or depends on one.
    Cycle { node: u32 },
    /// Nesting depth exceeds the configured limit while validating.
    Depth { limit: u32 },

    // ---- limits --------------------------------------------------------
    /// A configured decode limit was exceeded.
    Limit { kind: &'static str, limit: u64 },
    /// A caller-supplied value is outside its legal range.
    InvalidArgument(&'static str),
    /// The Active evaluator rejected the module; the payload is its stable
    /// diagnostic class (`S001`, `T001`, `X00n`, ...).
    Evaluation(&'static str),
    /// A companion schema rejected the instance shape.
    Schema(&'static str),
    /// Optional compression/decompression failed or exceeded its bound.
    Compression(&'static str),
    /// Local content-addressed store failed.
    Store(&'static str),
    /// Detached signature envelope is malformed or the signature is invalid.
    Signature(&'static str),
    /// A proof sidecar does not match the image it describes.
    Proof(&'static str),

    // ---- encoding ------------------------------------------------------
    /// A module cannot be encoded (dangling reference, duplicate key, ...).
    Encode(&'static str),
    /// A node id referenced during encoding does not exist.
    EncodeDangling(u32),
    /// The encoded image would exceed `u32` offset space.
    TooLarge,

    // ---- streaming -----------------------------------------------------
    /// Stream frame magic `AINS` missing.
    StreamMagic,
    /// Unsupported stream frame version.
    StreamVersion(u8),
    /// A stream frame declares a payload past the frame ceiling.
    ///
    /// This is a permanent fault: no amount of additional input makes a frame
    /// larger than `MAX_FRAME_PAYLOAD` acceptable. A buffer that merely stops
    /// short of a legal frame is [`Error::Truncated`] instead.
    StreamFrameLen { declared: u32, available: u64 },
    /// A complete stream frame's payload contradicts its kind.
    ///
    /// Distinct from [`Error::StreamFrameLen`], which reports bytes that have
    /// not arrived yet: feeding more bytes cannot fix this one, so it is fatal.
    StreamPayloadLen { kind: u8, expected: u32, found: u64 },
    /// A stream frame kind is unknown.
    StreamFrameKind(u8),
    /// A stream frame carries flag bits this reader does not implement.
    ///
    /// Distinct from [`Error::UnknownFlags`]: that variant is the image
    /// header's flag word, and a consumer that sees `infinity/flags` knows to
    /// look in one place. A stream fault reports `infinity/stream-flags`.
    StreamFlags(u32),
    /// A stream frame is out of sequence or the stream is truncated.
    StreamSequence { expected: u64, found: u64 },
    /// A frame arrived before `Begin` or after `End`.
    StreamState(&'static str),
    /// The reassembled module hash does not match the `End` frame.
    StreamHashMismatch,
    /// A delta operation cannot be applied to the current module state.
    StreamDelta(&'static str),
    /// The stream ended without an `End` frame.
    StreamUnterminated,
}

impl Error {
    /// Permanent, machine-readable code. Stable across releases.
    pub const fn code(&self) -> &'static str {
        match self {
            Error::Magic => "infinity/magic",
            Error::VersionMajor(_) => "infinity/version-major",
            Error::VersionMinor(_) => "infinity/version-minor",
            Error::HeaderTruncated => "infinity/header-truncated",
            Error::HeaderSize(_) => "infinity/header-size",
            Error::UnknownFlags(_) => "infinity/flags",
            Error::ReservedNonZero { .. } => "infinity/reserved",
            Error::Offset { .. } => "infinity/offset",
            Error::Truncated { .. } => "infinity/truncated",
            Error::TrailingBytes { .. } => "infinity/trailing-bytes",
            Error::Count { .. } => "infinity/count",
            Error::Padding { .. } => "infinity/padding",
            Error::HashMismatch => "infinity/hash-mismatch",
            Error::DialectMismatch(_) => "infinity/dialect",
            Error::NotCanonical => "infinity/not-canonical",
            Error::StringRef(_) => "infinity/string-ref",
            Error::NodeRef(_) => "infinity/node-ref",
            Error::Node { .. } => "infinity/node",
            Error::Utf8 { .. } => "infinity/utf8",
            Error::UnknownUnit(_) => "infinity/unknown-unit",
            Error::UnitRef(_) => "infinity/unit-ref",
            Error::Type { .. } => "infinity/type",
            Error::Edge { .. } | Error::EdgeSet => "infinity/edge",
            Error::Part { .. } => "infinity/node",
            Error::AuxUnreferenced { .. } => "infinity/count",
            Error::Annotation { .. } => "infinity/annotation",
            Error::Provenance(_) => "infinity/provenance",
            Error::Extension { .. } => "infinity/extension",
            Error::Blob { .. } => "infinity/blob",
            Error::SecretEntry(_) => "infinity/secret-entry",
            Error::DuplicateField { .. } => "infinity/duplicate-field",
            Error::DuplicateBinding => "infinity/duplicate-binding",
            Error::Cycle { .. } => "infinity/cycle",
            Error::Depth { .. } => "infinity/depth",
            Error::Limit { .. } => "infinity/limit",
            Error::InvalidArgument(_) => "infinity/invalid-argument",
            Error::Evaluation(_) => "infinity/evaluation",
            Error::Schema(_) => "infinity/schema",
            Error::Compression(_) => "infinity/compression",
            Error::Store(_) => "infinity/store",
            Error::Signature(_) => "infinity/signature",
            Error::Proof(_) => "infinity/proof",
            Error::Encode(_) => "infinity/encode",
            Error::EncodeDangling(_) => "infinity/encode-dangling",
            Error::TooLarge => "infinity/too-large",
            Error::StreamMagic => "infinity/stream-magic",
            Error::StreamVersion(_) => "infinity/stream-version",
            Error::StreamFrameLen { .. } => "infinity/stream-frame-len",
            Error::StreamPayloadLen { .. } => "infinity/stream-payload",
            Error::StreamFrameKind(_) => "infinity/stream-frame-kind",
            Error::StreamFlags(_) => "infinity/stream-flags",
            Error::StreamSequence { .. } => "infinity/stream-sequence",
            Error::StreamState(_) => "infinity/stream-state",
            Error::StreamHashMismatch => "infinity/stream-hash",
            Error::StreamDelta(_) => "infinity/stream-delta",
            Error::StreamUnterminated => "infinity/stream-unterminated",
        }
    }

    /// The evaluator's subordinate code, when this error carries one.
    ///
    /// `Error::Evaluation` wraps the Active evaluator's stable diagnostic class
    /// (`S001`, `T001`, `X00n`, ...). The outer [`Error::code`] stays
    /// `infinity/evaluation` so every evaluator failure is one branch; this
    /// accessor exposes the class without parsing [`std::fmt::Display`]. Every
    /// other variant returns `None`.
    pub const fn sub_code(&self) -> Option<&'static str> {
        match self {
            Error::Evaluation(code) => Some(code),
            _ => None,
        }
    }

    /// True when the input ended early and more bytes may make it valid.
    ///
    /// This is the streaming wait signal: [`crate::StreamDecoder::push_bytes`]
    /// returns `Ok(())` for these faults and waits for the next chunk. They are
    /// deliberately **not** fatal, so a caller that gates a retry on
    /// [`Error::is_fatal`] does not throw away a healthy partial stream. A
    /// one-shot reader has no more bytes to supply and treats every error as
    /// terminal.
    pub const fn is_incomplete(&self) -> bool {
        matches!(self, Error::HeaderTruncated | Error::Truncated { .. })
    }

    /// True when the failure means the input is untrusted or corrupt.
    ///
    /// A fatal error means the bytes cannot be trusted: drop the buffer rather
    /// than retrying with a different configuration. Structure, framing, hash,
    /// canonical-form and stream-frame faults are fatal; an incomplete input is
    /// the one exception (see [`Error::is_incomplete`]).
    ///
    /// A non-fatal error says the operation failed for a reason a different
    /// limit, a different companion file or a retry may fix: `limit` (raise the
    /// ceiling), `invalid-argument`, `evaluation` (the module is valid; the
    /// program failed), `schema`, `compression` and `store` (transient or
    /// media-dependent), `signature` and `proof` (the sidecar, not the image),
    /// `encode` (the caller's own module), `stream-delta` and `stream-state`
    /// (the caller's protocol state).
    pub const fn is_fatal(&self) -> bool {
        matches!(
            self,
            Error::Magic
                | Error::VersionMajor(_)
                | Error::VersionMinor(_)
                | Error::HeaderSize(_)
                | Error::UnknownFlags(_)
                | Error::ReservedNonZero { .. }
                | Error::Offset { .. }
                | Error::TrailingBytes { .. }
                | Error::Count { .. }
                | Error::Padding { .. }
                | Error::HashMismatch
                | Error::DialectMismatch(_)
                | Error::NotCanonical
                | Error::StringRef(_)
                | Error::NodeRef(_)
                | Error::Node { .. }
                | Error::Utf8 { .. }
                | Error::UnknownUnit(_)
                | Error::UnitRef(_)
                | Error::Type { .. }
                | Error::Edge { .. }
                | Error::EdgeSet
                | Error::Part { .. }
                | Error::AuxUnreferenced { .. }
                | Error::Annotation { .. }
                | Error::Provenance(_)
                | Error::Extension { .. }
                | Error::Blob { .. }
                | Error::SecretEntry(_)
                | Error::DuplicateField { .. }
                | Error::DuplicateBinding
                | Error::Cycle { .. }
                | Error::Depth { .. }
                | Error::StreamMagic
                | Error::StreamVersion(_)
                | Error::StreamFrameLen { .. }
                | Error::StreamFrameKind(_)
                | Error::StreamFlags(_)
                | Error::StreamPayloadLen { .. }
                | Error::StreamSequence { .. }
                | Error::StreamHashMismatch
                | Error::StreamUnterminated
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Messages never echo payload bytes: a malformed buffer must not be
        // able to turn an error report into a secret-leak channel.
        match self {
            Error::Magic => write!(f, "not an Active Infinity buffer (bad magic)"),
            Error::VersionMajor(v) => write!(f, "unsupported major version {v}"),
            Error::VersionMinor(v) => write!(f, "unsupported minor version {v}"),
            Error::HeaderTruncated => write!(f, "buffer shorter than the fixed header"),
            Error::HeaderSize(n) => write!(f, "unsupported header size {n}"),
            Error::UnknownFlags(bits) => write!(f, "unknown header flag bits {bits:#06x}"),
            Error::ReservedNonZero { section, offset } => {
                write!(f, "reserved field in {section} is non-zero at {offset}")
            }
            Error::Offset { section, offset } => {
                write!(f, "invalid {section} offset/range at {offset}")
            }
            Error::Truncated { needed, found } => {
                write!(f, "truncated buffer: need {needed} bytes, found {found}")
            }
            Error::TrailingBytes { at } => write!(f, "trailing bytes after {at}"),
            Error::Count { field, value } => write!(f, "invalid {field} count {value}"),
            Error::Padding { offset } => write!(f, "non-zero padding at {offset}"),
            Error::HashMismatch => write!(f, "content hash mismatch"),
            Error::DialectMismatch(h) => write!(f, "dialect hash {h:#018x} not supported"),
            Error::NotCanonical => write!(f, "buffer is not in canonical form"),
            Error::StringRef(id) => write!(f, "dangling string reference {id}"),
            Error::NodeRef(id) => write!(f, "dangling node reference {id}"),
            Error::Node { id, reason } => write!(f, "node {id} is invalid: {reason}"),
            Error::Utf8 { offset } => write!(f, "invalid UTF-8 in string heap at {offset}"),
            Error::UnknownUnit(d) => write!(f, "unknown unit discriminant {d}"),
            Error::UnitRef(id) => write!(f, "dangling unit reference {id}"),
            Error::Type { id, reason } => write!(f, "type {id} is invalid: {reason}"),
            Error::Edge { from, to } => write!(f, "invalid edge {from} -> {to}"),
            Error::EdgeSet => write!(f, "edge table does not match the node references"),
            Error::Part { index, reason } => write!(f, "part {index} is invalid: {reason}"),
            Error::AuxUnreferenced { index } => {
                write!(f, "aux entry {index} is not referenced")
            }
            Error::Annotation { id, reason } => write!(f, "annotation {id} is invalid: {reason}"),
            Error::Provenance(reason) => write!(f, "provenance block is invalid: {reason}"),
            Error::Extension { tag, reason } => {
                write!(f, "extension {tag} is invalid: {reason}")
            }
            Error::Blob { id, reason } => write!(f, "blob {id} is invalid: {reason}"),
            Error::SecretEntry(id) => write!(f, "secret entry {id} is invalid"),
            Error::DuplicateField { node } => write!(f, "table node {node} repeats a field name"),
            Error::DuplicateBinding => write!(f, "duplicate binding name"),
            Error::Cycle { node } => write!(
                f,
                "dependency cycle: node {node} is on a cycle or depends on one"
            ),
            Error::Depth { limit } => write!(f, "nesting deeper than {limit}"),
            Error::Limit { kind, limit } => write!(f, "{kind} limit {limit} exceeded"),
            Error::InvalidArgument(what) => write!(f, "invalid argument: {what}"),
            Error::Evaluation(code) => write!(f, "Active evaluation failed: {code}"),
            Error::Schema(reason) => write!(f, "schema validation failed: {reason}"),
            Error::Compression(reason) => write!(f, "compression failed: {reason}"),
            Error::Store(reason) => write!(f, "store failed: {reason}"),
            Error::Signature(reason) => write!(f, "signature envelope failed: {reason}"),
            Error::Proof(reason) => write!(f, "proof sidecar rejected: {reason}"),
            Error::Encode(what) => write!(f, "cannot encode module: {what}"),
            Error::EncodeDangling(id) => write!(f, "cannot encode: dangling node {id}"),
            Error::TooLarge => write!(f, "module exceeds the 4 GiB addressable image"),
            Error::StreamMagic => write!(f, "not an Active Infinity stream frame"),
            Error::StreamVersion(v) => write!(f, "unsupported stream frame version {v}"),
            Error::StreamFlags(bits) => write!(f, "unknown stream frame flag bits {bits:#06x}"),
            Error::StreamFrameLen {
                declared,
                available,
            } => {
                write!(
                    f,
                    "stream frame declares {declared} bytes, {available} available"
                )
            }
            Error::StreamFrameKind(k) => write!(f, "unknown stream frame kind {k}"),
            Error::StreamPayloadLen {
                kind,
                expected,
                found,
            } => write!(
                f,
                "stream frame kind {kind} needs {expected} payload bytes, found {found}"
            ),
            Error::StreamSequence { expected, found } => {
                write!(
                    f,
                    "stream frame out of order: expected {expected}, got {found}"
                )
            }
            Error::StreamState(what) => write!(f, "stream state error: {what}"),
            Error::StreamHashMismatch => write!(f, "streamed module hash mismatch"),
            Error::StreamDelta(what) => write!(f, "delta cannot be applied: {what}"),
            Error::StreamUnterminated => write!(f, "stream ended without an end frame"),
        }
    }
}

impl std::error::Error for Error {}

// No `From<Utf8Error>`: `valid_up_to` is relative to the slice, while every
// `Error::Utf8` the decoder reports is an absolute image offset. A blanket
// conversion would silently mix the two bases.

#[cfg(test)]
mod code_tests {
    use super::*;

    /// Every variant of [`Error`], so a code can be checked for uniqueness and
    /// documentation without a running parser.
    ///
    /// A new variant must be added here: this list is also the reverse gate that
    /// `docs/spec/layout.md` documents every code the crate can return.
    fn every_variant() -> Vec<Error> {
        vec![
            Error::Magic,
            Error::VersionMajor(2),
            Error::VersionMinor(9),
            Error::HeaderTruncated,
            Error::HeaderSize(1),
            Error::UnknownFlags(1),
            Error::ReservedNonZero {
                section: "header",
                offset: 0,
            },
            Error::Offset {
                section: "nodes",
                offset: 0,
            },
            Error::Truncated {
                needed: 1,
                found: 0,
            },
            Error::TrailingBytes { at: 0 },
            Error::Count {
                field: "nodes",
                value: 1,
            },
            Error::Padding { offset: 0 },
            Error::HashMismatch,
            Error::DialectMismatch(1),
            Error::NotCanonical,
            Error::StringRef(0),
            Error::NodeRef(0),
            Error::Node {
                id: 0,
                reason: "test",
            },
            Error::Utf8 { offset: 0 },
            Error::UnknownUnit(0),
            Error::UnitRef(0),
            Error::Type {
                id: 0,
                reason: "test",
            },
            Error::Edge { from: 0, to: 1 },
            Error::Annotation {
                id: 0,
                reason: "test",
            },
            Error::Provenance("test"),
            Error::Extension {
                tag: 0,
                reason: "test",
            },
            Error::Blob {
                id: 0,
                reason: "test",
            },
            Error::SecretEntry(0),
            Error::DuplicateField { node: 0 },
            Error::DuplicateBinding,
            Error::Cycle { node: 0 },
            Error::Depth { limit: 1 },
            Error::Limit {
                kind: "test",
                limit: 1,
            },
            Error::InvalidArgument("test"),
            Error::Evaluation("S001"),
            Error::Schema("test"),
            Error::Compression("test"),
            Error::Store("test"),
            Error::Signature("test"),
            Error::Proof("test"),
            Error::Encode("test"),
            Error::EncodeDangling(0),
            Error::TooLarge,
            Error::StreamMagic,
            Error::StreamVersion(9),
            Error::StreamFrameLen {
                declared: 1,
                available: 0,
            },
            Error::StreamFrameKind(9),
            Error::StreamFlags(9),
            Error::StreamPayloadLen {
                kind: 2,
                expected: 24,
                found: 23,
            },
            Error::StreamSequence {
                expected: 1,
                found: 2,
            },
            Error::StreamState("test"),
            Error::StreamHashMismatch,
            Error::StreamDelta("test"),
            Error::StreamUnterminated,
        ]
    }

    #[test]
    fn codes_are_unique_and_every_code_is_documented() {
        let spec = include_str!("../docs/spec/layout.md");
        let mut seen = std::collections::BTreeSet::new();
        for error in every_variant() {
            let code = error.code();
            assert!(
                seen.insert(code),
                "two variants share the code {code}: {error:?}"
            );
            assert!(
                spec.contains(&format!("| `{code}` |")),
                "docs/spec/layout.md must document {code} as its own table row"
            );
        }
        assert!(
            seen.len() >= 51,
            "the variant list should cover the whole surface, found {}",
            seen.len()
        );
    }

    #[test]
    fn the_fatal_classification_matches_its_documented_rule() {
        for fatal in [
            Error::Magic,
            Error::NotCanonical,
            Error::NodeRef(0),
            Error::HashMismatch,
            Error::StreamHashMismatch,
            // A frame past the wire ceiling is permanent: more bytes cannot make
            // it valid.
            Error::StreamFrameLen {
                declared: u32::MAX,
                available: 40,
            },
        ] {
            assert!(fatal.is_fatal(), "{fatal:?} is a corrupt-input fault");
        }
        // An incomplete input may become valid once more bytes arrive, and a
        // caller-side encode fault says nothing about the input's trust.
        for incomplete in [
            Error::HeaderTruncated,
            Error::Truncated {
                needed: 4,
                found: 0,
            },
        ] {
            assert!(!incomplete.is_fatal(), "{incomplete:?} is incomplete");
            assert!(incomplete.is_incomplete(), "{incomplete:?} waits for bytes");
        }
        for caller_side in [Error::TooLarge, Error::EncodeDangling(0)] {
            assert!(
                !caller_side.is_fatal(),
                "{caller_side:?} is the caller's fault"
            );
            assert!(!caller_side.is_incomplete());
        }
        for recoverable in [
            Error::InvalidArgument("test"),
            Error::Limit {
                kind: "test",
                limit: 1,
            },
            Error::Evaluation("S001"),
            Error::Schema("test"),
            Error::Compression("test"),
            Error::Store("test"),
            Error::Signature("test"),
            Error::Proof("test"),
            Error::Encode("test"),
            Error::StreamDelta("test"),
            Error::StreamState("test"),
        ] {
            assert!(
                !recoverable.is_fatal(),
                "{recoverable:?} does not mean the bytes are corrupt"
            );
        }
    }

    #[test]
    fn only_an_evaluation_error_carries_a_sub_code() {
        assert_eq!(Error::Evaluation("T001").sub_code(), Some("T001"));
        assert_eq!(Error::Magic.sub_code(), None);
        assert_eq!(Error::Schema("shape").sub_code(), None);
    }
}
