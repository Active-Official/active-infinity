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
    /// Header is shorter than the fixed 160-byte prefix.
    HeaderTruncated,
    /// Header `header_size` field is not the supported fixed size.
    HeaderSize(u8),
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
    /// A stream frame length exceeds the limit or the available bytes.
    StreamFrameLen { declared: u32, available: u64 },
    /// A stream frame kind is unknown.
    StreamFrameKind(u8),
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
            Error::Edge { .. } => "infinity/edge",
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
            Error::Encode(_) => "infinity/encode",
            Error::EncodeDangling(_) => "infinity/encode-dangling",
            Error::TooLarge => "infinity/too-large",
            Error::StreamMagic => "infinity/stream-magic",
            Error::StreamVersion(_) => "infinity/stream-version",
            Error::StreamFrameLen { .. } => "infinity/stream-frame-len",
            Error::StreamFrameKind(_) => "infinity/stream-frame-kind",
            Error::StreamSequence { .. } => "infinity/stream-sequence",
            Error::StreamState(_) => "infinity/stream-state",
            Error::StreamHashMismatch => "infinity/stream-hash",
            Error::StreamDelta(_) => "infinity/stream-delta",
            Error::StreamUnterminated => "infinity/stream-unterminated",
        }
    }

    /// True when the failure means the input is untrusted or corrupt.
    ///
    /// All decode-side failures are fatal for the buffer: callers must drop
    /// it rather than retrying with a different configuration.
    pub const fn is_fatal(&self) -> bool {
        !matches!(self, Error::InvalidArgument(_))
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
            Error::Encode(what) => write!(f, "cannot encode module: {what}"),
            Error::EncodeDangling(id) => write!(f, "cannot encode: dangling node {id}"),
            Error::TooLarge => write!(f, "module exceeds the 4 GiB addressable image"),
            Error::StreamMagic => write!(f, "not an Active Infinity stream frame"),
            Error::StreamVersion(v) => write!(f, "unsupported stream frame version {v}"),
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

impl From<std::str::Utf8Error> for Error {
    fn from(_: std::str::Utf8Error) -> Self {
        Error::Utf8 { offset: 0 }
    }
}
