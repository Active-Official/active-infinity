//! Active Infinity (Active ∞) — the canonical binary form of Active modules.
//!
//! Active Infinity is a graph-native, unit-aware, secret-safe, canonical,
//! content-addressed binary data language for the Active ecosystem. It is the
//! runtime, storage, network and agent-to-agent exchange format for Active
//! modules: safer and faster than JSON for configuration and data, deterministic
//! by construction, and designed so that an untrusted buffer can be validated
//! in one bounded pass before any of it is trusted.
//!
//! # Quick start
//!
//! ```
//! use active_infinity::{Inode, InfinityModule, encode, decode, content_hash};
//!
//! let mut module = InfinityModule::new();
//! let hello = module.push(Inode::Str("hello".into()));
//! let number = module.push(Inode::Int(42));
//! let table = module.push(Inode::Table {
//!     fields: vec![("greeting".into(), hello), ("answer".into(), number)],
//! });
//! module.set_root(Some(table));
//!
//! let bytes = encode(&module).unwrap();
//! let decoded = decode(&bytes).unwrap();
//! assert_eq!(decoded, module);
//! assert_eq!(encode(&decoded).unwrap(), bytes);
//! assert_eq!(content_hash(&bytes).unwrap(), content_hash(&encode(&decoded).unwrap()).unwrap());
//! ```
//!
//! # The four guarantees
//!
//! 1. **Canonical identity.** Logically equal modules encode to identical
//!    bytes, and the Blake3 content hash covers the whole canonical payload, so
//!    content addressing is a real identity (`canonical`, `encode`).
//! 2. **Fail-closed validation.** Wrong magic/version, truncation, out-of-range
//!    offsets and counts, invalid UTF-8, unknown unit discriminants, cycles,
//!    unreachable nodes, non-canonical slack and size bombs are rejected with
//!    stable machine-readable codes before allocation (`validate`, `error`).
//! 3. **Secrets stay secrets.** Secret material is a structural kind, never
//!    equals anything (no oracle), carries no `Debug`/`Display`/`Serialize`
//!    path, and is absent from every export path (`ir::SecretBytes`).
//! 4. **Zero-copy and streaming.** A validated buffer can be read through
//!    [`view::InfinityView`] without copying strings or blobs, and a module can
//!    be shipped as ordered frames that reassemble to the identical canonical
//!    bytes and hash, including incremental deltas (`stream`).
//!
//! # Feature flags
//!
//! - `active-core` (default): interop with the Active text language IR
//!   (`interop::from_active_core`, `to_active_core`).
//! - `json` (default): the redacted JSON projection
//!   (`interop::to_redacted_json`).
//!
//! Both can be disabled for a dependency-free wire codec.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod canonical;
pub mod decode;
pub mod encode;
pub mod error;
pub mod interop;
pub mod ir;
pub mod layout;
pub mod protobuf;
pub mod stream;
pub mod unit;
pub mod validate;
pub mod view;

pub use decode::{decode, decode_with};
pub use encode::{encode, encode_with, hash_image};
pub use error::{Error, Result};
pub use ir::{
    Annotation, AnnotationKind, BinOp, Constraint, InfinityModule, Inode, InterpPart,
    ModuleBuilder, NodeId, PatchOp, ProvEntry, ProvKind, ProvValue, Provenance, SchemaFieldSpec,
    SecretBytes, SemanticTag, SerializedKind, TypeSpec, UnOp,
};
pub use layout::{
    dialect_hash, DecodeOpts, EncodeOpts, Limits, Meta, Section, FLAG_CANONICAL, FORMAT_MAJOR,
    FORMAT_MINOR, HEADER_SIZE,
};
pub use protobuf::to_protobuf;
pub use stream::{Frame, FrameKind, StreamDecoder, StreamEncoder};
pub use unit::UnitTag;
pub use validate::{validate, validate_canonical, validate_with, Validated};
pub use view::{InfinityView, NodeView};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Magic bytes at the start of every Active Infinity module.
pub const MAGIC: [u8; 4] = layout::MAGIC;

/// Compute the Blake3-256 content hash of a validated image.
///
/// The hash covers the whole canonical payload with the stored hash field
/// zeroed, so it changes when any canonical byte changes and is stable across
/// runs and processes.
pub fn content_hash(bytes: &[u8]) -> Result<[u8; 32]> {
    let validated = Validated::new(bytes, DecodeOpts::default())?;
    Ok(validated.header().content_hash)
}

/// Hex form of [`content_hash`].
pub fn content_hash_hex(bytes: &[u8]) -> Result<String> {
    content_hash(bytes).map(|hash| ir::hash_hex(&hash))
}

/// Encode a module and return `(bytes, hash)`.
pub fn encode_hashed(module: &InfinityModule) -> Result<(Vec<u8>, [u8; 32])> {
    let bytes = encode(module)?;
    let hash = hash_image(&bytes)?;
    Ok((bytes, hash))
}
