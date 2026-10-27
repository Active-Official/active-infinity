//! Protobuf-wire interop projection.
//!
//! Active Infinity is the canonical form, and it is the form peers should
//! exchange. The rest of the world, however, speaks Protobuf: dashboards,
//! queues, analytics, tracing pipelines and every language with a generated
//! client. This module renders a module into protobuf wire format so those
//! consumers can read Active data without implementing the AINF layout, and so
//! an Active producer can feed existing infrastructure directly.
//!
//! The projection is **redacted by construction**: it is built from the same
//! [`crate::interop::Projected`] tree as the JSON projection, so secrets are
//! replaced by [`crate::interop::SECRET_MARKER`] before a single byte is
//! written. Blob payloads never leave the module; only their identity does.
//!
//! # Schema
//!
//! ```proto
//! syntax = "proto3";
//! package active.infinity.v1;
//!
//! message Module {
//!   bytes content_hash = 1;   // Blake3-256 of the canonical AINF image
//!   uint64 total_size = 2;    // canonical AINF image size in bytes
//!   Value root = 3;           // omitted when the module has no root
//!   repeated Binding bindings = 4;
//!   Provenance provenance = 5; // omitted when absent
//!   repeated Annotation annotations = 6;
//!   repeated Extension extensions = 7;
//! }
//!
//! message Binding { string name = 1; Value value = 2; }
//!
//! message Annotation {
//!   uint32 subject = 1;      // node id
//!   oneof kind {
//!     string intent = 2;     // documentation only
//!     Constraint constraint = 3;
//!     bool ai_immutable = 4;
//!   }
//! }
//! message Constraint { string source = 1; uint32 expr = 2; }
//!
//! message Provenance {
//!   string producer = 1;
//!   uint64 timestamp_ms = 2;
//!   string model = 3;
//!   string tool = 4;
//!   bytes parent = 5;        // omitted when absent (32 bytes when present)
//!   repeated Entry entries = 6;
//!   message Entry {
//!     string key = 1;
//!     oneof value {
//!       string text = 2;
//!       sint64 integer = 3;
//!       bool flag = 4;
//!       bytes hash = 5;      // 32 bytes
//!     }
//!   }
//! }
//!
//! message Extension { uint64 tag = 1; bytes payload = 2; }
//!
//! message Value {
//!   oneof kind {
//!     Null null_value = 1;
//!     bool boolean = 2;
//!     sint64 integer = 3;
//!     double float = 4;
//!     string text = 5;
//!     Ms duration_ms = 6;
//!     Quantity quantity = 7;
//!     List list = 8;
//!     Record record = 9;
//!     Blob blob = 10;
//!     Env env = 11;
//!     Expr expr = 12;
//!   }
//! }
//! message Null {}
//! message Ms { uint64 ms = 1; }
//! message Quantity { Value value = 1; string unit = 2; }
//! message List { repeated Value items = 1; }
//! message Record { repeated Field fields = 1; }
//! message Field { string name = 1; Value value = 2; }
//! message Blob {
//!   bytes blake3 = 1;        // 32 bytes
//!   uint64 size = 2;
//!   string media_type = 3;
//!   bool tainted = 4;
//! }
//! message Env { string name = 1; }
//! message Expr { string kind = 1; }
//! ```
//!
//! # Encoding rules
//!
//! Rewriting a module always produces identical bytes, which lets consumers
//! hash, cache and diff the projection:
//!
//! - fields are emitted in ascending field-number order (`#[prost]`-generated
//!   structs parse it, and so does every conformant reader);
//! - scalar fields are emitted even when they equal the proto3 default, so the
//!   encoding is injective for the projected tree;
//! - absent optional messages (`root`, `provenance`) and empty repeated fields
//!   are omitted;
//! - varints are minimal, `sint64` uses zig-zag, `double` is little-endian
//!   IEEE-754, and every length prefix is exact.

use crate::encode::{encode, hash_image};
use crate::error::Result;
use crate::interop::{project_node_with, redacted_key, secret_table, Projected};
use crate::ir::{AnnotationKind, InfinityModule, ProvValue};

// ---------------------------------------------------------------------------
// wire primitives
// ---------------------------------------------------------------------------

const WIRE_VARINT: u8 = 0;
const WIRE_DOUBLE: u8 = 1;
const WIRE_LEN: u8 = 2;

fn varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn tag(out: &mut Vec<u8>, field: u32, wire: u8) {
    varint(out, (u64::from(field) << 3) | u64::from(wire));
}

fn uint(out: &mut Vec<u8>, field: u32, value: u64) {
    tag(out, field, WIRE_VARINT);
    varint(out, value);
}

fn sint(out: &mut Vec<u8>, field: u32, value: i64) {
    tag(out, field, WIRE_VARINT);
    varint(out, ((value << 1) ^ (value >> 63)) as u64);
}

fn boolean(out: &mut Vec<u8>, field: u32, value: bool) {
    tag(out, field, WIRE_VARINT);
    varint(out, u64::from(value));
}

fn double(out: &mut Vec<u8>, field: u32, value: f64) {
    tag(out, field, WIRE_DOUBLE);
    out.extend_from_slice(&value.to_bits().to_le_bytes());
}

fn bytes(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    tag(out, field, WIRE_LEN);
    varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn string(out: &mut Vec<u8>, field: u32, value: &str) {
    bytes(out, field, value.as_bytes());
}

fn message(out: &mut Vec<u8>, field: u32, body: &[u8]) {
    bytes(out, field, body);
}

// ---------------------------------------------------------------------------
// value tree
// ---------------------------------------------------------------------------

fn encode_value(value: &Projected, out: &mut Vec<u8>) {
    match value {
        Projected::Null => message(out, 1, &[]),
        Projected::Bool(flag) => boolean(out, 2, *flag),
        Projected::Int(number) => sint(out, 3, *number),
        Projected::Float(number) => double(out, 4, *number),
        Projected::Text(text) => string(out, 5, text),
        Projected::DurationMs(ms) => {
            let mut body = Vec::new();
            uint(&mut body, 1, *ms);
            message(out, 6, &body);
        }
        Projected::Quantity(value, unit) => {
            let mut body = Vec::new();
            let mut inner = Vec::new();
            encode_value(value, &mut inner);
            message(&mut body, 1, &inner);
            string(&mut body, 2, unit);
            message(out, 7, &body);
        }
        Projected::Array(items) => {
            let mut body = Vec::new();
            for item in items {
                let mut encoded = Vec::new();
                encode_value(item, &mut encoded);
                message(&mut body, 1, &encoded);
            }
            message(out, 8, &body);
        }
        Projected::Record(fields) => {
            let mut body = Vec::new();
            for (name, value) in fields {
                let mut field = Vec::new();
                string(&mut field, 1, name);
                let mut encoded = Vec::new();
                encode_value(value, &mut encoded);
                message(&mut field, 2, &encoded);
                message(&mut body, 1, &field);
            }
            message(out, 9, &body);
        }
        Projected::Blob {
            hash,
            size,
            media_type,
            tainted,
        } => {
            let mut body = Vec::new();
            bytes(&mut body, 1, hash);
            uint(&mut body, 2, *size);
            string(&mut body, 3, media_type);
            boolean(&mut body, 4, *tainted);
            message(out, 10, &body);
        }
        Projected::Env(name) => {
            let mut body = Vec::new();
            string(&mut body, 1, name);
            message(out, 11, &body);
        }
        Projected::Expr(kind) => {
            let mut body = Vec::new();
            string(&mut body, 1, kind);
            message(out, 12, &body);
        }
    }
}

// ---------------------------------------------------------------------------
// module
// ---------------------------------------------------------------------------

/// Project `module` into protobuf wire format.
///
/// The result is deterministic and redacted. The `content_hash` field is the
/// Blake3-256 of the canonical AINF image, so a consumer can request or verify
/// the authoritative bytes with [`crate::validate`] and the usual content
/// addressing.
///
/// A module that cannot be encoded canonically (a cycle, a dangling reference,
/// a duplicate binding) is refused instead of being projected approximately.
pub fn to_protobuf(module: &InfinityModule) -> Result<Vec<u8>> {
    let image = encode(module)?;
    let hash = hash_image(&image)?;
    let secrets = secret_table(module);

    let mut out = Vec::new();
    bytes(&mut out, 1, &hash);
    uint(&mut out, 2, image.len() as u64);

    if let Some(root) = module.root() {
        let value = project_node_with(module, root, &secrets)?;
        let mut body = Vec::new();
        encode_value(&value, &mut body);
        message(&mut out, 3, &body);
    }

    for (name, id) in module.bindings() {
        let value = project_node_with(module, *id, &secrets)?;
        let mut binding = Vec::new();
        string(&mut binding, 1, &redacted_key(name, &secrets));
        let mut encoded = Vec::new();
        encode_value(&value, &mut encoded);
        message(&mut binding, 2, &encoded);
        message(&mut out, 4, &binding);
    }

    if let Some(prov) = module.provenance() {
        message(&mut out, 5, &encode_provenance(prov, &secrets));
    }

    for annotation in module.annotations() {
        message(&mut out, 6, &encode_annotation(annotation, &secrets));
    }

    for (tag, payload) in module.extensions() {
        let mut extension = Vec::new();
        uint(&mut extension, 1, *tag);
        bytes(&mut extension, 2, payload);
        message(&mut out, 7, &extension);
    }

    Ok(out)
}

fn encode_annotation(annotation: &crate::ir::Annotation, secrets: &[String]) -> Vec<u8> {
    let mut body = Vec::new();
    uint(&mut body, 1, annotation.node.index() as u64);
    match &annotation.kind {
        AnnotationKind::Intent(text) => string(&mut body, 2, &redacted_key(text, secrets)),
        AnnotationKind::Constraint { source, expr } => {
            let mut constraint = Vec::new();
            string(&mut constraint, 1, &redacted_key(source, secrets));
            uint(&mut constraint, 2, expr.index() as u64);
            message(&mut body, 3, &constraint);
        }
        AnnotationKind::AiImmutable(flag) => boolean(&mut body, 4, *flag),
    }
    body
}

fn encode_provenance(prov: &crate::ir::Provenance, secrets: &[String]) -> Vec<u8> {
    let mut body = Vec::new();
    string(
        &mut body,
        1,
        &redacted_key(prov.producer.as_deref().unwrap_or(""), secrets),
    );
    uint(&mut body, 2, prov.timestamp_ms);
    string(
        &mut body,
        3,
        &redacted_key(prov.model.as_deref().unwrap_or(""), secrets),
    );
    string(
        &mut body,
        4,
        &redacted_key(prov.tool.as_deref().unwrap_or(""), secrets),
    );
    if let Some(parent) = &prov.parent {
        bytes(&mut body, 5, parent);
    }
    for entry in &prov.entries {
        let mut encoded = Vec::new();
        string(&mut encoded, 1, &redacted_key(&entry.key, secrets));
        match &entry.value {
            ProvValue::Text(text) => string(&mut encoded, 2, &redacted_key(text, secrets)),
            ProvValue::Int(number) => sint(&mut encoded, 3, *number),
            ProvValue::Flag(flag) => boolean(&mut encoded, 4, *flag),
            ProvValue::Hash(hash) => bytes(&mut encoded, 5, hash),
        }
        message(&mut body, 6, &encoded);
    }
    body
}
