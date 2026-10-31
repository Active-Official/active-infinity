//! Active Infinity's in-memory module model.
//!
//! This is the *canonical* IR: the encoder is a pure function of it, and the
//! decoder reproduces it exactly. It deliberately does **not** mirror the
//! `active-core` arena layout: the wire format is versioned independently of
//! any dependency's semver (see ADR-0002). Interop with the text language IR
//! lives in [`crate::interop`] behind the `active-core` feature.
//!
//! Structural invariants upheld by [`InfinityModule::validate_structure`]:
//!
//! - every referenced node id exists (no dangling references);
//! - table fields, binding names and array nodes are unique where required;
//! - the dependency graph is acyclic (Active rejects cycles before any value
//!   exists);
//! - nesting depth stays within the caller's budget.
//!
//! Secret material is held in [`SecretBytes`], which has **no** `Display`,
//! `Debug`, `Serialize` or equality path that can reveal it.

// The variant and field names in this module are the wire contract itself and
// are documented normatively in `docs/spec/layout.md`; per-variant rustdoc would
// duplicate that table without adding information.
#![allow(missing_docs)]

use std::collections::HashMap;
use std::fmt;

/// Index into the module arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub u32);

impl NodeId {
    /// Sentinel for "no node".
    pub const NONE: NodeId = NodeId(u32::MAX);

    pub fn index(self) -> usize {
        self.0 as usize
    }

    pub fn is_none(self) -> bool {
        self == NodeId::NONE
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "n{}", self.0)
    }
}

/// A secret string held structurally.
///
/// The type exposes no way to read the bytes back through a public API: the
/// wire codec and the `active-core` bridge are the only in-crate readers, and
/// both are audited. `Debug`, `Display`, `PartialEq`, `Ord` and `Hash` are all
/// deliberately absent or redacting, so a secret can never leak through
/// logging, assertion output, sorting or map keys, and can never be compared
/// for equality (the anti-oracle rule).
#[derive(Clone)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wrap raw bytes as a secret.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        SecretBytes(bytes.into())
    }

    /// Number of bytes — length is not secret material and is used by
    /// budgets and diagnostics.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Read the raw bytes. Crate-internal: only the audited codec and the
    /// `active-core` bridge call this. There is no public unlock API.
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***SECRET***")
    }
}

impl PartialEq for SecretBytes {
    /// Anti-oracle: a secret never equals anything, including itself.
    fn eq(&self, _other: &Self) -> bool {
        false
    }
}

impl From<&str> for SecretBytes {
    fn from(value: &str) -> Self {
        SecretBytes(value.as_bytes().to_vec())
    }
}

impl From<String> for SecretBytes {
    fn from(value: String) -> Self {
        SecretBytes(value.into_bytes())
    }
}

/// Binary operators, with permanent wire codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

impl BinOp {
    pub const fn code(self) -> u32 {
        match self {
            BinOp::Add => 0,
            BinOp::Sub => 1,
            BinOp::Mul => 2,
            BinOp::Div => 3,
            BinOp::Eq => 4,
            BinOp::Ne => 5,
            BinOp::Lt => 6,
            BinOp::Le => 7,
            BinOp::Gt => 8,
            BinOp::Ge => 9,
            BinOp::And => 10,
            BinOp::Or => 11,
        }
    }

    pub const fn from_code(code: u32) -> Option<Self> {
        let op = match code {
            0 => BinOp::Add,
            1 => BinOp::Sub,
            2 => BinOp::Mul,
            3 => BinOp::Div,
            4 => BinOp::Eq,
            5 => BinOp::Ne,
            6 => BinOp::Lt,
            7 => BinOp::Le,
            8 => BinOp::Gt,
            9 => BinOp::Ge,
            10 => BinOp::And,
            11 => BinOp::Or,
            _ => return None,
        };
        Some(op)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::Div => "/",
            BinOp::Eq => "==",
            BinOp::Ne => "!=",
            BinOp::Lt => "<",
            BinOp::Le => "<=",
            BinOp::Gt => ">",
            BinOp::Ge => ">=",
            BinOp::And => "and",
            BinOp::Or => "or",
        }
    }
}

/// Unary operators, with permanent wire codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnOp {
    Neg,
    Not,
}

impl UnOp {
    pub const fn code(self) -> u32 {
        match self {
            UnOp::Neg => 0,
            UnOp::Not => 1,
        }
    }

    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(UnOp::Neg),
            1 => Some(UnOp::Not),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            UnOp::Neg => "-",
            UnOp::Not => "!",
        }
    }
}

/// Semantic tag for a multi-line string block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticTag {
    Prompt,
    Policy,
    Template,
}

impl SemanticTag {
    pub const fn code(self) -> u32 {
        match self {
            SemanticTag::Prompt => 0,
            SemanticTag::Policy => 1,
            SemanticTag::Template => 2,
        }
    }

    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(SemanticTag::Prompt),
            1 => Some(SemanticTag::Policy),
            2 => Some(SemanticTag::Template),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            SemanticTag::Prompt => "prompt",
            SemanticTag::Policy => "policy",
            SemanticTag::Template => "template",
        }
    }
}

/// One interpolation part.
#[derive(Clone, PartialEq)]
pub enum InterpPart {
    Literal(String),
    Expr(NodeId),
}

impl fmt::Debug for InterpPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InterpPart::Literal(text) => write!(f, "Literal(<{} bytes>)", text.len()),
            InterpPart::Expr(id) => write!(f, "Expr({id})"),
        }
    }
}

/// A runtime constraint attached to a node (`@constraint` predicates and
/// schema bounds).
#[derive(Clone, PartialEq)]
pub enum Constraint {
    MinMax { min: Option<i64>, max: Option<i64> },
    Enum(Vec<String>),
    Pattern(String),
    Odd,
    Custom(String),
}

impl fmt::Debug for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Constraint::MinMax { min, max } => {
                write!(f, "MinMax {{ min: {min:?}, max: {max:?} }}")
            }
            Constraint::Enum(values) => write!(f, "Enum(<{} values>)", values.len()),
            Constraint::Pattern(_) => f.write_str("Pattern(<redacted>)"),
            Constraint::Odd => f.write_str("Odd"),
            Constraint::Custom(_) => f.write_str("Custom(<redacted>)"),
        }
    }
}

/// Declared value type of a schema field.
#[derive(Clone, PartialEq)]
pub enum TypeSpec {
    Null,
    Bool,
    Int,
    Float,
    String,
    Duration,
    Bytes,
    Table { closed: bool },
    Enum(Vec<String>),
    Secret,
    Any,
    Blob,
}

impl fmt::Debug for TypeSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeSpec::Table { closed } => write!(f, "Table {{ closed: {closed} }}"),
            TypeSpec::Enum(values) => write!(f, "Enum(<{} values>)", values.len()),
            other => f.write_str(other.name().as_str()),
        }
    }
}

impl TypeSpec {
    pub const fn code(&self) -> u32 {
        match self {
            TypeSpec::Null => 0,
            TypeSpec::Bool => 1,
            TypeSpec::Int => 2,
            TypeSpec::Float => 3,
            TypeSpec::String => 4,
            TypeSpec::Duration => 5,
            TypeSpec::Bytes => 6,
            TypeSpec::Table { .. } => 7,
            TypeSpec::Enum(_) => 8,
            TypeSpec::Secret => 9,
            TypeSpec::Any => 10,
            TypeSpec::Blob => 11,
        }
    }

    /// Human-readable name for diagnostics (mirrors `active-core`).
    pub fn name(&self) -> String {
        match self {
            TypeSpec::Null => "Null".into(),
            TypeSpec::Bool => "Bool".into(),
            TypeSpec::Int => "Int".into(),
            TypeSpec::Float => "Float".into(),
            TypeSpec::String => "String".into(),
            TypeSpec::Duration => "Duration".into(),
            TypeSpec::Bytes => "Bytes".into(),
            TypeSpec::Table { closed } => {
                if *closed {
                    "Table(closed)".into()
                } else {
                    "Table".into()
                }
            }
            TypeSpec::Enum(values) => format!("Enum({})", values.join(", ")),
            TypeSpec::Secret => "Secret".into(),
            TypeSpec::Any => "Any".into(),
            TypeSpec::Blob => "Blob".into(),
        }
    }
}

/// A structural patch operation.
#[derive(Clone, PartialEq)]
pub enum PatchOp {
    Set { path: String, value: NodeId },
    Remove { path: String },
    Rename { from: String, to: String },
}

impl fmt::Debug for PatchOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatchOp::Set { value, .. } => write!(f, "Set {{ path: <redacted>, value: {value} }}"),
            PatchOp::Remove { .. } => f.write_str("Remove { path: <redacted> }"),
            PatchOp::Rename { .. } => f.write_str("Rename { from: <redacted>, to: <redacted> }"),
        }
    }
}

/// One schema field's constraints.
#[derive(Clone, PartialEq)]
pub struct SchemaFieldSpec {
    pub typ: TypeSpec,
    pub min: Option<NodeId>,
    pub max: Option<NodeId>,
    pub min_len: Option<NodeId>,
    pub max_len: Option<NodeId>,
    pub pattern: Option<NodeId>,
    pub default: Option<NodeId>,
    pub deprecated: Option<String>,
}

impl fmt::Debug for SchemaFieldSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchemaFieldSpec")
            .field("typ", &self.typ)
            .field("min", &self.min)
            .field("max", &self.max)
            .field("min_len", &self.min_len)
            .field("max_len", &self.max_len)
            .field("pattern", &self.pattern)
            .field("default", &self.default)
            .field(
                "deprecated",
                &self.deprecated.as_ref().map(|text| text.len()),
            )
            .finish()
    }
}

impl SchemaFieldSpec {
    pub fn bare(typ: TypeSpec) -> Self {
        Self {
            typ,
            min: None,
            max: None,
            min_len: None,
            max_len: None,
            pattern: None,
            default: None,
            deprecated: None,
        }
    }
}

/// A module node.
///
/// Every variant is a value of the Active IR after name resolution; `Ident`
/// is retained only because decoded third-party modules may still contain
/// one (the encoder never emits it for canonical modules produced from
/// `active-core`).
///
/// `Debug` is written by hand (never derived): blob payloads are summarized
/// by identity and secrets render as `Secret(***)`, so logging a module can
/// never dump payload or secret bytes.
#[derive(Clone, PartialEq)]
pub enum Inode {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    DurationMs(u64),
    Quantity {
        value: NodeId,
        unit: super::UnitTag,
    },
    Array {
        elements: Vec<NodeId>,
    },
    Table {
        fields: Vec<(String, NodeId)>,
    },
    /// A structural secret literal. Never equals anything.
    Secret(SecretBytes),
    /// A secret derived from a locator node (`secret.env(NAME)`,
    /// `secret(<expr>)`).
    SecretRef {
        locator: NodeId,
    },
    Ref(NodeId),
    Env {
        name: String,
        default: Option<NodeId>,
    },
    Ident(String),
    Interpolate {
        parts: Vec<InterpPart>,
    },
    Binary {
        op: BinOp,
        lhs: NodeId,
        rhs: NodeId,
    },
    Unary {
        op: UnOp,
        expr: NodeId,
    },
    Constrained {
        target: NodeId,
        constraint: Constraint,
    },
    Patch(PatchOp),
    SchemaField(SchemaFieldSpec),
    SchemaTable {
        fields: Vec<(String, NodeId)>,
        closed: bool,
    },
    SchemaArray {
        element: NodeId,
    },
    Semantic {
        tag: SemanticTag,
        inner: NodeId,
    },
    /// `blob(media_type, data)` construction site (reserved kind 24).
    ContentAddressed {
        media_type: NodeId,
        data: NodeId,
    },
    /// A materialised content-addressed blob identity.
    ///
    /// `payload` is present only for untainted blobs that were materialised;
    /// a tainted blob never carries bytes, and the codec refuses a tainted
    /// blob entry whose payload is non-empty.
    Blob {
        hash: [u8; 32],
        size: u64,
        tainted: bool,
        media_type: String,
        payload: Option<Vec<u8>>,
    },
}

impl fmt::Debug for Inode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Inode::Null => f.write_str("Null"),
            Inode::Bool(value) => write!(f, "Bool({value})"),
            Inode::Int(value) => write!(f, "Int({value})"),
            Inode::Float(value) => write!(f, "Float({value})"),
            Inode::Str(value) => write!(f, "Str(<{} bytes>)", value.len()),
            Inode::DurationMs(ms) => write!(f, "DurationMs({ms})"),
            Inode::Quantity { value, .. } => write!(f, "Quantity({value}, <unit>)"),
            Inode::Array { elements } => write!(f, "Array({elements:?})"),
            Inode::Table { fields } => write!(f, "Table(<{} fields>)", fields.len()),
            Inode::Secret(_) => f.write_str("Secret(***)"),
            Inode::SecretRef { locator } => write!(f, "SecretRef({locator})"),
            Inode::Ref(id) => write!(f, "Ref({id})"),
            Inode::Env { name, default } => write!(f, "Env(<{} bytes>, {default:?})", name.len()),
            Inode::Ident(name) => write!(f, "Ident(<{} bytes>)", name.len()),
            Inode::Interpolate { parts } => write!(f, "Interpolate(<{} parts>)", parts.len()),
            Inode::Binary { op, lhs, rhs } => write!(f, "Binary({}, {lhs}, {rhs})", op.as_str()),
            Inode::Unary { op, expr } => write!(f, "Unary({}, {expr})", op.as_str()),
            Inode::Constrained { target, .. } => {
                write!(f, "Constrained({target}, <constraint>)")
            }
            Inode::Patch(_) => f.write_str("Patch(<op>)"),
            Inode::SchemaField(_) => f.write_str("SchemaField(<spec>)"),
            Inode::SchemaTable { fields, closed } => {
                write!(f, "SchemaTable(<{} fields>, closed={closed})", fields.len())
            }
            Inode::SchemaArray { element } => write!(f, "SchemaArray({element})"),
            Inode::Semantic { tag, inner } => write!(f, "Semantic({}, {inner})", tag.as_str()),
            Inode::ContentAddressed { data, .. } => {
                write!(f, "ContentAddressed(<media>, {data})")
            }
            Inode::Blob {
                hash,
                size,
                tainted,
                media_type,
                payload,
            } => write!(
                f,
                "Blob(blake3:{}, size={size}, media=<{} bytes>, tainted={tainted}, payload={})",
                hash_hex(hash),
                media_type.len(),
                match payload {
                    Some(bytes) => format!("{} bytes", bytes.len()),
                    None => "absent".to_string(),
                }
            ),
        }
    }
}

/// Lowercase hex of a 32-byte digest.
pub fn hash_hex(hash: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in hash {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Parse a 64-character hex digest.
pub fn parse_hash_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[index] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Stable node-kind identity, usable without depending on wire ids.
///
/// Downstream tools (the RPC layer, projections, diagnostics) name kinds through
/// this enum; `code()` is the permanent wire discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(missing_docs)]
pub enum SerializedKind {
    Null,
    Bool,
    Int,
    Float,
    Str,
    DurationMs,
    Quantity,
    Array,
    Table,
    Secret,
    SecretRef,
    Ref,
    Env,
    Ident,
    Interpolate,
    Binary,
    Unary,
    Constrained,
    Patch,
    SchemaField,
    SchemaTable,
    SchemaArray,
    Semantic,
    Blob,
    ContentAddressed,
}

impl SerializedKind {
    pub const fn code(self) -> u8 {
        match self {
            SerializedKind::Null => 0,
            SerializedKind::Bool => 1,
            SerializedKind::Int => 2,
            SerializedKind::Float => 3,
            SerializedKind::Str => 4,
            SerializedKind::DurationMs => 5,
            SerializedKind::Quantity => 6,
            SerializedKind::Array => 7,
            SerializedKind::Table => 8,
            SerializedKind::Secret => 9,
            SerializedKind::SecretRef => 10,
            SerializedKind::Ref => 11,
            SerializedKind::Env => 12,
            SerializedKind::Ident => 13,
            SerializedKind::Interpolate => 14,
            SerializedKind::Binary => 15,
            SerializedKind::Unary => 16,
            SerializedKind::Constrained => 17,
            SerializedKind::Patch => 18,
            SerializedKind::SchemaField => 19,
            SerializedKind::SchemaTable => 20,
            SerializedKind::SchemaArray => 21,
            SerializedKind::Semantic => 22,
            SerializedKind::Blob => 23,
            SerializedKind::ContentAddressed => 24,
        }
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        let kind = match code {
            0 => SerializedKind::Null,
            1 => SerializedKind::Bool,
            2 => SerializedKind::Int,
            3 => SerializedKind::Float,
            4 => SerializedKind::Str,
            5 => SerializedKind::DurationMs,
            6 => SerializedKind::Quantity,
            7 => SerializedKind::Array,
            8 => SerializedKind::Table,
            9 => SerializedKind::Secret,
            10 => SerializedKind::SecretRef,
            11 => SerializedKind::Ref,
            12 => SerializedKind::Env,
            13 => SerializedKind::Ident,
            14 => SerializedKind::Interpolate,
            15 => SerializedKind::Binary,
            16 => SerializedKind::Unary,
            17 => SerializedKind::Constrained,
            18 => SerializedKind::Patch,
            19 => SerializedKind::SchemaField,
            20 => SerializedKind::SchemaTable,
            21 => SerializedKind::SchemaArray,
            22 => SerializedKind::Semantic,
            23 => SerializedKind::Blob,
            24 => SerializedKind::ContentAddressed,
            _ => return None,
        };
        Some(kind)
    }

    pub const fn name(self) -> &'static str {
        crate::view::node_kind_name(self.code())
    }
}

impl Inode {
    /// Stable kind identity of this node.
    pub const fn kind(&self) -> SerializedKind {
        match self {
            Inode::Null => SerializedKind::Null,
            Inode::Bool(_) => SerializedKind::Bool,
            Inode::Int(_) => SerializedKind::Int,
            Inode::Float(_) => SerializedKind::Float,
            Inode::Str(_) => SerializedKind::Str,
            Inode::DurationMs(_) => SerializedKind::DurationMs,
            Inode::Quantity { .. } => SerializedKind::Quantity,
            Inode::Array { .. } => SerializedKind::Array,
            Inode::Table { .. } => SerializedKind::Table,
            Inode::Secret(_) => SerializedKind::Secret,
            Inode::SecretRef { .. } => SerializedKind::SecretRef,
            Inode::Ref(_) => SerializedKind::Ref,
            Inode::Env { .. } => SerializedKind::Env,
            Inode::Ident(_) => SerializedKind::Ident,
            Inode::Interpolate { .. } => SerializedKind::Interpolate,
            Inode::Binary { .. } => SerializedKind::Binary,
            Inode::Unary { .. } => SerializedKind::Unary,
            Inode::Constrained { .. } => SerializedKind::Constrained,
            Inode::Patch(_) => SerializedKind::Patch,
            Inode::SchemaField(_) => SerializedKind::SchemaField,
            Inode::SchemaTable { .. } => SerializedKind::SchemaTable,
            Inode::SchemaArray { .. } => SerializedKind::SchemaArray,
            Inode::Semantic { .. } => SerializedKind::Semantic,
            Inode::Blob { .. } => SerializedKind::Blob,
            Inode::ContentAddressed { .. } => SerializedKind::ContentAddressed,
        }
    }
}

impl Inode {
    /// Stable kind discriminant (wire contract, `docs/spec/layout.md` §5.1).
    pub const fn kind_code(&self) -> u8 {
        match self {
            Inode::Null => 0,
            Inode::Bool(_) => 1,
            Inode::Int(_) => 2,
            Inode::Float(_) => 3,
            Inode::Str(_) => 4,
            Inode::DurationMs(_) => 5,
            Inode::Quantity { .. } => 6,
            Inode::Array { .. } => 7,
            Inode::Table { .. } => 8,
            Inode::Secret(_) => 9,
            Inode::SecretRef { .. } => 10,
            Inode::Ref(_) => 11,
            Inode::Env { .. } => 12,
            Inode::Ident(_) => 13,
            Inode::Interpolate { .. } => 14,
            Inode::Binary { .. } => 15,
            Inode::Unary { .. } => 16,
            Inode::Constrained { .. } => 17,
            Inode::Patch(_) => 18,
            Inode::SchemaField(_) => 19,
            Inode::SchemaTable { .. } => 20,
            Inode::SchemaArray { .. } => 21,
            Inode::Semantic { .. } => 22,
            Inode::Blob { .. } => 23,
            Inode::ContentAddressed { .. } => 24,
        }
    }

    /// Whether this node carries secret material or a secret locator.
    pub const fn is_secret(&self) -> bool {
        matches!(self, Inode::Secret(_) | Inode::SecretRef { .. })
    }

    /// Node references in canonical child order.
    ///
    /// This is the single source of truth for the dependency edges, the
    /// canonical numbering traversal, cycle detection and graph queries. It
    /// must list *every* node reference the variant holds.
    pub fn children(&self) -> Vec<NodeId> {
        match self {
            Inode::Quantity { value, .. } => vec![*value],
            Inode::Array { elements } => elements.clone(),
            Inode::Table { fields } => fields.iter().map(|(_, id)| *id).collect(),
            Inode::SecretRef { locator } => vec![*locator],
            Inode::Ref(id) => vec![*id],
            Inode::Env { default, .. } => default.iter().copied().collect(),
            Inode::Interpolate { parts } => parts
                .iter()
                .filter_map(|part| match part {
                    InterpPart::Expr(id) => Some(*id),
                    InterpPart::Literal(_) => None,
                })
                .collect(),
            Inode::Binary { lhs, rhs, .. } => vec![*lhs, *rhs],
            Inode::Unary { expr, .. } => vec![*expr],
            Inode::Constrained { target, .. } => vec![*target],
            Inode::Patch(op) => match op {
                PatchOp::Set { value, .. } => vec![*value],
                PatchOp::Remove { .. } | PatchOp::Rename { .. } => Vec::new(),
            },
            Inode::SchemaField(spec) => {
                let mut out = Vec::new();
                for id in [
                    spec.min,
                    spec.max,
                    spec.min_len,
                    spec.max_len,
                    spec.pattern,
                    spec.default,
                ]
                .into_iter()
                .flatten()
                {
                    out.push(id);
                }
                out
            }
            Inode::SchemaTable { fields, .. } => fields.iter().map(|(_, id)| *id).collect(),
            Inode::SchemaArray { element } => vec![*element],
            Inode::Semantic { inner, .. } => vec![*inner],
            Inode::ContentAddressed { media_type, data } => vec![*media_type, *data],
            Inode::Null
            | Inode::Bool(_)
            | Inode::Int(_)
            | Inode::Float(_)
            | Inode::Str(_)
            | Inode::DurationMs(_)
            | Inode::Secret(_)
            | Inode::Ident(_)
            | Inode::Blob { .. } => Vec::new(),
        }
    }

    /// Every string this node owns, for heap construction.
    pub fn strings(&self, out: &mut Vec<String>) {
        match self {
            Inode::Str(s) | Inode::Ident(s) => out.push(s.clone()),
            Inode::Table { fields } => {
                for (name, _) in fields {
                    out.push(name.clone());
                }
            }
            Inode::Env { name, .. } => out.push(name.clone()),
            Inode::Interpolate { parts } => {
                for part in parts {
                    if let InterpPart::Literal(s) = part {
                        out.push(s.clone());
                    }
                }
            }
            Inode::Constrained { constraint, .. } => match constraint {
                Constraint::Enum(items) => out.extend(items.iter().cloned()),
                Constraint::Pattern(s) | Constraint::Custom(s) => out.push(s.clone()),
                Constraint::MinMax { .. } | Constraint::Odd => {}
            },
            Inode::Patch(op) => match op {
                PatchOp::Set { path, .. } | PatchOp::Remove { path } => out.push(path.clone()),
                PatchOp::Rename { from, to } => {
                    out.push(from.clone());
                    out.push(to.clone());
                }
            },
            Inode::SchemaField(spec) => {
                if let TypeSpec::Enum(items) = &spec.typ {
                    out.extend(items.iter().cloned());
                }
                if let Some(deprecated) = &spec.deprecated {
                    out.push(deprecated.clone());
                }
            }
            Inode::SchemaTable { fields, .. } => {
                for (name, _) in fields {
                    out.push(name.clone());
                }
            }
            Inode::Blob { media_type, .. } => out.push(media_type.clone()),
            Inode::Null
            | Inode::Bool(_)
            | Inode::Int(_)
            | Inode::Float(_)
            | Inode::DurationMs(_)
            | Inode::Quantity { .. }
            | Inode::Array { .. }
            | Inode::Secret(_)
            | Inode::SecretRef { .. }
            | Inode::Ref(_)
            | Inode::Unary { .. }
            | Inode::Binary { .. }
            | Inode::SchemaArray { .. }
            | Inode::Semantic { .. }
            | Inode::ContentAddressed { .. } => {}
        }
    }
}

/// Annotation kinds (spec/annotations.md §2–§4).
#[derive(Clone, PartialEq)]
pub enum AnnotationKind {
    /// Documentation only, never enforced.
    Intent(String),
    /// A constraint predicate attached to a node.
    Constraint { source: String, expr: NodeId },
    /// Agent-immutable flag.
    AiImmutable(bool),
}

impl fmt::Debug for AnnotationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnnotationKind::Intent(text) => write!(f, "Intent(<{} bytes>)", text.len()),
            AnnotationKind::Constraint { expr, .. } => {
                write!(f, "Constraint {{ source: <redacted>, expr: {expr} }}")
            }
            AnnotationKind::AiImmutable(flag) => write!(f, "AiImmutable({flag})"),
        }
    }
}

/// One annotation attached to a node.
#[derive(Debug, Clone, PartialEq)]
pub struct Annotation {
    pub node: NodeId,
    pub kind: AnnotationKind,
}

/// Kinds of provenance entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProvKind {
    Text,
    Int,
    Flag,
    Hash,
    /// Input module content hash (delta/derivation lineage).
    Input,
}

impl ProvKind {
    pub const fn code(self) -> u32 {
        match self {
            ProvKind::Text => 0,
            ProvKind::Int => 1,
            ProvKind::Flag => 2,
            ProvKind::Hash => 3,
            ProvKind::Input => 4,
        }
    }

    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(ProvKind::Text),
            1 => Some(ProvKind::Int),
            2 => Some(ProvKind::Flag),
            3 => Some(ProvKind::Hash),
            4 => Some(ProvKind::Input),
            _ => None,
        }
    }
}

/// A provenance value.
#[derive(Clone, PartialEq)]
pub enum ProvValue {
    Text(String),
    Int(i64),
    Flag(bool),
    Hash([u8; 32]),
}

impl fmt::Debug for ProvValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProvValue::Text(text) => write!(f, "Text(<{} bytes>)", text.len()),
            ProvValue::Int(value) => write!(f, "Int({value})"),
            ProvValue::Flag(flag) => write!(f, "Flag({flag})"),
            ProvValue::Hash(hash) => write!(f, "Hash(blake3:{})", hash_hex(hash)),
        }
    }
}

/// One provenance entry: a typed key/value pair.
#[derive(Clone, PartialEq)]
pub struct ProvEntry {
    pub key: String,
    pub value: ProvValue,
}

impl fmt::Debug for ProvEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProvEntry {{ key: <{} bytes>, value: {:?} }}",
            self.key.len(),
            self.value
        )
    }
}

impl ProvEntry {
    pub fn kind(&self) -> ProvKind {
        match self.value {
            ProvValue::Text(_) => ProvKind::Text,
            ProvValue::Int(_) => ProvKind::Int,
            ProvValue::Flag(_) => ProvKind::Flag,
            ProvValue::Hash(_) => ProvKind::Hash,
        }
    }
}

/// Module provenance: who produced this module, when, with what, from what.
#[derive(Clone, PartialEq, Default)]
pub struct Provenance {
    /// Producer identity (agent, tool, human, pipeline).
    pub producer: Option<String>,
    /// Unix epoch milliseconds; `0` means "unrecorded".
    pub timestamp_ms: u64,
    /// Model identity when an AI produced the module.
    pub model: Option<String>,
    /// Tool identity.
    pub tool: Option<String>,
    /// Content hash of the parent module this one derives from.
    pub parent: Option<[u8; 32]>,
    /// Free-form typed entries, sorted by key in canonical form.
    pub entries: Vec<ProvEntry>,
}

impl fmt::Debug for Provenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provenance")
            .field("producer", &self.producer.as_ref().map(|text| text.len()))
            .field("timestamp_ms", &self.timestamp_ms)
            .field("model", &self.model.as_ref().map(|text| text.len()))
            .field("tool", &self.tool.as_ref().map(|text| text.len()))
            .field("parent", &self.parent)
            .field("entries", &self.entries)
            .finish()
    }
}

/// A canonical Active Infinity module.
///
/// The struct is an arena of [`Inode`] plus roots, bindings, annotations and
/// provenance. Edges are *derived* from node children, so a module can never
/// hold an edge table inconsistent with its nodes.
#[derive(Clone, Default)]
pub struct InfinityModule {
    nodes: Vec<Inode>,
    root: Option<NodeId>,
    bindings: Vec<(String, NodeId)>,
    annotations: Vec<Annotation>,
    provenance: Option<Provenance>,
    extensions: Vec<(u64, Vec<u8>)>,
}

/// Debug is an export path (I-3). Binding names, table keys, annotations,
/// provenance text and every other string field can contain a copy of a secret
/// literal, so the module is cloned and redacted before it is formatted.
/// Extension payloads print as a length: a payload can contain secret-shaped
/// bytes and has no safe renderer.
impl fmt::Debug for InfinityModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secrets = crate::interop::secret_texts(self);
        let redact = |text: &str| crate::canonical::redact_text(text, &secrets);
        let mut redacted = self.clone();
        redact_for_debug(&mut redacted, &redact);
        let extensions: Vec<(u64, usize)> = redacted
            .extensions
            .iter()
            .map(|(tag, payload)| (*tag, payload.len()))
            .collect();
        f.debug_struct("InfinityModule")
            .field("nodes", &redacted.nodes)
            .field("root", &redacted.root)
            .field("bindings", &redacted.bindings)
            .field("annotations", &redacted.annotations)
            .field("provenance", &redacted.provenance)
            .field("extensions", &extensions)
            .finish()
    }
}

fn redact_for_debug(module: &mut InfinityModule, redact: &impl Fn(&str) -> String) {
    for node in &mut module.nodes {
        redact_inode(node, redact);
    }
    for (name, _) in &mut module.bindings {
        *name = redact(name);
    }
    for annotation in &mut module.annotations {
        match &mut annotation.kind {
            AnnotationKind::Intent(text) => *text = redact(text),
            AnnotationKind::Constraint { source, .. } => *source = redact(source),
            AnnotationKind::AiImmutable(_) => {}
        }
    }
    if let Some(prov) = &mut module.provenance {
        if let Some(text) = &mut prov.producer {
            *text = redact(text);
        }
        if let Some(text) = &mut prov.model {
            *text = redact(text);
        }
        if let Some(text) = &mut prov.tool {
            *text = redact(text);
        }
        for entry in &mut prov.entries {
            entry.key = redact(&entry.key);
            if let ProvValue::Text(text) = &mut entry.value {
                *text = redact(text);
            }
        }
    }
}

fn redact_inode(node: &mut Inode, redact: &impl Fn(&str) -> String) {
    match node {
        Inode::Str(text) => *text = redact(text),
        Inode::Quantity { unit, .. } => {
            if let super::UnitTag::Named(name) = unit {
                *name = redact(name);
            }
        }
        Inode::Table { fields } | Inode::SchemaTable { fields, .. } => {
            for (name, _) in fields {
                *name = redact(name);
            }
        }
        Inode::Env { name, .. } => *name = redact(name),
        Inode::Ident(text) => *text = redact(text),
        Inode::Interpolate { parts } => {
            for part in parts {
                if let InterpPart::Literal(text) = part {
                    *text = redact(text);
                }
            }
        }
        Inode::Constrained { constraint, .. } => match constraint {
            Constraint::Enum(values) => {
                for value in values {
                    *value = redact(value);
                }
            }
            Constraint::Pattern(text) | Constraint::Custom(text) => *text = redact(text),
            Constraint::MinMax { .. } | Constraint::Odd => {}
        },
        Inode::Patch(op) => match op {
            PatchOp::Set { path, .. } | PatchOp::Remove { path } => *path = redact(path),
            PatchOp::Rename { from, to } => {
                *from = redact(from);
                *to = redact(to);
            }
        },
        Inode::SchemaField(spec) => {
            if let TypeSpec::Enum(values) = &mut spec.typ {
                for value in values {
                    *value = redact(value);
                }
            }
            if let Some(text) = &mut spec.deprecated {
                *text = redact(text);
            }
        }
        Inode::Blob { media_type, .. } => *media_type = redact(media_type),
        Inode::Null
        | Inode::Bool(_)
        | Inode::Int(_)
        | Inode::Float(_)
        | Inode::DurationMs(_)
        | Inode::Array { .. }
        | Inode::Secret(_)
        | Inode::SecretRef { .. }
        | Inode::Ref(_)
        | Inode::Binary { .. }
        | Inode::Unary { .. }
        | Inode::SchemaArray { .. }
        | Inode::Semantic { .. }
        | Inode::ContentAddressed { .. } => {}
    }
}

impl PartialEq for InfinityModule {
    /// Canonical structural equality: two modules are equal when their
    /// canonical forms match, so arena order, table field order and blob
    /// numbering are irrelevant.
    ///
    /// Secret *contents* are never compared — only the fact that a secret is
    /// there — so equality can never become a guessing oracle, and a module
    /// holding a secret is equal to a structurally identical copy of itself.
    /// Use [`SecretBytes`] directly when you need the anti-oracle behaviour of
    /// two secret values.
    fn eq(&self, other: &Self) -> bool {
        self.structurally_eq(other)
    }
}

/// Compare two canonical nodes, blinding secret payloads.
fn node_eq(left: &Inode, right: &Inode) -> bool {
    match (left, right) {
        (Inode::Secret(_), Inode::Secret(_)) => true,
        (Inode::Secret(_), _) | (_, Inode::Secret(_)) => false,
        // Canonicalization normalizes floats; compare their bits so a NaN is
        // equal to itself.
        (Inode::Float(a), Inode::Float(b)) => a.to_bits() == b.to_bits(),
        _ => left == right,
    }
}

impl InfinityModule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node, returning its id.
    pub fn push(&mut self, node: Inode) -> NodeId {
        let id = NodeId(u32::try_from(self.nodes.len()).expect("arena exceeds u32 ids"));
        self.nodes.push(node);
        id
    }

    /// Alias for [`InfinityModule::push`], mirroring `Module::add_node`.
    pub fn add_node(&mut self, node: Inode) -> NodeId {
        self.push(node)
    }

    pub fn get(&self, id: NodeId) -> Option<&Inode> {
        self.nodes.get(id.index())
    }

    pub fn get_mut(&mut self, id: NodeId) -> Option<&mut Inode> {
        self.nodes.get_mut(id.index())
    }

    pub fn node_mut(&mut self, id: NodeId) -> Result<&mut Inode, super::Error> {
        self.nodes
            .get_mut(id.index())
            .ok_or(super::Error::NodeRef(id.0))
    }

    pub fn nodes(&self) -> &[Inode] {
        &self.nodes
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn root(&self) -> Option<NodeId> {
        self.root
    }

    pub fn set_root(&mut self, root: Option<NodeId>) {
        self.root = root;
    }

    pub fn bindings(&self) -> &[(String, NodeId)] {
        &self.bindings
    }

    /// Drop every name binding.
    pub fn clear_bindings(&mut self) {
        self.bindings.clear();
    }

    /// Bind a name to a node. Replaces an existing binding with the same name.
    pub fn bind(&mut self, name: impl Into<String>, id: NodeId) {
        let name = name.into();
        if let Some(slot) = self.bindings.iter_mut().find(|(n, _)| *n == name) {
            slot.1 = id;
        } else {
            self.bindings.push((name, id));
        }
    }

    pub fn annotations(&self) -> &[Annotation] {
        &self.annotations
    }

    pub fn annotate(&mut self, node: NodeId, kind: AnnotationKind) {
        self.annotations.push(Annotation { node, kind });
    }

    /// Drop every annotation.
    pub fn clear_annotations(&mut self) {
        self.annotations.clear();
    }

    /// Remove a binding by name; returns the old target when present.
    pub fn remove_binding(&mut self, name: &str) -> Option<NodeId> {
        let position = self.bindings.iter().position(|(key, _)| key == name)?;
        Some(self.bindings.remove(position).1)
    }

    pub fn provenance(&self) -> Option<&Provenance> {
        self.provenance.as_ref()
    }

    /// True when the module holds a structural secret literal.
    pub fn has_secret(&self) -> bool {
        self.nodes
            .iter()
            .any(|node| matches!(node, Inode::Secret(_)))
    }

    /// Canonical structural equality, blinding secret payloads.
    ///
    /// This is what [`PartialEq`] implements; it is also available by name for
    /// readers who want the intent spelled out.
    pub fn structurally_eq(&self, other: &Self) -> bool {
        let (Ok(left), Ok(right)) = (
            crate::canonical::prepare(self),
            crate::canonical::prepare(other),
        ) else {
            return false;
        };
        left.root == right.root
            && left.bindings == right.bindings
            && left.annotations == right.annotations
            && left.provenance == right.provenance
            && left.strings == right.strings
            && left.units == right.units
            && left.blobs == right.blobs
            && left.hashes == right.hashes
            && left.numbers == right.numbers
            && left.secrets.len() == right.secrets.len()
            && left.types.len() == right.types.len()
            && left
                .types
                .iter()
                .zip(right.types.iter())
                .all(|(a, b)| a.spec == b.spec && a.aux == b.aux)
            && left.nodes.len() == right.nodes.len()
            && left
                .nodes
                .iter()
                .zip(right.nodes.iter())
                .all(|(a, b)| node_eq(a, b))
    }

    /// Append an extension block (tag, payload).
    ///
    /// Tags are unique; the canonical encoder sorts blocks by tag and refuses a
    /// duplicate. Extension payloads are opaque bytes owned by the application;
    /// the codec never interprets them.
    pub fn add_extension(&mut self, tag: u64, payload: impl Into<Vec<u8>>) {
        self.extensions.push((tag, payload.into()));
    }

    /// Extension blocks, in stored order.
    pub fn extensions(&self) -> &[(u64, Vec<u8>)] {
        &self.extensions
    }

    /// Replace the extension set.
    pub fn set_extensions(&mut self, extensions: Vec<(u64, Vec<u8>)>) {
        self.extensions = extensions;
    }

    pub fn set_provenance(&mut self, provenance: Option<Provenance>) {
        // Provenance is a map keyed by name: the last value for a key wins, so
        // the stored form can never contain the duplicate keys that validation
        // (correctly) rejects. Entries stay sorted for canonical equality.
        self.provenance = provenance.map(|prov| {
            let mut by_key: std::collections::BTreeMap<String, ProvValue> =
                std::collections::BTreeMap::new();
            for entry in prov.entries {
                by_key.insert(entry.key, entry.value);
            }
            let entries: Vec<ProvEntry> = by_key
                .into_iter()
                .map(|(key, value)| ProvEntry { key, value })
                .collect();
            Provenance { entries, ..prov }
        });
    }

    /// Roots used to define the reachable graph: the module root, every
    /// binding, every annotation subject, and provenance-only references.
    pub fn roots(&self) -> Vec<NodeId> {
        let mut roots = Vec::new();
        if let Some(root) = self.root {
            roots.push(root);
        }
        let mut bindings: Vec<&(String, NodeId)> = self.bindings.iter().collect();
        bindings.sort_by(|a, b| a.0.cmp(&b.0));
        roots.extend(bindings.into_iter().map(|(_, id)| *id));
        for annotation in &self.annotations {
            roots.push(annotation.node);
            if let AnnotationKind::Constraint { expr, .. } = &annotation.kind {
                roots.push(*expr);
            }
        }
        roots
    }

    /// Derived dependency edges, direction dependency → dependent, sorted and
    /// deduplicated. Nodes that reference where they are referenced from are
    /// normal; the graph is a DAG after [`Self::validate_structure`].
    pub fn edges(&self) -> Vec<(NodeId, NodeId)> {
        let mut edges = Vec::new();
        for (index, node) in self.nodes.iter().enumerate() {
            let dependent = NodeId(index as u32);
            for child in node.children() {
                edges.push((child, dependent));
            }
        }
        edges.sort_unstable();
        edges.dedup();
        edges
    }

    /// Reverse adjacency (dependent → dependencies).
    pub fn dependency_map(&self) -> HashMap<NodeId, Vec<NodeId>> {
        let mut map: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
        for (index, node) in self.nodes.iter().enumerate() {
            map.insert(NodeId(index as u32), node.children());
        }
        map
    }

    /// Check every structural invariant the wire format also enforces.
    ///
    /// `max_nodes` and `max_depth` bound the work so a hostile module cannot
    /// make this function hang or recurse without limit.
    pub fn validate_structure(&self, max_nodes: u64, max_depth: u32) -> Result<(), super::Error> {
        use super::Error;
        if self.nodes.len() as u64 > max_nodes {
            return Err(Error::Limit {
                kind: "nodes",
                limit: max_nodes,
            });
        }
        let count = self.nodes.len() as u32;
        let check = |id: NodeId| -> Result<(), Error> {
            if id.0 >= count {
                return Err(Error::NodeRef(id.0));
            }
            Ok(())
        };
        for (index, node) in self.nodes.iter().enumerate() {
            let id = NodeId(index as u32);
            for child in node.children() {
                check(child)?;
            }
            match node {
                Inode::Table { fields } | Inode::SchemaTable { fields, .. } => {
                    // O(k) duplicate detection: a 256-field table is common and
                    // the quadratic form dominated encoding time.
                    let mut seen = std::collections::HashSet::with_capacity(fields.len());
                    for (name, _) in fields {
                        if !seen.insert(name.as_str()) {
                            return Err(Error::DuplicateField { node: id.0 });
                        }
                    }
                }
                Inode::Float(value)
                    if value.is_nan() && !crate::canonical::is_canonical_nan(*value) =>
                {
                    return Err(Error::Node {
                        id: id.0,
                        reason: "non-canonical NaN",
                    });
                }
                Inode::Constrained { constraint, .. } => match constraint {
                    Constraint::MinMax {
                        min: Some(min),
                        max: Some(max),
                    } if min > max => {
                        return Err(Error::Node {
                            id: id.0,
                            reason: "constraint min exceeds max",
                        });
                    }
                    Constraint::Enum(items) if items.is_empty() => {
                        return Err(Error::Node {
                            id: id.0,
                            reason: "empty enum constraint",
                        });
                    }
                    _ => {}
                },
                _ => {}
            }
        }
        if let Some(root) = self.root {
            check(root)?;
        }
        let mut seen = std::collections::HashSet::new();
        for (name, id) in &self.bindings {
            check(*id)?;
            if !seen.insert(name.as_str()) {
                return Err(Error::DuplicateBinding);
            }
        }
        for annotation in &self.annotations {
            check(annotation.node)?;
            if let AnnotationKind::Constraint { expr, .. } = &annotation.kind {
                check(*expr)?;
            }
        }
        self.check_acyclic(count)?;
        self.check_depth(max_depth)?;
        Ok(())
    }

    /// Cycle detection over the derived dependency graph (Kahn sweep).
    ///
    /// One child-list derivation per node, so a wide table stays linear; the
    /// sweep is iterative by construction, because a hostile 4M-node chain must
    /// not overflow the thread stack (`active-core` treats cycles as fatal, so
    /// this is a hard invariant, not a hint).
    pub fn check_acyclic(&self, count: u32) -> Result<(), super::Error> {
        use super::Error;
        let mut incoming = vec![0u32; count as usize];
        for node in &self.nodes {
            for child in node.children() {
                if child.0 >= count {
                    return Err(Error::NodeRef(child.0));
                }
                let slot = &mut incoming[child.index()];
                *slot = slot.saturating_add(1);
            }
        }
        let mut queue: std::collections::VecDeque<u32> = incoming
            .iter()
            .enumerate()
            .filter(|(_, degree)| **degree == 0)
            .map(|(node, _)| node as u32)
            .collect();
        let mut processed = 0u32;
        while let Some(node) = queue.pop_front() {
            processed += 1;
            for child in self.nodes[node as usize].children() {
                let slot = &mut incoming[child.index()];
                *slot = slot.saturating_sub(1);
                if *slot == 0 {
                    queue.push_back(child.0);
                }
            }
        }
        if processed != count {
            // A node that could not be ordered depends on a cycle; report the
            // lowest one so the answer is stable.
            let node = incoming.iter().position(|degree| *degree > 0).unwrap_or(0) as u32;
            return Err(Error::Cycle { node });
        }
        Ok(())
    }

    /// Depth check over the derived dependency graph (topological sweep).
    ///
    /// Each edge is examined exactly once, so a wide or diamond-shaped graph is
    /// linear rather than polynomial.
    pub fn check_depth(&self, max_depth: u32) -> Result<(), super::Error> {
        use super::Error;
        let count = self.nodes.len();
        if count == 0 {
            return Ok(());
        }
        if max_depth == 0 {
            // Zero means "no depth ceiling", not "no checks": a direct caller
            // still gets cycle detection.
            return self.check_acyclic(count as u32);
        }
        let mut incoming = vec![0u32; count];
        for node in &self.nodes {
            for child in node.children() {
                if child.index() >= count {
                    return Err(Error::NodeRef(child.0));
                }
                incoming[child.index()] = incoming[child.index()].saturating_add(1);
            }
        }
        let mut depth = vec![1u32; count];
        let mut queue: std::collections::VecDeque<u32> = incoming
            .iter()
            .enumerate()
            .filter(|(_, degree)| **degree == 0)
            .map(|(node, _)| node as u32)
            .collect();
        if queue.is_empty() {
            // Acyclicity runs first; stay total for a direct caller.
            return Err(Error::Cycle { node: 0 });
        }
        let mut processed = 0u32;
        while let Some(node) = queue.pop_front() {
            processed += 1;
            let next = depth[node as usize] + 1;
            for child in self.nodes[node as usize].children() {
                if next > max_depth {
                    return Err(Error::Depth { limit: max_depth });
                }
                if next > depth[child.index()] {
                    depth[child.index()] = next;
                }
                let slot = &mut incoming[child.index()];
                *slot = slot.saturating_sub(1);
                if *slot == 0 {
                    queue.push_back(child.0);
                }
            }
        }
        if processed as usize != count {
            // Acyclicity runs first, so this is defensive; report the lowest
            // node that could not be ordered, like `check_acyclic`.
            let node = incoming.iter().position(|degree| *degree > 0).unwrap_or(0) as u32;
            return Err(Error::Cycle { node });
        }
        Ok(())
    }

    /// Total string payload bytes (heap size before deduplication).
    pub fn string_bytes(&self) -> u64 {
        let mut strings = Vec::new();
        for node in &self.nodes {
            node.strings(&mut strings);
        }
        strings.iter().map(|s| s.len() as u64).sum()
    }

    /// Rebuild a module from decoded parts (used by the decoder and the
    /// stream reassembler).
    pub fn from_parts(
        nodes: Vec<Inode>,
        root: Option<NodeId>,
        bindings: Vec<(String, NodeId)>,
        mut annotations: Vec<Annotation>,
        provenance: Option<Provenance>,
    ) -> Self {
        annotations.sort_by(|a, b| {
            (a.node.0, annotation_order(&a.kind)).cmp(&(b.node.0, annotation_order(&b.kind)))
        });
        InfinityModule {
            nodes,
            root,
            bindings,
            annotations,
            provenance,
            extensions: Vec::new(),
        }
    }
}

fn annotation_order(kind: &AnnotationKind) -> u32 {
    match kind {
        AnnotationKind::Intent(_) => 0,
        AnnotationKind::Constraint { .. } => 1,
        AnnotationKind::AiImmutable(_) => 2,
    }
}

/// Builder helpers that keep the node graph consistent while constructing a
/// module by hand or from another IR.
#[derive(Debug, Default)]
pub struct ModuleBuilder {
    module: InfinityModule,
}

impl ModuleBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, node: Inode) -> NodeId {
        self.module.push(node)
    }

    pub fn root(&mut self, id: NodeId) -> &mut Self {
        self.module.set_root(Some(id));
        self
    }

    pub fn bind(&mut self, name: impl Into<String>, id: NodeId) -> &mut Self {
        self.module.bind(name, id);
        self
    }

    pub fn annotate(&mut self, node: NodeId, kind: AnnotationKind) -> &mut Self {
        self.module.annotate(node, kind);
        self
    }

    pub fn provenance(&mut self, provenance: Provenance) -> &mut Self {
        self.module.set_provenance(Some(provenance));
        self
    }

    pub fn build(self) -> InfinityModule {
        self.module
    }
}
