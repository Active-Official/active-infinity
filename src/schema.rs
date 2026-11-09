//! Schema-class companion modules.
//!
//! A schema is itself an Active Infinity module whose root is a
//! [`Inode::SchemaTable`]. It constrains an instance's root table without
//! changing the open node model and without changing the instance hash: the
//! content address always covers the canonical instance bytes.
//!
//! The current schema class supports top-level fields and the [`TypeSpec`]
//! family already carried by AINF. Nested schema constraints are a later
//! additive extension; the wire kinds already reserve them.

use crate::ir::{InfinityModule, Inode, NodeId, SchemaFieldSpec, TypeSpec};
use crate::{decode, decode_with, encode, DecodeOpts, Error, Result};

/// A validated companion schema module.
#[derive(Clone, Debug)]
pub struct Schema {
    module: InfinityModule,
    closed: bool,
}

impl Schema {
    /// Build a schema from field names and type specs. All fields are required.
    pub fn from_fields(fields: &[(&str, TypeSpec)], closed: bool) -> Result<Self> {
        let mut module = InfinityModule::new();
        let mut encoded = Vec::with_capacity(fields.len());
        let mut names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for (name, typ) in fields {
            if name.is_empty() {
                return Err(Error::Schema("field name is empty"));
            }
            if !names.insert(name) {
                // Two specs for one name would make acceptance depend on the
                // order of the schema table, and only the first would be checked.
                return Err(Error::Schema("duplicate field name"));
            }
            let node = module.try_push(Inode::SchemaField(SchemaFieldSpec::bare(typ.clone())))?;
            encoded.push(((*name).to_string(), node));
        }
        let root = module.push(Inode::SchemaTable {
            fields: encoded,
            closed,
        });
        module.set_root(Some(root));
        module.bind("schema", root);
        Ok(Self { module, closed })
    }

    /// Read a schema from an AINF schema module.
    ///
    /// The input need not be canonical: it is canonicalized on load, so the
    /// stored module is always the canonical form (INF-SCHEMA-05). A stored
    /// schema image may carry slack or a cleared canonical flag (written
    /// before canonical enforcement, or by a lenient writer); decoding it
    /// leniently, re-encoding, and decoding strictly normalizes it, and the
    /// strict decode proves the stored form is canonical. The lenient decode
    /// is the only place this path opts out of the INF-02 default, and it is
    /// immediately followed by canonicalization, so no non-canonical module
    /// is ever stored. The secret/blob refusal below still runs on the
    /// as-decoded module, so an unreachable secret or blob node is refused
    /// exactly as before (canonicalization would otherwise drop it).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // `decode_with` validates the image; a second `validate` would double
        // the work. Lenient here: canonicalization below is what guarantees
        // the stored form, not the input form.
        let module = decode_with(
            bytes,
            DecodeOpts {
                verify_canonical: false,
                ..DecodeOpts::default()
            },
        )?;
        if module.nodes().iter().any(|node| {
            matches!(
                node,
                Inode::Secret(_) | Inode::SecretRef { .. } | Inode::Blob { .. }
            )
        }) {
            // A schema is a description: secret or blob nodes in it are a covert
            // channel inside the pinned schema hash with no meaning to a reader.
            return Err(Error::Schema("schema carries secret or blob nodes"));
        }
        // Canonicalize: re-encode the decoded module (the encoder always
        // emits canonical bytes) and decode strictly, so the stored module
        // is the canonical form and `module()` never exposes slack, an
        // unflagged image, or dropped unreachable nodes as if canonical.
        let canonical_bytes = encode(&module)?;
        let module = decode(&canonical_bytes)?;
        let root = module
            .root()
            .ok_or(Error::Schema("schema module has no root"))?;
        let closed = match module.get(root) {
            Some(Inode::SchemaTable { closed, .. }) => *closed,
            _ => return Err(Error::Schema("schema root must be a SchemaTable")),
        };
        Ok(Self { module, closed })
    }

    /// Encode the schema as a canonical AINF image.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encode(&self.module)
    }

    /// The underlying schema module.
    pub fn module(&self) -> &InfinityModule {
        &self.module
    }

    /// Whether an unknown instance field is an error.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Validate an instance module against this schema.
    ///
    /// Fail-closed: a constraint this reader cannot enforce exactly is refused,
    /// a duplicate instance field is refused, and a default is held to the same
    /// type and bounds as a present value.
    pub fn validate_instance(&self, instance: &InfinityModule) -> Result<()> {
        let root = instance
            .root()
            .ok_or(Error::Schema("instance has no root"))?;
        let instance_fields = match instance.get(root) {
            // Only a plain `Table` is an instance. A `SchemaTable` in that
            // position is a schema-shaped program fragment, not a value.
            Some(Inode::Table { fields }) => fields,
            _ => return Err(Error::Schema("instance root must be a table")),
        };
        let mut by_name: std::collections::HashMap<&str, NodeId> =
            std::collections::HashMap::with_capacity(instance_fields.len());
        for (name, id) in instance_fields {
            if by_name.insert(name.as_str(), *id).is_some() {
                // `find` used to take the first of two same-named fields and
                // leave the second unchecked; a duplicate is ambiguous.
                return Err(Error::Schema("instance has duplicate field names"));
            }
        }
        let schema_root = self
            .module
            .root()
            .ok_or(Error::Schema("schema module has no root"))?;
        let schema_fields = match self.module.get(schema_root) {
            Some(Inode::SchemaTable { fields, .. }) => fields,
            _ => return Err(Error::Schema("schema root must be a SchemaTable")),
        };
        let mut declared: std::collections::HashSet<&str> =
            std::collections::HashSet::with_capacity(schema_fields.len());
        for (name, node) in schema_fields {
            declared.insert(name.as_str());
            let spec = match self.module.get(*node) {
                Some(Inode::SchemaField(spec)) => spec,
                _ => return Err(Error::Schema("schema field is not a SchemaField")),
            };
            if let TypeSpec::Table { closed: true } = &spec.typ {
                // The schema class models top-level fields only; a nested closed
                // table cannot be enforced field by field, so accepting the spec
                // would promise more than this reader checks.
                return Err(Error::Schema(
                    "nested closed tables are not enforceable by this reader",
                ));
            }
            match by_name.get(name.as_str()).copied() {
                Some(id) => {
                    let inode = instance
                        .get(id)
                        .ok_or(Error::Schema("instance field points outside the module"))?;
                    if !matches_type(&spec.typ, instance, inode) {
                        return Err(Error::Schema("instance field has the wrong type"));
                    }
                    self.check_constraints(spec, instance, id, inode)?;
                }
                None if spec.default.is_some() => {
                    let default = spec.default.expect("checked above");
                    let node = self
                        .module
                        .get(default)
                        .ok_or(Error::Schema("schema default points outside the module"))?;
                    if !matches_type(&spec.typ, &self.module, node) {
                        return Err(Error::Schema("schema default has the wrong type"));
                    }
                    // A default is what a consumer reads for a missing field, so
                    // it must satisfy the same bounds a present value would.
                    self.check_constraints(spec, &self.module, default, node)?;
                }
                None => return Err(Error::Schema("required instance field is missing")),
            }
        }
        if self.closed {
            for (name, _) in instance_fields {
                if !declared.contains(name.as_str()) {
                    return Err(Error::Schema("closed schema rejects an unknown field"));
                }
            }
        }
        Ok(())
    }

    /// Validate bytes by validating, decoding and checking the instance.
    pub fn validate_bytes(&self, bytes: &[u8]) -> Result<()> {
        // `decode` is a full validating decode; validating again would double the
        // cost on untrusted bytes.
        let instance = decode(bytes)?;
        self.validate_instance(&instance)
    }

    /// Enforce the declared bounds on one instance value.
    ///
    /// A constraint this reader cannot enforce is refused rather than ignored: a
    /// schema that looks restrictive must reject what it says it rejects, or the
    /// pinned schema hash means nothing. Comparisons are exact per numeric kind:
    /// an integer bound against an integer value never goes through `f64`, and a
    /// mixed integer/float comparison is refused because rounding would make it
    /// vacuous.
    fn check_constraints(
        &self,
        spec: &SchemaFieldSpec,
        instance: &InfinityModule,
        id: NodeId,
        node: &Inode,
    ) -> Result<()> {
        if spec.pattern.is_some() {
            return Err(Error::Schema(
                "pattern constraints are not enforceable by this reader",
            ));
        }
        if spec.min.is_some() || spec.max.is_some() {
            let value = numeric(instance, id)
                .ok_or(Error::Schema("a bounded field must hold a numeric value"))?;
            if let Some(min) = spec.min {
                let bound = numeric(&self.module, min)
                    .ok_or(Error::Schema("schema minimum is not a finite number"))?;
                if below(&value, &bound)? {
                    return Err(Error::Schema("instance field is below its minimum"));
                }
            }
            if let Some(max) = spec.max {
                let bound = numeric(&self.module, max)
                    .ok_or(Error::Schema("schema maximum is not a finite number"))?;
                if above(&value, &bound)? {
                    return Err(Error::Schema("instance field is above its maximum"));
                }
            }
        }
        if spec.min_len.is_some() || spec.max_len.is_some() {
            let Inode::Str(text) = node else {
                return Err(Error::Schema("a length-bounded field must hold a string"));
            };
            let length = text.chars().count() as u64;
            if let Some(min) = spec.min_len {
                let bound = length_bound(&self.module, min)?;
                if length < bound {
                    return Err(Error::Schema("instance field is shorter than its minimum"));
                }
            }
            if let Some(max) = spec.max_len {
                let bound = length_bound(&self.module, max)?;
                if length > bound {
                    return Err(Error::Schema("instance field is longer than its maximum"));
                }
            }
        }
        Ok(())
    }

    /// Root field names declared by the schema.
    pub fn field_names(&self) -> Result<Vec<String>> {
        let root = self
            .module
            .root()
            .ok_or(Error::Schema("schema module has no root"))?;
        match self.module.get(root) {
            Some(Inode::SchemaTable { fields, .. }) => {
                Ok(fields.iter().map(|(name, _)| name.clone()).collect())
            }
            _ => Err(Error::Schema("schema root must be a SchemaTable")),
        }
    }

    /// Root node id of the schema module (for diagnostics/tools).
    pub fn root(&self) -> Option<NodeId> {
        self.module.root()
    }
}

/// A numeric value of an instance or a schema bound.
#[derive(Clone, Copy)]
enum Numeric {
    Int(i128),
    Float(f64),
}

/// Resolve a node to a finite number.
///
/// A non-finite float is not a number for constraint purposes: every comparison
/// against it is false, which would make a bound vacuous.
fn numeric(module: &InfinityModule, id: NodeId) -> Option<Numeric> {
    match module.get(id)? {
        Inode::Int(value) => Some(Numeric::Int(i128::from(*value))),
        Inode::DurationMs(value) => Some(Numeric::Int(i128::from(*value))),
        Inode::Float(value) if value.is_finite() => Some(Numeric::Float(*value)),
        Inode::Quantity { value, .. } => match module.get(*value)? {
            Inode::Int(value) => Some(Numeric::Int(i128::from(*value))),
            Inode::Float(value) if value.is_finite() => Some(Numeric::Float(*value)),
            _ => None,
        },
        _ => None,
    }
}

fn below(value: &Numeric, bound: &Numeric) -> Result<bool> {
    match (value, bound) {
        (Numeric::Int(value), Numeric::Int(bound)) => Ok(value < bound),
        (Numeric::Float(value), Numeric::Float(bound)) => Ok(value < bound),
        _ => Err(Error::Schema(
            "mixed integer/float bounds are not enforceable",
        )),
    }
}

fn above(value: &Numeric, bound: &Numeric) -> Result<bool> {
    match (value, bound) {
        (Numeric::Int(value), Numeric::Int(bound)) => Ok(value > bound),
        (Numeric::Float(value), Numeric::Float(bound)) => Ok(value > bound),
        _ => Err(Error::Schema(
            "mixed integer/float bounds are not enforceable",
        )),
    }
}

fn length_bound(module: &InfinityModule, id: NodeId) -> Result<u64> {
    match numeric(module, id) {
        Some(Numeric::Int(value)) if value >= 0 => {
            u64::try_from(value).map_err(|_| Error::Schema("length bound is too large"))
        }
        _ => Err(Error::Schema("length bound must be a non-negative integer")),
    }
}

/// Whether a node is a *value* of the declared type.
///
/// Only the value plane matches: an `Ident`, an `Interpolate`, a `SecretRef`, a
/// `SchemaTable`, an `Env` or a `ContentAddressed` node is a program fragment,
/// not a value, and accepting one would let a "typed" instance resolve into
/// something the schema never described.
fn matches_type(typ: &TypeSpec, module: &InfinityModule, node: &Inode) -> bool {
    match typ {
        TypeSpec::Null => matches!(node, Inode::Null),
        TypeSpec::Bool => matches!(node, Inode::Bool(_)),
        TypeSpec::Int => matches!(node, Inode::Int(_)),
        TypeSpec::Float => matches!(node, Inode::Float(value) if value.is_finite()),
        TypeSpec::String => matches!(node, Inode::Str(_)),
        // A duration is a millisecond count or a quantity in a time unit; the
        // discriminant range 0..=7 is the closed time table (layout §5.2). The
        // quantity's value must itself be numeric.
        TypeSpec::Duration => match node {
            Inode::DurationMs(_) => true,
            Inode::Quantity { value, unit } => {
                unit.discriminant() <= 7
                    && match module.get(*value) {
                        Some(Inode::Int(_)) => true,
                        Some(Inode::Float(value)) => value.is_finite(),
                        _ => false,
                    }
            }
            _ => false,
        },
        // A tainted blob carries secret-bearing payload identity; it is not a
        // public value of a declared Bytes/Blob field.
        TypeSpec::Bytes | TypeSpec::Blob => {
            matches!(node, Inode::Blob { tainted: false, .. })
        }
        // An open table admits any shape, but its cone is still data: a nested
        // `Ident` or `SecretRef` is program plane and must not pass because its
        // parent is a table (F-05).
        TypeSpec::Table { closed } => {
            !closed && matches!(node, Inode::Table { .. }) && is_value_subtree(module, node)
        }
        TypeSpec::Enum(values) => match node {
            Inode::Str(value) => values.iter().any(|candidate| candidate == value),
            _ => false,
        },
        // A locator is not a secret value; only the secret itself is.
        TypeSpec::Secret => matches!(node, Inode::Secret(_)),
        // `Any` still means a value: it does not open the program plane, and
        // that has to hold for the whole cone, not only this node (F-05).
        TypeSpec::Any => is_value_subtree(module, node),
    }
}

/// Whether this node and every node under it is value plane.
///
/// `Any` and an open table admit a container, but the schema's promise is that
/// the data plane does not smuggle a program node (an `Ident`, a `SecretRef`, an
/// interpolation) in a child. The walk is iterative and budgeted: a hostile
/// graph (a cycle cannot survive validation, but `validate_instance` also
/// accepts a hand-built module) is refused rather than walked forever (F-05).
fn is_value_subtree(module: &InfinityModule, root: &Inode) -> bool {
    let mut budget = module.node_count().saturating_mul(2).saturating_add(64);
    let mut stack: Vec<&Inode> = vec![root];
    while let Some(node) = stack.pop() {
        match budget.checked_sub(1) {
            Some(left) => budget = left,
            None => return false,
        }
        match node {
            Inode::Array { elements } => {
                for item in elements {
                    let Some(child) = module.get(*item) else {
                        return false;
                    };
                    stack.push(child);
                }
            }
            Inode::Table { fields } => {
                for (_, value) in fields {
                    let Some(child) = module.get(*value) else {
                        return false;
                    };
                    stack.push(child);
                }
            }
            other if is_value_node(module, other) => {}
            _ => return false,
        }
    }
    true
}

/// The value plane: literals and the containers a consumer can read directly.
fn is_value_node(module: &InfinityModule, node: &Inode) -> bool {
    match node {
        Inode::Null
        | Inode::Bool(_)
        | Inode::Int(_)
        | Inode::Str(_)
        | Inode::DurationMs(_)
        | Inode::Array { .. }
        | Inode::Table { .. } => true,
        Inode::Float(value) => value.is_finite(),
        Inode::Quantity { value, .. } => match module.get(*value) {
            Some(Inode::Int(_)) => true,
            Some(Inode::Float(value)) => value.is_finite(),
            _ => false,
        },
        Inode::Blob { tainted, .. } => !tainted,
        _ => false,
    }
}
