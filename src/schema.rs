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
use crate::{decode, encode, Error, Result};

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

    /// Read a schema from a canonical AINF schema module.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // `decode` validates the image; a second `validate` would double the work.
        let module = decode(bytes)?;
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
    pub fn validate_instance(&self, instance: &InfinityModule) -> Result<()> {
        let root = instance
            .root()
            .ok_or(Error::Schema("instance has no root"))?;
        let instance_fields = match instance.get(root) {
            Some(Inode::Table { fields }) | Some(Inode::SchemaTable { fields, .. }) => fields,
            _ => return Err(Error::Schema("instance root must be a table")),
        };
        let schema_root = self
            .module
            .root()
            .ok_or(Error::Schema("schema module has no root"))?;
        let schema_fields = match self.module.get(schema_root) {
            Some(Inode::SchemaTable { fields, .. }) => fields,
            _ => return Err(Error::Schema("schema root must be a SchemaTable")),
        };

        for (name, node) in schema_fields {
            let spec = match self.module.get(*node) {
                Some(Inode::SchemaField(spec)) => spec,
                _ => return Err(Error::Schema("schema field is not a SchemaField")),
            };
            let value = instance_fields
                .iter()
                .find(|(field, _)| field == name)
                .map(|(_, id)| *id);
            match value {
                Some(id) => {
                    let inode = instance
                        .get(id)
                        .ok_or(Error::Schema("instance field points outside the module"))?;
                    if !matches_type(&spec.typ, inode) {
                        return Err(Error::Schema("instance field has the wrong type"));
                    }
                    self.check_constraints(spec, instance, id, inode)?;
                }
                None if spec.default.is_some() => {
                    // A default marks the field optional. Its value must still be a
                    // value of the declared type, or the schema is lying about what
                    // a consumer will read.
                    let default = spec.default.expect("checked above");
                    let node = self
                        .module
                        .get(default)
                        .ok_or(Error::Schema("schema default points outside the module"))?;
                    if !matches_type(&spec.typ, node) {
                        return Err(Error::Schema("schema default has the wrong type"));
                    }
                }
                None => return Err(Error::Schema("required instance field is missing")),
            }
        }

        if self.closed {
            for (name, _) in instance_fields {
                if !schema_fields.iter().any(|(field, _)| field == name) {
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
    /// pinned schema hash means nothing.
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
        let numeric = |module: &InfinityModule, node: NodeId| -> Option<f64> {
            match module.get(node)? {
                Inode::Int(value) => Some(*value as f64),
                Inode::Float(value) => Some(*value),
                Inode::DurationMs(value) => Some(*value as f64),
                Inode::Quantity { value, .. } => match module.get(*value)? {
                    Inode::Int(value) => Some(*value as f64),
                    Inode::Float(value) => Some(*value),
                    _ => None,
                },
                _ => None,
            }
        };
        if spec.min.is_some() || spec.max.is_some() {
            let value = numeric(instance, id)
                .ok_or(Error::Schema("a bounded field must hold a numeric value"))?;
            if let Some(min) = spec.min {
                let bound = numeric(&self.module, min)
                    .ok_or(Error::Schema("schema minimum is not numeric"))?;
                if value < bound {
                    return Err(Error::Schema("instance field is below its minimum"));
                }
            }
            if let Some(max) = spec.max {
                let bound = numeric(&self.module, max)
                    .ok_or(Error::Schema("schema maximum is not numeric"))?;
                if value > bound {
                    return Err(Error::Schema("instance field is above its maximum"));
                }
            }
        }
        if spec.min_len.is_some() || spec.max_len.is_some() {
            let Inode::Str(text) = node else {
                return Err(Error::Schema("a length-bounded field must hold a string"));
            };
            let length = text.chars().count() as f64;
            if let Some(min) = spec.min_len {
                let bound = numeric(&self.module, min)
                    .ok_or(Error::Schema("schema minimum length is not numeric"))?;
                if length < bound {
                    return Err(Error::Schema("instance field is shorter than its minimum"));
                }
            }
            if let Some(max) = spec.max_len {
                let bound = numeric(&self.module, max)
                    .ok_or(Error::Schema("schema maximum length is not numeric"))?;
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

/// Whether a node is a *value* of the declared type.
///
/// Only the value plane matches: an `Ident`, an `Interpolate`, a `SecretRef`, a
/// `SchemaTable` or a `ContentAddressed` node is a program fragment, not a value,
/// and accepting one would let a "typed" instance resolve into something the
/// schema never described.
fn matches_type(typ: &TypeSpec, node: &Inode) -> bool {
    match typ {
        TypeSpec::Null => matches!(node, Inode::Null),
        TypeSpec::Bool => matches!(node, Inode::Bool(_)),
        TypeSpec::Int => matches!(node, Inode::Int(_)),
        TypeSpec::Float => matches!(node, Inode::Float(_)),
        TypeSpec::String => matches!(node, Inode::Str(_)),
        // A duration is a millisecond count or a quantity in a time unit; the
        // discriminant range 0..=7 is the closed time table (layout §5.2).
        TypeSpec::Duration => match node {
            Inode::DurationMs(_) => true,
            Inode::Quantity { unit, .. } => unit.discriminant() <= 7,
            _ => false,
        },
        TypeSpec::Bytes => matches!(node, Inode::Blob { .. }),
        TypeSpec::Blob => matches!(node, Inode::Blob { .. }),
        TypeSpec::Table { .. } => matches!(node, Inode::Table { .. }),
        TypeSpec::Enum(values) => match node {
            Inode::Str(value) => values.iter().any(|candidate| candidate == value),
            _ => false,
        },
        // A locator is not a secret value; only the secret itself is.
        TypeSpec::Secret => matches!(node, Inode::Secret(_)),
        TypeSpec::Any => true,
    }
}
