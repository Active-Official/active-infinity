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
use crate::{decode, encode, validate, Error, Result};

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
        for (name, typ) in fields {
            if name.is_empty() {
                return Err(Error::Schema("field name is empty"));
            }
            let node = module.push(Inode::SchemaField(SchemaFieldSpec::bare(typ.clone())));
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
        let validated = validate(bytes)?;
        let _ = validated;
        let module = decode(bytes)?;
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
                }
                None if spec.default.is_some() => {}
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
        validate(bytes)?;
        let instance = decode(bytes)?;
        self.validate_instance(&instance)
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

fn matches_type(typ: &TypeSpec, node: &Inode) -> bool {
    match typ {
        TypeSpec::Null => matches!(node, Inode::Null),
        TypeSpec::Bool => matches!(node, Inode::Bool(_)),
        TypeSpec::Int => matches!(node, Inode::Int(_)),
        TypeSpec::Float => matches!(node, Inode::Float(_)),
        TypeSpec::String => matches!(
            node,
            Inode::Str(_) | Inode::Ident(_) | Inode::Interpolate { .. }
        ),
        TypeSpec::Duration => matches!(node, Inode::DurationMs(_) | Inode::Quantity { .. }),
        TypeSpec::Bytes | TypeSpec::Blob => {
            matches!(node, Inode::Blob { .. } | Inode::ContentAddressed { .. })
        }
        TypeSpec::Table { .. } => {
            matches!(node, Inode::Table { .. } | Inode::SchemaTable { .. })
        }
        TypeSpec::Enum(values) => match node {
            Inode::Str(value) => values.iter().any(|candidate| candidate == value),
            _ => false,
        },
        TypeSpec::Secret => {
            matches!(node, Inode::Secret(_) | Inode::SecretRef { .. })
        }
        TypeSpec::Any => true,
    }
}
