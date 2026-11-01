//! Marathon section I-07: the schema class.

use active_infinity::ir::{SchemaFieldSpec, TypeSpec};
use active_infinity::{
    encode, InfinityModule, Inode, InterpPart, NodeId, Schema, SecretBytes, UnitTag,
};

fn instance(fields: Vec<(&str, Inode)>) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut table = Vec::new();
    for (name, node) in fields {
        let id = module.push(node);
        table.push((name.to_string(), id));
    }
    let root = module.push(Inode::Table { fields: table });
    module.set_root(Some(root));
    module
}

#[test]
fn only_value_nodes_match_a_declared_type() {
    // An `Ident`, an interpolation, a `SecretRef` and a `SchemaTable` are program
    // fragments; accepting them let a "typed" instance resolve into something the
    // schema never described.
    let schema = Schema::from_fields(&[("field", TypeSpec::String)], false).expect("schema");
    let with_ident = instance(vec![("field", Inode::Ident("x".to_string()))]);
    assert!(
        schema.validate_instance(&with_ident).is_err(),
        "an Ident is not a string value"
    );
    let with_interpolation = instance(vec![(
        "field",
        Inode::Interpolate {
            parts: vec![InterpPart::Literal("x".to_string())],
        },
    )]);
    assert!(schema.validate_instance(&with_interpolation).is_err());

    let table_schema = Schema::from_fields(&[("field", TypeSpec::Table { closed: false })], false)
        .expect("schema");
    let with_schema_table = instance(vec![(
        "field",
        Inode::SchemaTable {
            fields: Vec::new(),
            closed: false,
        },
    )]);
    assert!(
        table_schema.validate_instance(&with_schema_table).is_err(),
        "a SchemaTable is a schema, not a data table"
    );

    let secret_schema = Schema::from_fields(&[("field", TypeSpec::Secret)], false).expect("schema");
    let locator = Inode::Env {
        name: "TOKEN".to_string(),
        default: None,
    };
    let with_locator = instance(vec![("field", locator.clone())]);
    let mut module = with_locator;
    // A SecretRef needs a locator node; the Env is enough for the shape check.
    let env_id = NodeId(0);
    let secret_ref = module.push(Inode::SecretRef { locator: env_id });
    let root = module.root().expect("root");
    if let Some(Inode::Table { fields }) = module.get_mut(root) {
        if let Some((_, id)) = fields.iter_mut().find(|(name, _)| name == "field") {
            *id = secret_ref;
        }
    }
    assert!(
        secret_schema.validate_instance(&module).is_err(),
        "a locator is not a secret value"
    );

    let bytes_schema = Schema::from_fields(&[("field", TypeSpec::Bytes)], false).expect("schema");
    let with_construction = instance(vec![(
        "field",
        Inode::ContentAddressed {
            media_type: NodeId(0),
            data: NodeId(0),
        },
    )]);
    assert!(
        bytes_schema.validate_instance(&with_construction).is_err(),
        "a construction site is not a bytes value"
    );
}

#[test]
fn a_duration_accepts_time_units_only() {
    let schema = Schema::from_fields(&[("field", TypeSpec::Duration)], false).expect("schema");
    let mut value = InfinityModule::new();
    let count = value.push(Inode::Int(5));
    let time = value.push(Inode::Quantity {
        value: count,
        unit: UnitTag::Seconds,
    });
    let root = value.push(Inode::Table {
        fields: vec![("field".to_string(), time)],
    });
    value.set_root(Some(root));
    schema
        .validate_instance(&value)
        .expect("a time quantity is a duration");

    let mut mass = InfinityModule::new();
    let count = mass.push(Inode::Int(5));
    let grams = mass.push(Inode::Quantity {
        value: count,
        unit: UnitTag::Grams,
    });
    let root = mass.push(Inode::Table {
        fields: vec![("field".to_string(), grams)],
    });
    mass.set_root(Some(root));
    assert!(
        schema.validate_instance(&mass).is_err(),
        "grams are not a duration"
    );
}

#[test]
fn declared_bounds_are_enforced() {
    // A schema that looks restrictive has to reject what it says it rejects.
    let mut module = InfinityModule::new();
    let min = module.push(Inode::Int(10));
    let max = module.push(Inode::Int(20));
    let spec = SchemaFieldSpec {
        typ: TypeSpec::Int,
        min: Some(min),
        max: Some(max),
        ..SchemaFieldSpec::bare(TypeSpec::Int)
    };
    let field = module.push(Inode::SchemaField(spec));
    let root = module.push(Inode::SchemaTable {
        fields: vec![("port".to_string(), field)],
        closed: true,
    });
    module.set_root(Some(root));
    let schema = Schema::from_bytes(&encode(&module).expect("encode")).expect("schema");

    let ok = instance(vec![("port", Inode::Int(15))]);
    schema.validate_instance(&ok).expect("inside the bounds");

    let low = instance(vec![("port", Inode::Int(9))]);
    let error = schema
        .validate_instance(&low)
        .expect_err("below the minimum");
    assert_eq!(error.code(), "infinity/schema");

    let high = instance(vec![("port", Inode::Int(21))]);
    assert!(
        schema.validate_instance(&high).is_err(),
        "above the maximum"
    );
}

#[test]
fn string_length_bounds_are_enforced() {
    let mut module = InfinityModule::new();
    let min = module.push(Inode::Int(3));
    let max = module.push(Inode::Int(5));
    let spec = SchemaFieldSpec {
        typ: TypeSpec::String,
        min_len: Some(min),
        max_len: Some(max),
        ..SchemaFieldSpec::bare(TypeSpec::String)
    };
    let field = module.push(Inode::SchemaField(spec));
    let root = module.push(Inode::SchemaTable {
        fields: vec![("name".to_string(), field)],
        closed: true,
    });
    module.set_root(Some(root));
    let schema = Schema::from_bytes(&encode(&module).expect("encode")).expect("schema");

    schema
        .validate_instance(&instance(vec![("name", Inode::Str("abcd".to_string()))]))
        .expect("inside the length bounds");
    assert!(schema
        .validate_instance(&instance(vec![("name", Inode::Str("ab".to_string()))]))
        .is_err());
    assert!(schema
        .validate_instance(&instance(vec![("name", Inode::Str("abcdef".to_string()))]))
        .is_err());
}

#[test]
fn a_pattern_constraint_is_refused_instead_of_ignored() {
    // The reader has no pattern engine, so a schema carrying one cannot be
    // enforced; accepting the instance would turn the pinned schema hash into a
    // false guarantee.
    let mut module = InfinityModule::new();
    let pattern = module.push(Inode::Str("^admin$".to_string()));
    let spec = SchemaFieldSpec {
        typ: TypeSpec::String,
        pattern: Some(pattern),
        ..SchemaFieldSpec::bare(TypeSpec::String)
    };
    let field = module.push(Inode::SchemaField(spec));
    let root = module.push(Inode::SchemaTable {
        fields: vec![("role".to_string(), field)],
        closed: true,
    });
    module.set_root(Some(root));
    let schema = Schema::from_bytes(&encode(&module).expect("encode")).expect("schema loads");
    let error = schema
        .validate_instance(&instance(vec![("role", Inode::Str("x".to_string()))]))
        .expect_err("an unenforceable constraint is refused");
    assert_eq!(error.code(), "infinity/schema");
    assert!(format!("{error}").contains("pattern"), "{error}");
}

#[test]
fn duplicate_field_names_are_refused_at_construction() {
    let error = Schema::from_fields(&[("a", TypeSpec::Int), ("a", TypeSpec::String)], true)
        .expect_err("two specs for one name");
    assert_eq!(error.code(), "infinity/schema");
}

#[test]
fn a_schema_carrying_a_secret_node_is_refused() {
    // A secret inside a schema is a covert channel in the pinned schema hash with
    // no meaning to a reader.
    let mut module = InfinityModule::new();
    let canary = module.push(Inode::Secret(SecretBytes::from("schema-canary-4411")));
    let spec = SchemaFieldSpec {
        typ: TypeSpec::Int,
        default: Some(canary),
        ..SchemaFieldSpec::bare(TypeSpec::Int)
    };
    let field = module.push(Inode::SchemaField(spec));
    let root = module.push(Inode::SchemaTable {
        fields: vec![("port".to_string(), field)],
        closed: true,
    });
    module.set_root(Some(root));
    let bytes = encode(&module).expect("encode");
    let error = Schema::from_bytes(&bytes).expect_err("a schema is a description");
    assert_eq!(error.code(), "infinity/schema");
}

#[test]
fn a_default_of_the_wrong_type_is_refused() {
    let mut module = InfinityModule::new();
    let default = module.push(Inode::Str("not-a-port".to_string()));
    let spec = SchemaFieldSpec {
        typ: TypeSpec::Int,
        default: Some(default),
        ..SchemaFieldSpec::bare(TypeSpec::Int)
    };
    let field = module.push(Inode::SchemaField(spec));
    let root = module.push(Inode::SchemaTable {
        fields: vec![("port".to_string(), field)],
        closed: true,
    });
    module.set_root(Some(root));
    let schema = Schema::from_bytes(&encode(&module).expect("encode")).expect("schema");
    // The field is absent, so the default would be read; it must be an Int.
    let empty = instance(vec![]);
    let error = schema
        .validate_instance(&empty)
        .expect_err("the default has the wrong type");
    assert_eq!(error.code(), "infinity/schema");
}

#[test]
fn a_bare_schema_still_validates() {
    let schema = Schema::from_fields(&[("port", TypeSpec::Int)], true).expect("schema");
    schema
        .validate_instance(&instance(vec![("port", Inode::Int(1))]))
        .expect("bare schema");
}

fn schema_with(build: impl FnOnce(&mut InfinityModule) -> SchemaFieldSpec) -> Schema {
    let mut module = InfinityModule::new();
    let spec = build(&mut module);
    let field = module.push(Inode::SchemaField(spec));
    let root = module.push(Inode::SchemaTable {
        fields: vec![("value".to_string(), field)],
        closed: false,
    });
    module.set_root(Some(root));
    Schema::from_bytes(&encode(&module).expect("encode schema")).expect("schema")
}

fn bare(typ: TypeSpec) -> SchemaFieldSpec {
    SchemaFieldSpec {
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

#[test]
fn a_default_is_held_to_the_declared_bounds() {
    let schema = schema_with(|module| {
        let min = module.push(Inode::Int(10));
        let max = module.push(Inode::Int(20));
        let default = module.push(Inode::Int(999));
        SchemaFieldSpec {
            min: Some(min),
            max: Some(max),
            default: Some(default),
            ..bare(TypeSpec::Int)
        }
    });
    // No "value" field: the schema falls back to its default, which is outside
    // 10..=20. A missing field must not bypass the bounds.
    let instance = instance(vec![]);
    let error = schema
        .validate_instance(&instance)
        .expect_err("an out-of-bounds default is refused");
    assert_eq!(error.code(), "infinity/schema", "{error}");
}

#[test]
fn a_non_finite_bound_is_refused() {
    let schema = schema_with(|module| {
        let min = module.push(Inode::Float(f64::NAN));
        SchemaFieldSpec {
            min: Some(min),
            ..bare(TypeSpec::Float)
        }
    });
    let instance = instance(vec![("value", Inode::Float(1.0))]);
    let error = schema
        .validate_instance(&instance)
        .expect_err("a NaN bound is not enforceable");
    assert_eq!(error.code(), "infinity/schema", "{error}");
}

#[test]
fn a_non_finite_float_value_is_refused() {
    let schema = schema_with(|_| bare(TypeSpec::Float));
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let instance = instance(vec![("value", Inode::Float(value))]);
        let error = schema
            .validate_instance(&instance)
            .expect_err("a non-finite value is not a Float value");
        assert_eq!(error.code(), "infinity/schema", "{value}: {error}");
    }
}

#[test]
fn duplicate_instance_fields_are_refused() {
    let schema = schema_with(|_| bare(TypeSpec::Int));
    let mut module = InfinityModule::new();
    let first = module.push(Inode::Int(1));
    let second = module.push(Inode::Int(2));
    let root = module.push(Inode::Table {
        fields: vec![("value".to_string(), first), ("value".to_string(), second)],
    });
    module.set_root(Some(root));
    let error = schema
        .validate_instance(&module)
        .expect_err("a duplicate field is ambiguous");
    assert_eq!(error.code(), "infinity/schema", "{error}");
}

#[test]
fn a_duration_quantity_must_hold_a_number() {
    let schema = schema_with(|_| bare(TypeSpec::Duration));
    let mut module = InfinityModule::new();
    let text = module.push(Inode::Str("five".to_string()));
    let quantity = module.push(Inode::Quantity {
        value: text,
        unit: UnitTag::Seconds,
    });
    let root = module.push(Inode::Table {
        fields: vec![("value".to_string(), quantity)],
    });
    module.set_root(Some(root));
    let error = schema
        .validate_instance(&module)
        .expect_err("a duration quantity must be numeric");
    assert_eq!(error.code(), "infinity/schema", "{error}");
}

#[test]
fn a_schema_table_is_not_an_instance() {
    let schema = schema_with(|_| bare(TypeSpec::Int));
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Int(1));
    let root = module.push(Inode::SchemaTable {
        fields: vec![("value".to_string(), value)],
        closed: false,
    });
    module.set_root(Some(root));
    let error = schema
        .validate_instance(&module)
        .expect_err("a SchemaTable is a program fragment");
    assert_eq!(error.code(), "infinity/schema", "{error}");
}

#[test]
fn length_bounds_must_be_non_negative_integers() {
    for bound in [Inode::Int(-1), Inode::Float(2.5), Inode::Float(f64::NAN)] {
        let schema = schema_with(|module| {
            let bound = module.push(bound.clone());
            SchemaFieldSpec {
                min_len: Some(bound),
                ..bare(TypeSpec::String)
            }
        });
        let instance = instance(vec![("value", Inode::Str("abc".to_string()))]);
        let error = schema
            .validate_instance(&instance)
            .expect_err("an unusable length bound is refused");
        assert_eq!(error.code(), "infinity/schema", "{error}");
    }
}

#[test]
fn a_nested_closed_table_is_refused_as_unenforceable() {
    let schema = schema_with(|_| bare(TypeSpec::Table { closed: true }));
    let mut module = InfinityModule::new();
    let inner = module.push(Inode::Int(1));
    let table = module.push(Inode::Table {
        fields: vec![("inner".to_string(), inner)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("value".to_string(), table)],
    });
    module.set_root(Some(root));
    let error = schema
        .validate_instance(&module)
        .expect_err("a nested closed table is not enforceable");
    assert_eq!(error.code(), "infinity/schema", "{error}");
}

#[test]
fn any_does_not_open_the_program_plane() {
    let schema = schema_with(|_| bare(TypeSpec::Any));
    for node in [
        Inode::Secret(SecretBytes::from("any-canary")),
        Inode::Ident("TOKEN".to_string()),
        Inode::Env {
            name: "TOKEN".to_string(),
            default: None,
        },
        Inode::SecretRef { locator: NodeId(0) },
    ] {
        let instance = instance(vec![("value", node.clone())]);
        let error = schema
            .validate_instance(&instance)
            .expect_err("Any is still a value plane");
        assert_eq!(error.code(), "infinity/schema", "{node:?}: {error}");
    }
}

#[test]
fn a_tainted_blob_is_not_a_public_value() {
    let schema = schema_with(|_| bare(TypeSpec::Blob));
    let mut module = InfinityModule::new();
    let blob = module.push(Inode::Blob {
        hash: *blake3::hash(b"tainted").as_bytes(),
        size: 7,
        tainted: true,
        media_type: "application/octet-stream".to_string(),
        payload: None,
    });
    let root = module.push(Inode::Table {
        fields: vec![("value".to_string(), blob)],
    });
    module.set_root(Some(root));
    let error = schema
        .validate_instance(&module)
        .expect_err("a tainted blob carries secret-bearing identity");
    assert_eq!(error.code(), "infinity/schema", "{error}");
}
