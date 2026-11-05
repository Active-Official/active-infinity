//! F-05 (DeepSeek fix pack): `Any` and an open table keep the whole cone on the
//! value plane.
//!
//! `is_value_node` used to accept an array or table without looking inside, so a
//! nested `Ident` (program plane) passed a schema that documents itself as a
//! data description. These tests drive the shipped `validate_instance`.

use active_infinity::schema::Schema;
use active_infinity::{InfinityModule, Inode, TypeSpec};

fn any_schema() -> Schema {
    Schema::from_fields(&[("payload", TypeSpec::Any)], false).expect("schema")
}

#[test]
fn a_nested_program_node_under_any_is_refused() {
    let schema = any_schema();
    let mut instance = InfinityModule::new();
    let ident = instance.push(Inode::Ident("outside".to_string()));
    let table = instance.push(Inode::Table {
        fields: vec![("ref".to_string(), ident)],
    });
    let root = instance.push(Inode::Table {
        fields: vec![("payload".to_string(), table)],
    });
    instance.set_root(Some(root));
    let error = schema
        .validate_instance(&instance)
        .expect_err("an Ident is program plane, even in a table");
    assert_eq!(error.code(), "infinity/schema", "{error}");
}

#[test]
fn a_nested_program_node_in_an_array_is_refused() {
    let schema = any_schema();
    let mut instance = InfinityModule::new();
    let ident = instance.push(Inode::Ident("outside".to_string()));
    let array = instance.push(Inode::Array {
        elements: vec![ident],
    });
    let root = instance.push(Inode::Table {
        fields: vec![("payload".to_string(), array)],
    });
    instance.set_root(Some(root));
    let error = schema
        .validate_instance(&instance)
        .expect_err("an Ident is program plane, even in an array");
    assert_eq!(error.code(), "infinity/schema", "{error}");
}

#[test]
fn a_pure_data_table_under_any_is_accepted() {
    let schema = any_schema();
    let mut instance = InfinityModule::new();
    let number = instance.push(Inode::Int(7));
    let text = instance.push(Inode::Str("blue".to_string()));
    let table = instance.push(Inode::Table {
        fields: vec![("n".to_string(), number), ("c".to_string(), text)],
    });
    let array = instance.push(Inode::Array {
        elements: vec![table],
    });
    let root = instance.push(Inode::Table {
        fields: vec![("payload".to_string(), array)],
    });
    instance.set_root(Some(root));
    schema
        .validate_instance(&instance)
        .expect("a data cone is accepted");
}

#[test]
fn a_table_field_also_keeps_its_cone_on_the_value_plane() {
    let schema = Schema::from_fields(&[("payload", TypeSpec::Table { closed: false })], false)
        .expect("schema");
    let mut instance = InfinityModule::new();
    let ident = instance.push(Inode::Ident("outside".to_string()));
    let table = instance.push(Inode::Table {
        fields: vec![("ref".to_string(), ident)],
    });
    let root = instance.push(Inode::Table {
        fields: vec![("payload".to_string(), table)],
    });
    instance.set_root(Some(root));
    let error = schema
        .validate_instance(&instance)
        .expect_err("an open table is data, not a program");
    assert_eq!(error.code(), "infinity/schema", "{error}");
}
