#![no_main]
//! The companion-schema class parses attacker bytes as a module and then
//! validates an instance against it: both steps must stay total.

use libfuzzer_sys::fuzz_target;

use active_infinity::{encode, InfinityModule, Inode, Schema};

fn fixture() -> Vec<u8> {
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Str("schema-fixture".into()));
    let root = module.push(Inode::Table {
        fields: vec![("value".into(), value)],
    });
    module.set_root(Some(root));
    encode(&module).expect("fixture encodes")
}

fuzz_target!(|data: &[u8]| {
    let image = fixture();
    match Schema::from_bytes(data) {
        Ok(schema) => {
            if let Err(error) = schema.validate_bytes(&image) {
                assert!(
                    error.code().starts_with("infinity/"),
                    "schema refusal without a codec code: {error}"
                );
            }
        }
        Err(error) => assert!(
            error.code().starts_with("infinity/"),
            "schema parse refusal without a codec code: {error}"
        ),
    }
});
