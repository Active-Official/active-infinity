#![no_main]
//! A proof sidecar is JSON text from a peer: parsing and verification must be
//! total and every refusal must carry `infinity/proof`.

use libfuzzer_sys::fuzz_target;

use active_infinity::{encode, InfinityModule, Inode, Proof};

fn fixture() -> Vec<u8> {
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Str("sidecar-fixture".into()));
    let root = module.push(Inode::Table {
        fields: vec![("value".into(), value)],
    });
    module.set_root(Some(root));
    encode(&module).expect("fixture encodes")
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let image = fixture();
    match Proof::from_json(text) {
        Ok(proof) => {
            if let Err(error) = proof.verify(&image) {
                assert_eq!(error.code(), "infinity/proof", "verify code");
            }
        }
        Err(error) => assert_eq!(error.code(), "infinity/proof", "parse code"),
    }
});
