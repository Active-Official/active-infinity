#![no_main]
//! Merging two decoded modules must be total and deterministic: the same pair
//! always produces the same decision shape, and a conflict list is stable.

use libfuzzer_sys::fuzz_target;

use active_infinity::{
    encode, merge, Conflict, InfinityModule, Inode, Merge,
};

fn wrap(bytes: &[u8]) -> Vec<u8> {
    let mut module = InfinityModule::new();
    let text = String::from_utf8_lossy(bytes).into_owned();
    let value = module.push(Inode::Str(text));
    let root = module.push(Inode::Table {
        fields: vec![("value".into(), value)],
    });
    module.set_root(Some(root));
    encode(&module).expect("a wrapped module encodes")
}

fn summary(result: Merge) -> (bool, Vec<String>) {
    match result {
        Merge::Clean(module) => {
            // A clean merge must be a real module: encode and validate it, or a
            // merge that leaves a dangling node would pass unnoticed.
            let image = encode(&module).expect("a clean merge encodes");
            assert!(
                active_infinity::validate(&image).is_ok(),
                "a clean merge produced an invalid image"
            );
            (true, Vec::new())
        }
        Merge::Conflicts(conflicts) => (
            false,
            conflicts
                .into_iter()
                .map(|Conflict { field, .. }| field)
                .collect(),
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    let (left_bytes, right_bytes) = data.split_at(data.len() / 2);
    let left = active_infinity::decode(&wrap(left_bytes)).expect("wrapped image decodes");
    let right = active_infinity::decode(&wrap(right_bytes)).expect("wrapped image decodes");
    let mut empty = InfinityModule::new();
    empty.set_root(None);

    let first = summary(merge(&empty, &left, &right).expect("merge is total"));
    let second = summary(merge(&empty, &left, &right).expect("merge is deterministic"));
    assert_eq!(first, second, "merge is not deterministic");
});
