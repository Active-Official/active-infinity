//! Print the encoded-size matrix used in `docs/spec/performance.md`.
//!
//! The same logical table (N string-to-integer fields plus a name) is encoded by
//! Active Infinity and by three real competitor formats. Run:
//!
//! ```text
//! cargo run --release --example bakeoff_sizes --all-features
//! ```

use std::collections::{BTreeMap, HashMap};

use active_infinity::{encode, InfinityModule, Inode};

#[derive(Clone, PartialEq, prost::Message)]
struct ProstTable {
    #[prost(map = "string, int64", tag = "1")]
    fields: HashMap<String, i64>,
    #[prost(string, tag = "2")]
    name: String,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct RkyvTable {
    fields: BTreeMap<String, i64>,
    name: String,
}

fn pairs(fields: usize) -> BTreeMap<String, i64> {
    (0..fields)
        .map(|index| (format!("field-{index}"), index as i64))
        .collect()
}

fn infinity(fields: usize) -> Vec<u8> {
    let mut module = InfinityModule::new();
    let mut table = Vec::with_capacity(fields + 1);
    for index in 0..fields {
        let value = module.push(Inode::Int(index as i64));
        table.push((format!("field-{index}"), value));
    }
    let name = module.push(Inode::Str("bakeoff".into()));
    table.push(("name".into(), name));
    let root = module.push(Inode::Table { fields: table });
    module.set_root(Some(root));
    encode(&module).expect("encode")
}

fn main() {
    println!("| Fields | Infinity | serde_json | prost | rkyv |");
    println!("|---|---|---|---|---|");
    for fields in [8usize, 1_000, 10_000] {
        let mut map = serde_json::Map::new();
        for (key, value) in pairs(fields) {
            map.insert(key, serde_json::Value::from(value));
        }
        map.insert("name".to_string(), serde_json::Value::from("bakeoff"));
        let json = serde_json::to_vec(&map).expect("json");
        let prost = ProstTable {
            fields: pairs(fields).into_iter().collect(),
            name: "bakeoff".to_string(),
        };
        let prost = prost::Message::encode_to_vec(&prost);
        let rkyv = rkyv::to_bytes::<rkyv::rancor::Error>(&RkyvTable {
            fields: pairs(fields),
            name: "bakeoff".to_string(),
        })
        .expect("rkyv")
        .to_vec();
        let infinity = infinity(fields);
        println!(
            "| {fields} | {} | {} | {} | {} |",
            infinity.len(),
            json.len(),
            prost.len(),
            rkyv.len()
        );
    }
}
