//! Agent-facing graph queries over a binary module.
//!
//! ```bash
//! cargo run --example agent_queries
//! ```
//!
//! Answers the three questions an agent asks about a module it received:
//! *why does this value exist*, *what does changing it affect*, and *where is
//! the secret cone* — from the Infinity bytes, not from the source text.

use active_infinity::interop::{impact, node_label, resolve_path, secret_tainted_paths, why};
use active_infinity::{decode, encode};

#[cfg_attr(not(feature = "active-core"), allow(dead_code))]
const SOURCE: &str = r#"
let base = "https://api.example.com"
let timeout = 1500ms

# @intent: "Public edge configuration"
[edge]
host         = "api.example.com"
port         = 8443
read_timeout = timeout * 2
token        = secret("edge-token-canary")
routes       = ["/auth", "/users", "/billing"]

[observability]
level = "info"
"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let module = load()?;
    let bytes = encode(&module)?;
    let module = decode(&bytes)?;
    println!("labels:");
    for (id, label) in sorted_labels(&module) {
        println!("  n{:<3} {}", id.0, label);
    }

    let port = resolve_path(&module, "edge.port").expect("edge.port");
    println!("\nimpact of {}:", node_label(&module, port));
    for label in impact(&module, port) {
        println!("  -> {label}");
    }

    let read_timeout = resolve_path(&module, "edge.read_timeout").expect("read_timeout");
    println!("\nwhy {}:", node_label(&module, read_timeout));
    for label in why(&module, read_timeout) {
        println!("  <- {label}");
    }

    println!("\nsecret cone:");
    for path in secret_tainted_paths(&module) {
        println!("  * {path}");
    }
    Ok(())
}

fn sorted_labels(
    module: &active_infinity::InfinityModule,
) -> Vec<(active_infinity::NodeId, String)> {
    let mut rows: Vec<(active_infinity::NodeId, String)> = (0..module.node_count())
        .map(|index| {
            let id = active_infinity::NodeId(index as u32);
            (id, node_label(module, id))
        })
        .collect();
    rows.sort_by(|a, b| a.1.cmp(&b.1));
    rows
}

fn load() -> Result<active_infinity::InfinityModule, Box<dyn std::error::Error>> {
    #[cfg(feature = "active-core")]
    {
        Ok(active_infinity::interop::from_active_source(
            SOURCE,
            "agent.active",
        )?)
    }
    #[cfg(not(feature = "active-core"))]
    {
        use active_infinity::Inode;
        let mut module = active_infinity::InfinityModule::new();
        let name = module.push(Inode::Str("agent".into()));
        let port = module.push(Inode::Int(8443));
        let root = module.push(Inode::Table {
            fields: vec![("host".into(), name), ("port".into(), port)],
        });
        module.set_root(Some(root));
        Ok(module)
    }
}
