use active_infinity::interop::to_redacted_json;
use active_infinity::{InfinityModule, Inode, SecretBytes};

fn build(pairs: i64) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut elements = Vec::new();
    for index in 0..pairs {
        elements.push(module.push(Inode::Secret(SecretBytes::from(format!("{index:05}")))));
        elements.push(module.push(Inode::Int(index)));
    }
    let root = module.push(Inode::Array { elements });
    module.set_root(Some(root));
    module
}

#[test]
fn probe_scaling() {
    for pairs in [1000i64, 2000, 4000, 8000] {
        let module = build(pairs);
        let start = std::time::Instant::now();
        let json = to_redacted_json(&module);
        println!("PROBE pairs={pairs} nodes={} ok={} took {:?}", module.node_count(), json.is_ok(), start.elapsed());
    }
}
