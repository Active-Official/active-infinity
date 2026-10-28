//! Shared helpers for the Active Infinity fuzz targets.
//!
//! These helpers only use the public API plus the documented wire layout. They
//! never weaken validation: a mutation is written to bytes, the content hash is
//! recomputed, and the library decides.

#![allow(dead_code)]

use active_infinity::layout::{Header, Section};
use active_infinity::{
    hash_image, AnnotationKind, InfinityModule, Inode, ProvEntry, ProvValue, Provenance,
    SecretBytes, UnitTag,
};

/// A small module with a table, a quantity, an annotation, provenance and a
/// secret. It gives every target a valid structural seed.
pub fn fixture() -> InfinityModule {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("svc".into()));
    let port = module.push(Inode::Int(8080));
    let number = module.push(Inode::Int(5));
    let quantity = module.push(Inode::Quantity {
        value: number,
        unit: UnitTag::Milliseconds,
    });
    let secret = module.push(Inode::Secret(SecretBytes::from("canary-0123456789")));
    let root = module.push(Inode::Table {
        fields: vec![
            ("name".into(), name),
            ("port".into(), port),
            ("q".into(), quantity),
            ("secret".into(), secret),
        ],
    });
    module.set_root(Some(root));
    module.annotate(root, AnnotationKind::Intent("service table".into()));
    module.set_provenance(Some(Provenance {
        producer: Some("fuzz".into()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: None,
        entries: vec![
            ProvEntry {
                key: "producer".into(),
                value: ProvValue::Text("fuzz".into()),
            },
            ProvEntry {
                key: "source".into(),
                value: ProvValue::Text("fixture".into()),
            },
        ],
    }));
    module
}

/// A short secret derived from fuzz input. The fixed prefix and hex alphabet
/// keep it out of formatter field names (`timestamp_ms` once collided with a
/// three-letter canary and produced a false leak).
pub fn canary(data: &[u8]) -> String {
    let mut out = String::from("canary-");
    for byte in data.iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    if out.len() < 10 {
        out.push_str("00");
    }
    out
}

/// The root node id from the bindings section, if one is set.
pub fn root_node(bytes: &[u8]) -> Option<u32> {
    let header = Header::parse(bytes).ok()?;
    let at = header.span(Section::Bindings).offset as usize;
    let root = get_u32(bytes, at)?;
    if root == u32::MAX {
        None
    } else {
        Some(root)
    }
}

/// A ring of `length` `Ref` nodes with a leaf `Int`, plus a root table that
/// points at both the head of the chain and the leaf. Closing the ring keeps
/// every node reachable, so validation reaches the acyclicity check rather than
/// the reachability check that fires first for a stranded tail.
pub fn ring_chain(length: u32) -> InfinityModule {
    let mut module = InfinityModule::new();
    let leaf = module.push(Inode::Int(7));
    let mut head = module.push(Inode::Ref(leaf));
    for _ in 1..length.max(1) {
        head = module.push(Inode::Ref(head));
    }
    let root = module.push(Inode::Table {
        fields: vec![("head".into(), head), ("leaf".into(), leaf)],
    });
    module.set_root(Some(root));
    module
}

/// Kind byte of a node record.
pub fn kind(bytes: &[u8], node: u32) -> Option<u8> {
    let header = Header::parse(bytes).ok()?;
    let at = header.span(Section::Nodes).offset as usize + node as usize * 32;
    bytes.get(at).copied()
}

/// Children of a `Table` node, read from the children table.
pub fn table_children(bytes: &[u8], node: u32) -> Vec<u32> {
    let Ok(header) = Header::parse(bytes) else {
        return Vec::new();
    };
    let nodes = header.span(Section::Nodes).offset as usize;
    let at = nodes + node as usize * 32;
    if at + 32 > bytes.len() || bytes[at] != 8 {
        return Vec::new();
    }
    let first = get_u64(bytes, at + 8).unwrap_or(0) as usize;
    let count = get_u64(bytes, at + 16).unwrap_or(0) as usize;
    let table = header.span(Section::Children).offset as usize + first * 4;
    let mut out = Vec::with_capacity(count.min(1024));
    for index in 0..count.min(1024) {
        if let Some(value) = get_u32(bytes, table + index * 4) {
            out.push(value);
        }
    }
    out
}

/// Number of node records.
pub fn node_count(bytes: &[u8]) -> Option<u32> {
    Header::parse(bytes)
        .ok()
        .map(|header| header.span(Section::Nodes).count)
}

/// The child of a `Ref` node, if `node` is a `Ref`.
pub fn ref_child(bytes: &[u8], node: u32) -> Option<u32> {
    let header = Header::parse(bytes).ok()?;
    let at = header.span(Section::Nodes).offset as usize + node as usize * 32;
    if at + 32 > bytes.len() || bytes[at] != 11 {
        return None;
    }
    get_u32(bytes, at + 8)
}

pub fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
    if at + 2 <= bytes.len() {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
}

pub fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    if at + 4 <= bytes.len() {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
}

pub fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    if at + 8 <= bytes.len() {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
}

pub fn get_u32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 4)
        .map(|slice| u32::from_le_bytes(slice.try_into().expect("four bytes")))
}

pub fn get_u64(bytes: &[u8], at: usize) -> Option<u64> {
    bytes
        .get(at..at + 8)
        .map(|slice| u64::from_le_bytes(slice.try_into().expect("eight bytes")))
}

/// Recompute the content hash after a byte mutation.
pub fn rehash(bytes: &mut [u8]) -> bool {
    match hash_image(bytes) {
        Ok(hash) if bytes.len() >= 48 => {
            bytes[16..48].copy_from_slice(&hash);
            true
        }
        _ => false,
    }
}

pub fn nodes_offset(bytes: &[u8]) -> Option<usize> {
    Header::parse(bytes)
        .ok()
        .map(|header| header.span(Section::Nodes).offset as usize)
}

pub fn edges_offset(bytes: &[u8]) -> Option<usize> {
    Header::parse(bytes)
        .ok()
        .map(|header| header.span(Section::Edges).offset as usize)
}

pub fn edges_count(bytes: &[u8]) -> Option<u32> {
    Header::parse(bytes)
        .ok()
        .map(|header| header.span(Section::Edges).count)
}

/// A `Ref` chain: node 0 is an `Int`, nodes 1..=depth are `Ref(previous)`, and
/// the root is the last node. Validation sees a chain of `depth` edges.
pub fn ref_chain(depth: u32) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut current = module.push(Inode::Int(0));
    for _ in 0..depth {
        current = module.push(Inode::Ref(current));
    }
    module.set_root(Some(current));
    module
}

/// Point `node`'s `a` field at `target` (the child of a `Ref`), then rebuild the
/// derived edge table in the documented sorted order and rehash.
///
/// Returns false when the image is too short or the record is not where the
/// header says it is.
pub fn repoint_ref(bytes: &mut [u8], node: u32, target: u32) -> bool {
    let Some(nodes) = nodes_offset(bytes) else {
        return false;
    };
    let Some(record) = nodes.checked_add(node as usize * 32) else {
        return false;
    };
    if record + 32 > bytes.len() {
        return false;
    }
    // Kind 11 is Ref; `a` (the child) is the u64 at offset 8.
    if bytes[record] != 11 {
        return false;
    }
    put_u64(bytes, record + 8, target as u64);

    let Some(edges) = edges_offset(bytes) else {
        return false;
    };
    let Some(count) = edges_count(bytes) else {
        return false;
    };
    if count as usize * 8 + edges > bytes.len() {
        return false;
    }
    // Every Ref node contributes (child, node). Rebuild all of them from the
    // node records so the table still equals the derivation.
    let Some(node_count) = Header::parse(bytes)
        .ok()
        .map(|header| header.span(Section::Nodes).count)
    else {
        return false;
    };
    let mut pairs = Vec::new();
    for index in 0..node_count {
        let at = nodes + index as usize * 32;
        if at + 32 > bytes.len() {
            return false;
        }
        if bytes[at] == 11 {
            let child = get_u64(bytes, at + 8).unwrap_or(u64::MAX) as u32;
            pairs.push((child, index));
        }
    }
    if pairs.len() != count as usize {
        return false;
    }
    pairs.sort_unstable();
    for (position, (child, owner)) in pairs.iter().enumerate() {
        put_u32(bytes, edges + position * 8, *child);
        put_u32(bytes, edges + position * 8 + 4, *owner);
    }
    rehash(bytes)
}
