//! Generate the checked-in conformance vector set.
//!
//! `cargo run --example generate_vectors`. The output is committed:
//!
//! - `tests/vectors/valid/*.ainf` — canonical images, plus one image that is
//!   *valid but not canonical* (an unreferenced string in the heap) to exercise
//!   `validate_canonical`;
//! - `tests/vectors/invalid/*.ainf` — one image per validation class declared in
//!   `docs/spec/layout.md`, each crafted to trigger exactly that class;
//! - `tests/vectors/invalid_stream/*.ainf` — one byte stream per frame-layer
//!   error class, fed through `StreamDecoder`;
//! - `index.txt` per directory with the expectation (`size`, hash, counts, or the
//!   stable error code, plus optional `limits=` / `canonical=no` suffixes).
//!
//! Vectors are derived from the shipped encoder and validator, so a change in
//! canonical form or in an error class shows up as a reviewable diff here. The
//! patch helpers below deliberately build malformed images by hand: the encoder
//! refuses to produce them, which is the point.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use active_infinity::stream::{encode_stream, Frame, FrameKind};
use active_infinity::{
    encode, hash_image, validate, AnnotationKind, DecodeOpts, InfinityModule, Inode, ProvEntry,
    ProvValue, Provenance, SchemaFieldSpec, Section, TypeSpec, UnitTag,
};

const HEADER_SIZE: usize = active_infinity::HEADER_SIZE;

fn fixture() -> InfinityModule {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("conformance".into()));
    let port = module.push(Inode::Int(8080));
    let rate = {
        let number = module.push(Inode::Float(2.5));
        module.push(Inode::Quantity {
            value: number,
            unit: UnitTag::RequestsPerSecond,
        })
    };
    let custom = {
        let number = module.push(Inode::Int(7));
        module.push(Inode::Quantity {
            value: number,
            unit: UnitTag::Named("widgets".into()),
        })
    };
    let secret = module.push(Inode::Secret(active_infinity::SecretBytes::from(
        "vector-secret",
    )));
    let flags = {
        let a = module.push(Inode::Bool(true));
        let b = module.push(Inode::Null);
        module.push(Inode::Array {
            elements: vec![a, b],
        })
    };
    let schema = module.push(Inode::SchemaField(SchemaFieldSpec::bare(TypeSpec::Table {
        closed: true,
    })));
    let root = module.push(Inode::Table {
        fields: vec![
            ("name".into(), name),
            ("port".into(), port),
            ("rate".into(), rate),
            ("custom".into(), custom),
            ("secret".into(), secret),
            ("flags".into(), flags),
            ("schema".into(), schema),
        ],
    });
    module.set_root(Some(root));
    module.bind("root", root);
    module.annotate(root, AnnotationKind::Intent("conformance fixture".into()));
    module.annotate(root, AnnotationKind::AiImmutable(true));
    module.set_provenance(Some(Provenance {
        producer: Some("generate_vectors".into()),
        timestamp_ms: 1_700_000_000_000,
        model: None,
        tool: Some("active-infinity".into()),
        parent: Some([4u8; 32]),
        entries: vec![ProvEntry {
            key: "kind".into(),
            value: ProvValue::Text("conformance".into()),
        }],
    }));
    module
}

fn simple() -> InfinityModule {
    let mut module = InfinityModule::new();
    let text = module.push(Inode::Str("hello".into()));
    let number = module.push(Inode::Int(42));
    let root = module.push(Inode::Table {
        fields: vec![("greeting".into(), text), ("answer".into(), number)],
    });
    module.set_root(Some(root));
    module
}

fn with_strings() -> InfinityModule {
    let mut module = InfinityModule::new();
    let a = module.push(Inode::Str("aaa".into()));
    let b = module.push(Inode::Str("mmm".into()));
    let c = module.push(Inode::Str("zzz".into()));
    let root = module.push(Inode::Array {
        elements: vec![a, b, c],
    });
    module.set_root(Some(root));
    module
}

fn with_two_bindings() -> InfinityModule {
    let mut module = simple();
    let extra = module.push(Inode::Int(1));
    module.bind("alpha", extra);
    module.bind("beta", extra);
    module
}

fn with_ref() -> InfinityModule {
    // A root reference to one leaf: the smallest module with an edge.
    let mut module = InfinityModule::new();
    let target = module.push(Inode::Int(1));
    let root = module.push(Inode::Ref(target));
    module.set_root(Some(root));
    module
}

fn with_extensions() -> InfinityModule {
    let mut module = simple();
    module.add_extension(10, b"first".to_vec());
    module.add_extension(20, b"second".to_vec());
    module.add_extension(30, b"third".to_vec());
    module
}

/// A flat table of integers, used by the merge vectors.
fn int_fields(fields: &[(&str, i64)]) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut nodes = Vec::with_capacity(fields.len());
    for (name, value) in fields {
        let id = module.push(Inode::Int(*value));
        nodes.push(((*name).to_string(), id));
    }
    let root = module.push(Inode::Table { fields: nodes });
    module.set_root(Some(root));
    module
}

/// One nested table (`server.host`, `server.port`), used by the merge vectors.
fn nested_fields(port: i64, host: i64) -> InfinityModule {
    let mut module = InfinityModule::new();
    let port_node = module.push(Inode::Int(port));
    let host_node = module.push(Inode::Int(host));
    let server = module.push(Inode::Table {
        fields: vec![
            ("host".to_string(), host_node),
            ("port".to_string(), port_node),
        ],
    });
    let root = module.push(Inode::Table {
        fields: vec![("server".to_string(), server)],
    });
    module.set_root(Some(root));
    module
}

// ---------------------------------------------------------------------------
// byte-level helpers
// ---------------------------------------------------------------------------

fn header(bytes: &[u8]) -> active_infinity::layout::Header {
    active_infinity::layout::Header::parse(bytes).expect("valid header")
}

fn nodes_offset(bytes: &[u8]) -> usize {
    header(bytes).span(Section::Nodes).offset as usize
}

fn node_field_offset(bytes: &[u8], id: u32, field: usize) -> usize {
    nodes_offset(bytes) + id as usize * 32 + field
}

fn find_node(bytes: &[u8], predicate: impl Fn(&Inode) -> bool) -> u32 {
    let module = active_infinity::decode(bytes).expect("decode");
    module
        .nodes()
        .iter()
        .position(predicate)
        .map(|index| index as u32)
        .expect("node found")
}

fn fix_hash(bytes: &mut [u8]) {
    let hash = hash_image(bytes).expect("hash");
    bytes[16..48].copy_from_slice(&hash);
}

fn patch_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn serialize_frames(frames: &[Frame]) -> Vec<u8> {
    let mut out = Vec::new();
    for frame in frames {
        out.extend_from_slice(&frame.to_bytes());
    }
    out
}

/// Rebuild a valid image from its section bodies after `mutate` edits them.
///
/// Section offsets, `total_size` and the content hash are recomputed, so a
/// mutation may change a section's length as long as it updates the matching
/// count in the header. The base must be valid; the result is not checked here
/// because these vectors are intentionally invalid.
fn rebuild(
    base: &[u8],
    mutate: impl FnOnce(&mut [Vec<u8>], &mut active_infinity::layout::Header),
) -> Vec<u8> {
    let validated = active_infinity::Validated::new(base, DecodeOpts::default())
        .expect("the rebuild base must be valid");
    let mut header = *validated.header();
    let mut bodies: Vec<Vec<u8>> = Section::ALL
        .iter()
        .map(|section| validated.section(*section).to_vec())
        .collect();
    mutate(&mut bodies, &mut header);

    let mut image = vec![0u8; HEADER_SIZE];
    for section in Section::ALL {
        while image.len() % 8 != 0 {
            image.push(0);
        }
        header.span_mut(section).offset = image.len() as u32;
        image.extend_from_slice(&bodies[section as usize]);
    }
    while image.len() % 8 != 0 {
        image.push(0);
    }
    header.total_size = image.len() as u64;
    header.write(&mut image);
    fix_hash(&mut image);
    image
}

/// Insert an unreferenced string into the heap, producing a valid but
/// non-canonical image (the encoder never emits unused strings).
fn add_unused_string(bytes: &[u8]) -> Vec<u8> {
    rebuild(bytes, |bodies, header| {
        let index = Section::Strings as usize;
        let count = header.span(Section::Strings).count as usize;
        let mut table: Vec<u32> = (0..=count)
            .map(|i| {
                u32::from_le_bytes(bodies[index][i * 4..i * 4 + 4].try_into().expect("4 bytes"))
            })
            .collect();
        let mut heap = bodies[index][(count + 1) * 4..].to_vec();
        heap.extend_from_slice(b"~~~unused");
        table.push(heap.len() as u32);
        let mut rebuilt = Vec::new();
        for offset in &table {
            rebuilt.extend_from_slice(&offset.to_le_bytes());
        }
        rebuilt.extend_from_slice(&heap);
        bodies[index] = rebuilt;
        header.span_mut(Section::Strings).count = (count + 1) as u32;
    })
}

/// Turn the two-node reference image into a two-node cycle.
///
/// The encoder refuses to produce a cycle, so the bytes are patched by hand:
/// node 1 becomes a reference back to node 0 and the stored edge table gains
/// `(0, 1)`. The result is layout-valid and edge-consistent, which is exactly
/// the case the acyclicity check exists for.
fn build_cycle(bytes: &[u8]) -> Vec<u8> {
    rebuild(bytes, |bodies, header| {
        let nodes = &mut bodies[Section::Nodes as usize];
        assert_eq!(nodes.len(), 64, "the base has exactly two nodes");
        nodes[32] = 11; // node 1: kind = Ref
        nodes[40..44].copy_from_slice(&0u32.to_le_bytes()); // ... pointing at node 0
        let stored = bodies[Section::Edges as usize].clone();
        assert_eq!(stored.len(), 8, "the base has exactly one edge");
        let mut edges = Vec::with_capacity(16);
        edges.extend_from_slice(&0u32.to_le_bytes()); // (child 0, parent 1)
        edges.extend_from_slice(&1u32.to_le_bytes());
        edges.extend_from_slice(&stored); // (child 1, parent 0)
        bodies[Section::Edges as usize] = edges;
        header.span_mut(Section::Edges).count = 2;
    })
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    let valid_dir = root.join("valid");
    let invalid_dir = root.join("invalid");
    fs::create_dir_all(&valid_dir).expect("valid dir");
    fs::create_dir_all(&invalid_dir).expect("invalid dir");

    // ---- valid --------------------------------------------------------
    let empty = InfinityModule::new();
    let fixtures: BTreeMap<&str, InfinityModule> = [
        ("empty", empty),
        ("simple", simple()),
        ("full", fixture()),
        ("extensions", with_extensions()),
    ]
    .into_iter()
    .collect();
    let mut index =
        String::from("# name total_size content_hash nodes strings blobs [canonical=no]\n");
    for (name, module) in &fixtures {
        let bytes = encode(module).expect("encode");
        fs::write(valid_dir.join(format!("{name}.ainf")), &bytes).expect("write");
        let meta = validate(&bytes).expect("validate");
        index.push_str(&format!(
            "{name} {} {} {} {} {}\n",
            meta.total_size,
            active_infinity::ir::hash_hex(&meta.content_hash),
            meta.nodes,
            meta.strings,
            meta.blobs
        ));
    }

    // A valid image that is not canonical: an unreferenced string.
    let non_canonical = add_unused_string(&encode(&simple()).expect("encode"));
    let meta = validate(&non_canonical).expect("structurally valid");
    fs::write(valid_dir.join("non_canonical.ainf"), &non_canonical).expect("write");
    index.push_str(&format!(
        "non_canonical {} {} {} {} {} canonical=no\n",
        meta.total_size,
        active_infinity::ir::hash_hex(&meta.content_hash),
        meta.nodes,
        meta.strings,
        meta.blobs
    ));
    fs::write(valid_dir.join("index.txt"), index).expect("index");

    // ---- invalid ------------------------------------------------------
    let base = encode(&fixture()).expect("encode");
    let simple_bytes = encode(&simple()).expect("encode");
    let strings_bytes = encode(&with_strings()).expect("encode");
    let bindings_bytes = encode(&with_two_bindings()).expect("encode");
    let ref_bytes = encode(&with_ref()).expect("encode");
    let extensions_bytes = encode(&with_extensions()).expect("encode");
    let h = header(&base);

    let mut vectors: Vec<(&str, &str, Vec<u8>, &str)> = Vec::new();
    let mut push =
        |name: &'static str, code: &'static str, bytes: Vec<u8>, suffix: &'static str| {
            vectors.push((name, code, bytes, suffix));
        };

    // Header and framing.
    let mut bad_magic = base.clone();
    bad_magic[0] = b'X';
    push("bad_magic", "infinity/magic", bad_magic, "");
    let mut bad_major = base.clone();
    bad_major[4] = 9;
    push("bad_major", "infinity/version-major", bad_major, "");
    let mut bad_minor = base.clone();
    bad_minor[7] = 9;
    push("bad_minor", "infinity/version-minor", bad_minor, "");
    push(
        "header_truncated",
        "infinity/header-truncated",
        base[..100].to_vec(),
        "",
    );
    let mut bad_header_size = base.clone();
    bad_header_size[10] = 8;
    push(
        "bad_header_size",
        "infinity/header-size",
        bad_header_size,
        "",
    );
    let mut bad_flags = base.clone();
    bad_flags[8] = 0x80;
    push("bad_flags", "infinity/flags", bad_flags, "");
    let mut reserved = base.clone();
    reserved[12] = 1;
    push("reserved", "infinity/reserved", reserved, "");
    let mut bad_dialect = base.clone();
    bad_dialect[48] ^= 0xff;
    push("bad_dialect", "infinity/dialect", bad_dialect, "");
    push(
        "truncated",
        "infinity/truncated",
        base[..base.len() - 8].to_vec(),
        "",
    );
    let mut trailing = base.clone();
    trailing.extend_from_slice(&[0u8; 8]);
    push("trailing", "infinity/trailing-bytes", trailing, "");
    let mut bad_hash = base.clone();
    bad_hash[16] ^= 0xff;
    push("bad_hash", "infinity/hash-mismatch", bad_hash, "");

    // Counts and layout.
    let mut count_bomb = base.clone();
    patch_u32(&mut count_bomb, 68, 1_000_000);
    push("count_bomb", "infinity/count", count_bomb, "");
    let mut short_count = base.clone();
    patch_u32(&mut short_count, 68, 100);
    push("short_count", "infinity/count", short_count, "");
    let mut bad_offset = base.clone();
    let nodes_off = h.span(Section::Nodes).offset;
    patch_u32(&mut bad_offset, 64, nodes_off + 4);
    push("bad_offset", "infinity/offset", bad_offset, "");
    push(
        "limit",
        "infinity/limit",
        simple_bytes.clone(),
        "limits=max_nodes:1",
    );
    let mut bad_padding = base.clone();
    let string_count = h.span(Section::Strings).count as usize;
    let strings_off = h.span(Section::Strings).offset as usize;
    let heap_len = u32::from_le_bytes(
        base[strings_off + string_count * 4..strings_off + string_count * 4 + 4]
            .try_into()
            .expect("4 bytes"),
    ) as usize;
    let padding_at = strings_off + 4 * (string_count + 1) + heap_len;
    if padding_at < base.len() && padding_at % 8 != 0 {
        bad_padding[padding_at] = 0xff;
        fix_hash(&mut bad_padding);
        push("bad_padding", "infinity/padding", bad_padding, "");
    }

    // Symbol tables.
    let mut bad_unit = base.clone();
    let units = h.span(Section::Units).offset as usize;
    patch_u32(&mut bad_unit, units, 999);
    fix_hash(&mut bad_unit);
    push("bad_unit", "infinity/unknown-unit", bad_unit, "");

    let mut unit_ref = base.clone();
    let quantity = find_node(&base, |node| matches!(node, Inode::Quantity { .. }));
    patch_u32(&mut unit_ref, node_field_offset(&base, quantity, 8), 9_999);
    fix_hash(&mut unit_ref);
    push("unit_ref", "infinity/unit-ref", unit_ref, "");

    let mut bad_type = base.clone();
    let schema = find_node(&base, |node| matches!(node, Inode::SchemaField(_)));
    patch_u32(&mut bad_type, node_field_offset(&base, schema, 4), 9_999);
    fix_hash(&mut bad_type);
    push("bad_type", "infinity/type", bad_type, "");

    let mut secret_entry = base.clone();
    let secret = find_node(&base, |node| matches!(node, Inode::Secret(_)));
    patch_u32(&mut secret_entry, node_field_offset(&base, secret, 8), 7);
    fix_hash(&mut secret_entry);
    push("secret_entry", "infinity/secret-entry", secret_entry, "");

    let mut string_ref = base.clone();
    let text = find_node(&base, |node| matches!(node, Inode::Str(_)));
    patch_u32(&mut string_ref, node_field_offset(&base, text, 4), 9_999);
    fix_hash(&mut string_ref);
    push("string_ref", "infinity/string-ref", string_ref, "");

    let mut node_ref = ref_bytes.clone();
    let reference = find_node(&ref_bytes, |node| matches!(node, Inode::Ref(_)));
    patch_u32(
        &mut node_ref,
        node_field_offset(&ref_bytes, reference, 8),
        9_999,
    );
    fix_hash(&mut node_ref);
    push("node_ref", "infinity/node-ref", node_ref, "");

    let mut bad_node = base.clone();
    let boolean = find_node(&base, |node| matches!(node, Inode::Bool(_)));
    patch_u32(&mut bad_node, node_field_offset(&base, boolean, 4), 1);
    fix_hash(&mut bad_node);
    push("bad_node", "infinity/node", bad_node, "");

    // Strings: break UTF-8 inside the last (largest) string.
    let mut bad_utf8 = strings_bytes.clone();
    let sh = header(&strings_bytes);
    let s_count = sh.span(Section::Strings).count as usize;
    let s_off = sh.span(Section::Strings).offset as usize;
    let last_start = u32::from_le_bytes(
        strings_bytes[s_off + (s_count - 1) * 4..s_off + (s_count - 1) * 4 + 4]
            .try_into()
            .expect("4 bytes"),
    ) as usize;
    let heap = s_off + (s_count + 1) * 4;
    bad_utf8[heap + last_start] = 0x80;
    fix_hash(&mut bad_utf8);
    push("bad_utf8", "infinity/utf8", bad_utf8, "");

    // Edges and graph.
    let mut bad_edge = base.clone();
    let edges = h.span(Section::Edges).offset as usize;
    patch_u32(&mut bad_edge, edges, 0xffff_fff0);
    fix_hash(&mut bad_edge);
    push("bad_edge", "infinity/edge", bad_edge, "");

    // A two-node cycle: the stored edge table is rewritten to match, so only
    // the acyclicity check refuses the image. The encoder refuses to produce a
    // cycle, which is why the bytes are patched by hand.
    push("cycle", "infinity/cycle", build_cycle(&ref_bytes), "");

    // Table fields: duplicate a key.
    let mut duplicate_field = simple_bytes.clone();
    let sh = header(&simple_bytes);
    let fields = sh.span(Section::Fields).offset as usize;
    let first_name = u32::from_le_bytes(
        simple_bytes[fields..fields + 4]
            .try_into()
            .expect("4 bytes"),
    );
    patch_u32(&mut duplicate_field, fields + 16, first_name);
    fix_hash(&mut duplicate_field);
    push(
        "duplicate_field",
        "infinity/duplicate-field",
        duplicate_field,
        "",
    );

    // Bindings: duplicate a name.
    let mut duplicate_binding = bindings_bytes.clone();
    let bh = header(&bindings_bytes);
    let bindings = bh.span(Section::Bindings).offset as usize;
    let first_binding_name = u32::from_le_bytes(
        bindings_bytes[bindings + 8..bindings + 12]
            .try_into()
            .expect("4 bytes"),
    );
    patch_u32(&mut duplicate_binding, bindings + 16, first_binding_name);
    fix_hash(&mut duplicate_binding);
    push(
        "duplicate_binding",
        "infinity/duplicate-binding",
        duplicate_binding,
        "",
    );

    // Metadata.
    let mut bad_annotation = base.clone();
    let annotations = h.span(Section::Annotations).offset as usize;
    patch_u32(&mut bad_annotation, annotations + 4, 9);
    fix_hash(&mut bad_annotation);
    push("bad_annotation", "infinity/annotation", bad_annotation, "");

    let mut bad_provenance = base.clone();
    let provenance = h.span(Section::Provenance).offset as usize;
    patch_u32(&mut bad_provenance, provenance + 96, 4);
    fix_hash(&mut bad_provenance);
    push("bad_provenance", "infinity/provenance", bad_provenance, "");

    let mut bad_extension = extensions_bytes.clone();
    let eh = header(&extensions_bytes);
    let ext = eh.span(Section::Extensions).offset as usize;
    let first_tag = u64::from_le_bytes(extensions_bytes[ext..ext + 8].try_into().expect("8 bytes"));
    bad_extension[ext + 16..ext + 24].copy_from_slice(&first_tag.to_le_bytes());
    fix_hash(&mut bad_extension);
    push("bad_extension", "infinity/extension", bad_extension, "");

    // A directory that leaves a gap between payloads: the section stays in
    // range and the tags are sorted, but the middle payload no longer starts
    // where packing puts it. Shifting the *middle* entry keeps the section end
    // unchanged, so this is not a layout fault.
    let mut bad_extension_gap = extensions_bytes.clone();
    let middle_offset = u32::from_le_bytes(
        extensions_bytes[ext + 16 + 8..ext + 16 + 12]
            .try_into()
            .expect("4 bytes"),
    );
    patch_u32(&mut bad_extension_gap, ext + 16 + 8, middle_offset + 8);
    fix_hash(&mut bad_extension_gap);
    push(
        "bad_extension_gap",
        "infinity/extension",
        bad_extension_gap,
        "",
    );

    // Depth: a chain deeper than the configured ceiling.
    let mut chain = InfinityModule::new();
    let mut current = chain.push(Inode::Int(0));
    for _ in 0..64 {
        current = chain.push(Inode::Ref(current));
    }
    chain.set_root(Some(current));
    let chain_bytes = encode(&chain).expect("encode chain");
    push(
        "too_deep",
        "infinity/depth",
        chain_bytes,
        "limits=max_depth:8",
    );

    // Blob payload substitution.
    let payload = b"vector-payload".to_vec();
    let mut blob_module = InfinityModule::new();
    let blob = blob_module.push(Inode::Blob {
        hash: *blake3::hash(&payload).as_bytes(),
        size: payload.len() as u64,
        tainted: false,
        media_type: "text/plain".into(),
        payload: Some(payload),
    });
    blob_module.set_root(Some(blob));
    let blob_bytes = encode(&blob_module).expect("encode blob");
    let mut bad_blob = blob_bytes.clone();
    let bh = header(&blob_bytes);
    let blob_off = bh.span(Section::Blobs).offset as usize;
    let blob_heap = blob_off + bh.span(Section::Blobs).count as usize * 40;
    bad_blob[blob_heap] ^= 0xff;
    fix_hash(&mut bad_blob);
    push("bad_blob", "infinity/blob", bad_blob, "");

    // Canonical-form enforcement is only reachable when the caller opts in
    // (`DecodeOpts::verify_canonical`), so this vector declares its verifier.
    push(
        "not_canonical",
        "infinity/not-canonical",
        non_canonical.clone(),
        "verify=canonical",
    );

    let mut invalid_index =
        String::from("# name expected_code [limits=key:value,...] [verify=canonical]\n");
    for (name, code, bytes, suffix) in &vectors {
        fs::write(invalid_dir.join(format!("{name}.ainf")), bytes).expect("write");
        if suffix.is_empty() {
            invalid_index.push_str(&format!("{name} {code}\n"));
        } else {
            invalid_index.push_str(&format!("{name} {code} {suffix}\n"));
        }
    }
    fs::write(invalid_dir.join("index.txt"), invalid_index).expect("index");

    // ---- invalid streams ----------------------------------------------
    //
    // The frame layer has its own error classes. Each vector below is a byte
    // stream a peer could actually send; the conformance test feeds it through
    // the shipped `StreamDecoder` and expects the declared code.
    let stream_dir = root.join("invalid_stream");
    fs::create_dir_all(&stream_dir).expect("stream dir");
    let frames = encode_stream(&simple(), 256).expect("stream frames");
    assert!(
        frames.len() >= 3 && frames.last().map(|f| f.kind) == Some(FrameKind::End),
        "the stream must begin, batch and end"
    );
    let valid_stream = serialize_frames(&frames);
    let mut stream_vectors: Vec<(&str, &str, Vec<u8>)> = Vec::new();

    let mut frame_magic = valid_stream.clone();
    frame_magic[0] = b'X';
    stream_vectors.push(("frame_magic", "infinity/stream-magic", frame_magic));

    let mut frame_version = valid_stream.clone();
    frame_version[4] = 99;
    stream_vectors.push(("frame_version", "infinity/stream-version", frame_version));

    let mut frame_kind = valid_stream.clone();
    frame_kind[5] = 0xfe;
    stream_vectors.push(("frame_kind", "infinity/stream-frame-kind", frame_kind));

    let mut frame_len = valid_stream.clone();
    patch_u32(&mut frame_len, 16, u32::MAX);
    stream_vectors.push(("frame_len", "infinity/stream-frame-len", frame_len));

    // A duplicated sequence number in the second frame.
    let mut resequenced = frames.clone();
    resequenced[1].sequence = 0;
    stream_vectors.push((
        "sequence",
        "infinity/stream-sequence",
        serialize_frames(&resequenced),
    ));

    // End before Begin.
    let end_payload = frames.last().expect("end frame").payload.clone();
    let state = vec![Frame::new(FrameKind::End, 0, end_payload.clone())];
    stream_vectors.push(("state", "infinity/stream-state", serialize_frames(&state)));

    // The end frame's digest disagrees with the reassembled image.
    let mut bad_hash_frames = frames.clone();
    let last = bad_hash_frames.len() - 1;
    bad_hash_frames[last].payload[0] ^= 0xff;
    stream_vectors.push((
        "hash",
        "infinity/stream-hash",
        serialize_frames(&bad_hash_frames),
    ));

    // A delta frame after a completed generation whose payload has trailing
    // bytes after a zero operation count.
    let mut delta_frames = frames.clone();
    delta_frames.push(Frame::new(
        FrameKind::Delta,
        frames.len() as u64,
        vec![0, 0, 0, 0, 0xff],
    ));
    stream_vectors.push((
        "delta",
        "infinity/stream-delta",
        serialize_frames(&delta_frames),
    ));

    // A generation that never ends.
    let unterminated = serialize_frames(&frames[..frames.len() - 1]);
    stream_vectors.push(("unterminated", "infinity/stream-unterminated", unterminated));

    let mut stream_index = String::from("# name expected_code\n");
    for (name, code, bytes) in &stream_vectors {
        fs::write(stream_dir.join(format!("{name}.ainf")), bytes).expect("write");
        stream_index.push_str(&format!("{name} {code}\n"));
    }
    fs::write(stream_dir.join("index.txt"), stream_index).expect("index");

    // ---- proof and merge vectors --------------------------------------
    //
    // These two features produce and consume files rather than new image
    // bytes, so they get their own directories and their own index files. The
    // proof vectors pin what a verifier must accept and refuse; the merge
    // vectors pin a clean result byte-for-byte and the exact conflict paths.
    #[cfg(feature = "json")]
    {
        write_proof_vectors(&root);
    }

    let merge_dir = root.join("merge");
    fs::create_dir_all(&merge_dir).expect("merge dir");
    let merge_cases: Vec<(&str, InfinityModule, InfinityModule, InfinityModule)> = vec![
        (
            "clean",
            int_fields(&[("alpha", 1), ("beta", 2)]),
            int_fields(&[("alpha", 10), ("beta", 2)]),
            int_fields(&[("alpha", 1), ("beta", 20)]),
        ),
        (
            "nested",
            nested_fields(80, 1),
            nested_fields(8080, 1),
            nested_fields(9090, 1),
        ),
        (
            "metadata",
            int_fields(&[("alpha", 1)]),
            {
                let mut module = int_fields(&[("alpha", 1)]);
                let root = module.root().expect("root");
                module.bind("extra", root);
                module
            },
            int_fields(&[("alpha", 1)]),
        ),
    ];
    let mut merge_index = String::from("# name base left right expected\n");
    for (name, base, left, right) in &merge_cases {
        let base_bytes = encode(base).expect("encode base");
        let left_bytes = encode(left).expect("encode left");
        let right_bytes = encode(right).expect("encode right");
        fs::write(merge_dir.join(format!("{name}.base.ainf")), &base_bytes).expect("write base");
        fs::write(merge_dir.join(format!("{name}.left.ainf")), &left_bytes).expect("write left");
        fs::write(merge_dir.join(format!("{name}.right.ainf")), &right_bytes).expect("write right");
        let expected = match active_infinity::merge(base, left, right).expect("merge") {
            active_infinity::Merge::Clean(module) => {
                let bytes = encode(&module).expect("encode merged");
                fs::write(merge_dir.join(format!("{name}.merged.ainf")), &bytes)
                    .expect("write merged");
                let hash = active_infinity::content_hash(&bytes).expect("hash");
                format!("clean:{}", active_infinity::ir::hash_hex(&hash))
            }
            active_infinity::Merge::Conflicts(conflicts) => {
                let rendered: Vec<String> = conflicts
                    .iter()
                    .map(|conflict| format!("{}:{:?}", conflict.field, conflict.kind))
                    .collect();
                format!("conflict:{}", rendered.join(","))
            }
        };
        merge_index.push_str(&format!(
            "{name} {name}.base.ainf {name}.left.ainf {name}.right.ainf {expected}\n"
        ));
    }
    fs::write(merge_dir.join("index.txt"), merge_index).expect("merge index");

    println!(
        "wrote {} valid, {} invalid and {} invalid-stream vectors, 3 proof cases and {} merge cases to {}",
        fixtures.len() + 1,
        vectors.len(),
        stream_vectors.len(),
        merge_cases.len(),
        root.display()
    );
}

/// Write the proof-sidecar vectors. They need the `json` feature because the
/// sidecar itself is JSON; the merge vectors below do not.
#[cfg(feature = "json")]
fn write_proof_vectors(root: &Path) {
    let proof_dir = root.join("proof");
    fs::create_dir_all(&proof_dir).expect("proof dir");
    let good_image = encode(&fixture()).expect("encode");
    let proof = active_infinity::Proof::issue(&good_image).expect("issue proof");
    fs::write(proof_dir.join("good.ainf"), &good_image).expect("write proof image");
    fs::write(proof_dir.join("good.json"), proof.to_json()).expect("write proof sidecar");
    let tampered = proof.to_json().replace(
        &format!("\"size\":{}", proof.size),
        &format!("\"size\":{}", proof.size.saturating_add(1)),
    );
    assert_ne!(
        tampered,
        proof.to_json(),
        "the tampered sidecar must differ"
    );
    fs::write(proof_dir.join("tampered.json"), &tampered).expect("write tampered sidecar");
    fs::write(
        proof_dir.join("wrong.ainf"),
        encode(&simple()).expect("encode"),
    )
    .expect("write wrong image");
    fs::write(
        proof_dir.join("index.txt"),
        "# name image proof expected\n\
         good good.ainf good.json ok\n\
         tampered good.ainf tampered.json infinity/proof\n\
         wrong wrong.ainf good.json infinity/proof\n",
    )
    .expect("proof index");
}
