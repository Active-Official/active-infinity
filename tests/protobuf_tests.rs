//! Protobuf projection: an independent wire reader checks the shipped encoder.
//!
//! The reader below is written from the published schema in
//! `active_infinity::protobuf`, not from the encoder, so the two sides are
//! independent implementations of the same contract. It also enforces the
//! properties a consumer relies on: exact length prefixes, no bytes left over
//! after a message, and forward-compatible skipping of unknown fields.

#[cfg(feature = "json")]
use active_infinity::interop::to_redacted_json;
use active_infinity::interop::{intents, secret_texts, SECRET_MARKER};
#[cfg(feature = "json")]
use active_infinity::ir::InterpPart;
use active_infinity::ir::{hash_hex, AnnotationKind, ProvEntry, ProvValue, Provenance};
use active_infinity::{
    encode, hash_image, to_protobuf, InfinityModule, Inode, SecretBytes, UnitTag,
};

// ---------------------------------------------------------------------------
// reader
// ---------------------------------------------------------------------------

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos == self.buf.len()
    }

    fn varint(&mut self) -> u64 {
        let mut value = 0u64;
        let mut width = 0usize;
        for shift in (0..64).step_by(7) {
            let byte = *self.buf.get(self.pos).expect("truncated varint");
            self.pos += 1;
            width += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                assert!(
                    width == 1 || byte != 0,
                    "non-minimal varint (trailing zero group)"
                );
                return value;
            }
        }
        panic!("varint longer than 64 bits");
    }

    fn key(&mut self) -> (u32, u8) {
        let key = self.varint();
        ((key >> 3) as u32, (key & 7) as u8)
    }

    fn bytes(&mut self) -> &'a [u8] {
        let len = self.varint() as usize;
        let end = self.pos.checked_add(len).expect("length overflow");
        assert!(end <= self.buf.len(), "length prefix runs past the buffer");
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        slice
    }

    fn string(&mut self) -> String {
        String::from_utf8(self.bytes().to_vec()).expect("utf-8 field")
    }

    fn double(&mut self) -> f64 {
        let bytes: [u8; 8] = self.bytes_fixed_8();
        f64::from_bits(u64::from_le_bytes(bytes))
    }

    fn bytes_fixed_8(&mut self) -> [u8; 8] {
        let end = self.pos + 8;
        assert!(end <= self.buf.len(), "fixed64 runs past the buffer");
        let mut out = [0u8; 8];
        out.copy_from_slice(&self.buf[self.pos..end]);
        self.pos = end;
        out
    }

    fn skip(&mut self, wire: u8) {
        match wire {
            0 => {
                self.varint();
            }
            1 => {
                self.bytes_fixed_8();
            }
            2 => {
                self.bytes();
            }
            5 => {
                let end = self.pos + 4;
                assert!(end <= self.buf.len(), "fixed32 runs past the buffer");
                self.pos = end;
            }
            other => panic!("unexpected wire type {other}"),
        }
    }
}

fn zigzag_decode(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

/// Encoders must emit fields in ascending field-number order (repeated fields
/// repeat the same number); a decoder that relies on it needs the guarantee
/// checked.
fn ascending(previous: &mut u32, field: u32) {
    assert!(
        field >= *previous,
        "fields must ascend: {field} after {previous}"
    );
    *previous = field;
}

// ---------------------------------------------------------------------------
// projected model
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum PValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    DurationMs(u64),
    Quantity(Box<PValue>, String),
    List(Vec<PValue>),
    Record(Vec<(String, PValue)>),
    Blob {
        hash: Vec<u8>,
        size: u64,
        media_type: String,
        tainted: bool,
    },
    Env(String),
    Expr(String),
}

#[derive(Debug, PartialEq)]
struct PBinding {
    name: String,
    value: PValue,
}

#[derive(Debug, PartialEq)]
struct PAnnotation {
    subject: u32,
    kind: String,
    text: String,
    flag: bool,
}

#[derive(Debug, PartialEq)]
struct PModule {
    content_hash: Vec<u8>,
    total_size: u64,
    root: Option<PValue>,
    bindings: Vec<PBinding>,
    producer: Option<String>,
    provenance_entries: Vec<(String, PValue)>,
    annotations: Vec<PAnnotation>,
    extensions: Vec<(u64, Vec<u8>)>,
}

fn decode_value(bytes: &[u8]) -> PValue {
    let mut cursor = Cursor::new(bytes);
    let (field, wire) = cursor.key();
    let value = match field {
        1 => {
            assert_eq!(wire, 2);
            assert!(cursor.bytes().is_empty(), "Null carries no body");
            PValue::Null
        }
        2 => {
            assert_eq!(wire, 0);
            PValue::Bool(cursor.varint() != 0)
        }
        3 => {
            assert_eq!(wire, 0);
            PValue::Int(zigzag_decode(cursor.varint()))
        }
        4 => {
            assert_eq!(wire, 1);
            PValue::Float(cursor.double())
        }
        5 => {
            assert_eq!(wire, 2);
            PValue::Text(cursor.string())
        }
        6 => {
            assert_eq!(wire, 2);
            let mut inner = Cursor::new(cursor.bytes());
            let (inner_field, inner_wire) = inner.key();
            assert_eq!((inner_field, inner_wire), (1, 0));
            let ms = inner.varint();
            assert!(inner.done());
            PValue::DurationMs(ms)
        }
        7 => {
            assert_eq!(wire, 2);
            let mut inner = Cursor::new(cursor.bytes());
            let (value_field, value_wire) = inner.key();
            assert_eq!((value_field, value_wire), (1, 2));
            let value = decode_value(inner.bytes());
            let (unit_field, unit_wire) = inner.key();
            assert_eq!((unit_field, unit_wire), (2, 2));
            let unit = inner.string();
            assert!(inner.done());
            PValue::Quantity(Box::new(value), unit)
        }
        8 => {
            assert_eq!(wire, 2);
            let mut inner = Cursor::new(cursor.bytes());
            let mut items = Vec::new();
            while !inner.done() {
                let (item_field, item_wire) = inner.key();
                assert_eq!((item_field, item_wire), (1, 2));
                items.push(decode_value(inner.bytes()));
            }
            PValue::List(items)
        }
        9 => {
            assert_eq!(wire, 2);
            let mut inner = Cursor::new(cursor.bytes());
            let mut fields = Vec::new();
            while !inner.done() {
                let (field_field, field_wire) = inner.key();
                assert_eq!((field_field, field_wire), (1, 2));
                let mut entry = Cursor::new(inner.bytes());
                let (name_field, name_wire) = entry.key();
                assert_eq!((name_field, name_wire), (1, 2));
                let name = entry.string();
                let (value_field, value_wire) = entry.key();
                assert_eq!((value_field, value_wire), (2, 2));
                let value = decode_value(entry.bytes());
                assert!(entry.done());
                fields.push((name, value));
            }
            PValue::Record(fields)
        }
        10 => {
            assert_eq!(wire, 2);
            let mut inner = Cursor::new(cursor.bytes());
            let (hash_field, hash_wire) = inner.key();
            assert_eq!((hash_field, hash_wire), (1, 2));
            let hash = inner.bytes().to_vec();
            let (size_field, size_wire) = inner.key();
            assert_eq!((size_field, size_wire), (2, 0));
            let size = inner.varint();
            let (media_field, media_wire) = inner.key();
            assert_eq!((media_field, media_wire), (3, 2));
            let media_type = inner.string();
            let (tainted_field, tainted_wire) = inner.key();
            assert_eq!((tainted_field, tainted_wire), (4, 0));
            let tainted = inner.varint() != 0;
            assert!(inner.done());
            PValue::Blob {
                hash,
                size,
                media_type,
                tainted,
            }
        }
        11 => {
            assert_eq!(wire, 2);
            let mut inner = Cursor::new(cursor.bytes());
            let (name_field, name_wire) = inner.key();
            assert_eq!((name_field, name_wire), (1, 2));
            let name = inner.string();
            assert!(inner.done());
            PValue::Env(name)
        }
        12 => {
            assert_eq!(wire, 2);
            let mut inner = Cursor::new(cursor.bytes());
            let (kind_field, kind_wire) = inner.key();
            assert_eq!((kind_field, kind_wire), (1, 2));
            let kind = inner.string();
            assert!(inner.done());
            PValue::Expr(kind)
        }
        other => panic!("unknown Value field {other}"),
    };
    assert!(cursor.done(), "trailing bytes inside a Value");
    value
}

fn decode_annotation(bytes: &[u8]) -> PAnnotation {
    let mut cursor = Cursor::new(bytes);
    let (subject_field, subject_wire) = cursor.key();
    assert_eq!((subject_field, subject_wire), (1, 0));
    let subject = cursor.varint() as u32;
    let mut annotation = PAnnotation {
        subject,
        kind: String::new(),
        text: String::new(),
        flag: false,
    };
    let mut previous = 1u32;
    while !cursor.done() {
        let (field, wire) = cursor.key();
        ascending(&mut previous, field);
        match field {
            2 => {
                assert_eq!(wire, 2);
                annotation.kind = "intent".into();
                annotation.text = cursor.string();
            }
            3 => {
                assert_eq!(wire, 2);
                annotation.kind = "constraint".into();
                let mut inner = Cursor::new(cursor.bytes());
                let (source_field, source_wire) = inner.key();
                assert_eq!((source_field, source_wire), (1, 2));
                annotation.text = inner.string();
                let (expr_field, expr_wire) = inner.key();
                assert_eq!((expr_field, expr_wire), (2, 0));
                let expr = inner.varint();
                assert!(inner.done());
                annotation.text = format!("{}#{}", annotation.text, expr);
            }
            4 => {
                assert_eq!(wire, 0);
                annotation.kind = "ai-immutable".into();
                annotation.flag = cursor.varint() != 0;
            }
            other => panic!("unknown Annotation field {other}"),
        }
    }
    annotation
}

fn decode_module(bytes: &[u8]) -> PModule {
    let mut cursor = Cursor::new(bytes);
    let mut module = PModule {
        content_hash: Vec::new(),
        total_size: 0,
        root: None,
        bindings: Vec::new(),
        producer: None,
        provenance_entries: Vec::new(),
        annotations: Vec::new(),
        extensions: Vec::new(),
    };
    let mut previous = 0u32;
    while !cursor.done() {
        let (field, wire) = cursor.key();
        ascending(&mut previous, field);
        match field {
            1 => {
                assert_eq!(wire, 2);
                module.content_hash = cursor.bytes().to_vec();
            }
            2 => {
                assert_eq!(wire, 0);
                module.total_size = cursor.varint();
            }
            3 => {
                assert_eq!(wire, 2);
                module.root = Some(decode_value(cursor.bytes()));
            }
            4 => {
                assert_eq!(wire, 2);
                let mut binding = Cursor::new(cursor.bytes());
                let (name_field, name_wire) = binding.key();
                assert_eq!((name_field, name_wire), (1, 2));
                let name = binding.string();
                let (value_field, value_wire) = binding.key();
                assert_eq!((value_field, value_wire), (2, 2));
                let value = decode_value(binding.bytes());
                assert!(binding.done());
                module.bindings.push(PBinding { name, value });
            }
            5 => {
                assert_eq!(wire, 2);
                let mut prov = Cursor::new(cursor.bytes());
                let mut prov_previous = 0u32;
                while !prov.done() {
                    let (prov_field, prov_wire) = prov.key();
                    ascending(&mut prov_previous, prov_field);
                    match prov_field {
                        1 => {
                            assert_eq!(prov_wire, 2);
                            module.producer = Some(prov.string());
                        }
                        2 => {
                            assert_eq!(prov_wire, 0);
                            prov.varint();
                        }
                        3 | 4 => {
                            assert_eq!(prov_wire, 2);
                            prov.string();
                        }
                        5 => {
                            assert_eq!(prov_wire, 2);
                            let parent = prov.bytes();
                            assert_eq!(parent.len(), 32);
                        }
                        6 => {
                            assert_eq!(prov_wire, 2);
                            let mut entry = Cursor::new(prov.bytes());
                            let (key_field, key_wire) = entry.key();
                            assert_eq!((key_field, key_wire), (1, 2));
                            let key = entry.string();
                            let (value_field, value_wire) = entry.key();
                            let value = match (value_field, value_wire) {
                                (2, 2) => PValue::Text(entry.string()),
                                (3, 0) => PValue::Int(zigzag_decode(entry.varint())),
                                (4, 0) => PValue::Bool(entry.varint() != 0),
                                (5, 2) => PValue::Text(hash_hex(
                                    entry.bytes().try_into().expect("32-byte provenance hash"),
                                )),
                                other => panic!("unknown provenance value {other:?}"),
                            };
                            assert!(entry.done());
                            module.provenance_entries.push((key, value));
                        }
                        other => panic!("unknown Provenance field {other}"),
                    }
                }
            }
            6 => {
                assert_eq!(wire, 2);
                module.annotations.push(decode_annotation(cursor.bytes()));
            }
            7 => {
                assert_eq!(wire, 2);
                let mut extension = Cursor::new(cursor.bytes());
                let (tag_field, tag_wire) = extension.key();
                assert_eq!((tag_field, tag_wire), (1, 0));
                let tag = extension.varint();
                let (payload_field, payload_wire) = extension.key();
                assert_eq!((payload_field, payload_wire), (2, 2));
                let payload = extension.bytes().to_vec();
                assert!(extension.done());
                module.extensions.push((tag, payload));
            }
            other => {
                assert!(other > 7, "a new Module field starts above the known range");
                cursor.skip(wire);
            }
        }
    }
    module
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

fn fixture() -> InfinityModule {
    let mut module = InfinityModule::new();
    let name = module.push(Inode::Str("projection".into()));
    let port = module.push(Inode::Int(8080));
    let rate = {
        let number = module.push(Inode::Float(2.5));
        module.push(Inode::Quantity {
            value: number,
            unit: UnitTag::RequestsPerSecond,
        })
    };
    let secret = module.push(Inode::Secret(SecretBytes::from("hunter2-secret")));
    let leaked = module.push(Inode::Str("prefix hunter2-secret suffix".into()));
    let env = module.push(Inode::Env {
        name: "ACTIVE_MODE".into(),
        default: None,
    });
    let payload = b"payload".to_vec();
    let blob = module.push(Inode::Blob {
        hash: *blake3::hash(&payload).as_bytes(),
        size: payload.len() as u64,
        tainted: true,
        media_type: "text/plain".into(),
        payload: None,
    });
    let elements = module.push(Inode::Array {
        elements: vec![port, rate],
    });
    let root = module.push(Inode::Table {
        fields: vec![
            ("name".into(), name),
            ("port".into(), port),
            ("rate".into(), rate),
            ("secret".into(), secret),
            ("leaked".into(), leaked),
            ("env".into(), env),
            ("blob".into(), blob),
            ("items".into(), elements),
        ],
    });
    module.set_root(Some(root));
    module.bind("root", root);
    module.bind("port", port);
    module.annotate(root, AnnotationKind::Intent("projection fixture".into()));
    module.annotate(root, AnnotationKind::AiImmutable(true));
    module.add_extension(9, b"extension".to_vec());
    module.set_provenance(Some(Provenance {
        producer: Some("test".into()),
        timestamp_ms: 1_700_000_000_000,
        model: None,
        tool: Some("cargo test".into()),
        parent: Some([7u8; 32]),
        entries: vec![
            ProvEntry {
                key: "kind".into(),
                value: ProvValue::Text("fixture".into()),
            },
            ProvEntry {
                key: "revision".into(),
                value: ProvValue::Int(3),
            },
        ],
    }));
    module
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[test]
fn projection_round_trips_through_an_independent_reader() {
    let module = fixture();
    let bytes = to_protobuf(&module).expect("project");
    let decoded = decode_module(&bytes);

    let image = encode(&module).expect("encode");
    assert_eq!(decoded.content_hash, hash_image(&image).expect("hash"));
    assert_eq!(decoded.total_size, image.len() as u64);

    let root = decoded.root.expect("root value");
    let PValue::Record(fields) = root else {
        panic!("the root is a table, got {root:?}");
    };
    let names: Vec<&str> = fields.iter().map(|(name, _)| name.as_str()).collect();
    // The projection is built from the canonical module, so table fields come
    // out sorted by key rather than in construction order.
    assert_eq!(
        names,
        ["blob", "env", "items", "leaked", "name", "port", "rate", "secret"]
    );

    let value = |field: &str| {
        fields
            .iter()
            .find(|(name, _)| name == field)
            .map(|(_, value)| value)
            .expect("field")
    };
    assert_eq!(*value("name"), PValue::Text("projection".into()));
    assert_eq!(*value("port"), PValue::Int(8080));
    let PValue::Quantity(inner, unit) = value("rate") else {
        panic!("rate must project as a quantity");
    };
    assert_eq!(**inner, PValue::Float(2.5));
    assert_eq!(unit, "requests-per-second");
    assert_eq!(*value("env"), PValue::Env("ACTIVE_MODE".into()));
    assert_eq!(*value("leaked"), PValue::Text(SECRET_MARKER.into()));
    match value("blob") {
        PValue::Blob {
            hash,
            size,
            media_type,
            tainted,
        } => {
            assert_eq!(hash.as_slice(), blake3::hash(b"payload").as_bytes());
            assert_eq!(*size, 7);
            assert_eq!(media_type, SECRET_MARKER, "a tainted blob hides its type");
            assert!(*tainted);
        }
        other => panic!("blob projected as {other:?}"),
    }
    let PValue::List(items) = value("items") else {
        panic!("items must project as a list");
    };
    assert_eq!(items.len(), 2);

    assert_eq!(decoded.bindings.len(), 2);
    let binding = |name: &str| {
        decoded
            .bindings
            .iter()
            .find(|binding| binding.name == name)
            .map(|binding| &binding.value)
            .expect("binding")
    };
    assert_eq!(*binding("port"), PValue::Int(8080));
    assert!(matches!(binding("root"), PValue::Record(_)));

    assert_eq!(decoded.annotations.len(), 2);
    assert!(decoded
        .annotations
        .iter()
        .any(|annotation| annotation.kind == "ai-immutable" && annotation.flag));
    assert!(decoded.annotations.iter().any(|annotation| {
        annotation.kind == "intent" && annotation.text == "projection fixture"
    }));

    assert_eq!(decoded.extensions, vec![(9u64, b"extension".to_vec())]);
    assert_eq!(decoded.producer.as_deref(), Some("test"));
    assert_eq!(
        decoded.provenance_entries,
        vec![
            ("kind".to_string(), PValue::Text("fixture".into())),
            ("revision".to_string(), PValue::Int(3)),
        ]
    );
}

#[test]
fn projection_is_deterministic() {
    let module = fixture();
    let first = to_protobuf(&module).expect("project");
    let second = to_protobuf(&module).expect("project");
    assert_eq!(first, second);
}

#[test]
fn projection_never_contains_secret_material() {
    let module = fixture();
    let bytes = to_protobuf(&module).expect("project");
    let needle = b"hunter2-secret";
    assert!(
        !bytes.windows(needle.len()).any(|window| window == needle),
        "the secret literal appears in the projection"
    );
    // The redaction rule itself still sees the secret — the point is that the
    // projection applied it.
    assert!(secret_texts(&module)
        .iter()
        .any(|text| text == "hunter2-secret"));
}

#[test]
fn projection_reports_an_empty_module_without_a_root() {
    let bytes = to_protobuf(&InfinityModule::new()).expect("project");
    let decoded = decode_module(&bytes);
    assert!(decoded.root.is_none());
    assert!(decoded.bindings.is_empty());
    assert!(decoded.extensions.is_empty());
    assert_eq!(
        decoded.total_size,
        encode(&InfinityModule::new()).unwrap().len() as u64
    );
}

#[test]
fn projection_of_a_cyclic_module_is_refused() {
    let mut module = InfinityModule::new();
    let a = module.push(Inode::Int(1));
    let b = module.push(Inode::Ref(a));
    *module.node_mut(a).unwrap() = Inode::Ref(b);
    module.set_root(Some(b));
    let error = to_protobuf(&module).expect_err("a cycle cannot be projected");
    assert_eq!(error.code(), "infinity/cycle");
}

#[test]
fn readers_skip_unknown_fields() {
    // Forward compatibility: append a field this version does not know about
    // and the reader must skip it instead of failing.
    let module = fixture();
    let mut bytes = to_protobuf(&module).expect("project");
    // field 99, wire type 2 (length-delimited), body "future".
    // The tag is `(99 << 3) | 2 == 794`, which needs a two-byte varint.
    bytes.extend_from_slice(&[0x9a, 0x06]);
    bytes.push(6);
    bytes.extend_from_slice(b"future");
    let decoded = decode_module(&bytes);
    assert!(decoded.root.is_some());
}

#[test]
fn projection_is_canonical_for_logically_equal_modules() {
    // Same content, different construction order: one AINF image, one
    // projection. This is what makes the bytes usable for caching and diffs.
    let mut first = InfinityModule::new();
    let z = first.push(Inode::Int(1));
    let a = first.push(Inode::Int(2));
    let root = first.push(Inode::Table {
        fields: vec![("z".into(), z), ("a".into(), a)],
    });
    first.set_root(Some(root));
    first.bind("beta", a);
    first.bind("alpha", z);
    first.add_extension(20, b"two".to_vec());
    first.add_extension(10, b"one".to_vec());
    first.annotate(root, AnnotationKind::AiImmutable(true));
    first.annotate(root, AnnotationKind::Intent("note".into()));

    let mut second = InfinityModule::new();
    let z = second.push(Inode::Int(1));
    let a = second.push(Inode::Int(2));
    let root = second.push(Inode::Table {
        fields: vec![("a".into(), a), ("z".into(), z)],
    });
    second.set_root(Some(root));
    second.bind("alpha", z);
    second.bind("beta", a);
    second.add_extension(10, b"one".to_vec());
    second.add_extension(20, b"two".to_vec());
    second.annotate(root, AnnotationKind::Intent("note".into()));
    second.annotate(root, AnnotationKind::AiImmutable(true));

    assert_eq!(
        encode(&first).unwrap(),
        encode(&second).unwrap(),
        "the AINF images must agree"
    );
    assert_eq!(
        to_protobuf(&first).unwrap(),
        to_protobuf(&second).unwrap(),
        "equal modules must project to equal bytes"
    );

    let decoded = decode_module(&to_protobuf(&first).unwrap());
    let names: Vec<&str> = decoded
        .bindings
        .iter()
        .map(|binding| binding.name.as_str())
        .collect();
    assert_eq!(names, ["alpha", "beta"]);
    let tags: Vec<u64> = decoded.extensions.iter().map(|(tag, _)| *tag).collect();
    assert_eq!(tags, [10, 20]);
}

#[test]
fn projection_handles_scalar_extremes() {
    let mut module = InfinityModule::new();
    let min = module.push(Inode::Int(i64::MIN));
    let max = module.push(Inode::Int(i64::MAX));
    let nan = module.push(Inode::Float(f64::NAN));
    let zero = module.push(Inode::Float(-0.0));
    let empty = module.push(Inode::Str(String::new()));
    let root = module.push(Inode::Array {
        elements: vec![min, max, nan, zero, empty],
    });
    module.set_root(Some(root));

    let decoded = decode_module(&to_protobuf(&module).expect("project"));
    let PValue::List(items) = decoded.root.expect("root") else {
        panic!("the root is an array");
    };
    assert_eq!(items[0], PValue::Int(i64::MIN));
    assert_eq!(items[1], PValue::Int(i64::MAX));
    match items[2] {
        PValue::Float(value) => assert!(value.is_nan(), "NaN survives the wire"),
        ref other => panic!("expected a float, got {other:?}"),
    }
    match items[3] {
        PValue::Float(value) => assert_eq!(
            value.to_bits(),
            0.0f64.to_bits(),
            "-0.0 is canonicalized to +0.0"
        ),
        ref other => panic!("expected a float, got {other:?}"),
    }
    assert_eq!(items[4], PValue::Text(String::new()));
}

#[test]
fn projection_refuses_an_extension_that_copies_a_secret() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from("hunter2-secret")));
    module.set_root(Some(secret));
    module.add_extension(7, b"note hunter2-secret note".to_vec());
    let error = to_protobuf(&module).expect_err("a secret copy must not leave");
    assert_eq!(error.code(), "infinity/encode");
    assert!(
        error.to_string().contains("extension payload"),
        "the message must name the reason, got {error}"
    );
}

#[test]
fn projection_renders_the_canonical_envelope() {
    // A module with an unreachable node: the canonical image drops it, and the
    // projection must describe what the image actually contains.
    let mut module = fixture();
    let stray = module.push(Inode::Int(999));
    module.annotate(stray, AnnotationKind::Intent("stray".into()));
    let bytes = to_protobuf(&module).expect("project");
    let decoded = decode_module(&bytes);
    let image = encode(&module).expect("encode");
    assert_eq!(decoded.content_hash, hash_image(&image).expect("hash"));

    // Bindings project as a name -> value map, not as nodes.
    let mut names: Vec<&str> = decoded
        .bindings
        .iter()
        .map(|binding| binding.name.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["port", "root"]);
}

#[test]
fn short_secrets_are_redacted_in_metadata_text() {
    // Redaction is unconditional, including for one- and two-byte secrets.
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Str("hello".into()));
    let secret = module.push(Inode::Secret(SecretBytes::from("xy")));
    let root = module.push(Inode::Table {
        fields: vec![("k".into(), value), ("s".into(), secret)],
    });
    module.set_root(Some(root));
    module.annotate(root, AnnotationKind::Intent("carries xy inside".into()));
    let text = intents(&module, root);
    assert!(
        text.iter().all(|line| !line.contains("xy")),
        "a two-byte secret must not survive in intent text: {text:?}"
    );
    assert!(text.iter().any(|line| line.contains(SECRET_MARKER)));
}

#[cfg(feature = "json")]
#[test]
fn taint_follows_references_in_interpolations() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from("hunter2-secret")));
    let reference = module.push(Inode::Ref(secret));
    let text = module.push(Inode::Interpolate {
        parts: vec![
            InterpPart::Literal("prefix ".into()),
            InterpPart::Expr(reference),
        ],
    });
    let root = module.push(Inode::Table {
        fields: vec![("t".into(), text)],
    });
    module.set_root(Some(root));

    let json = to_redacted_json(&module).expect("project");
    assert!(
        json.contains(SECRET_MARKER),
        "a reference to a secret taints the interpolation: {json}"
    );
    assert!(!json.contains("prefix"), "no literal prefix survives");
}
