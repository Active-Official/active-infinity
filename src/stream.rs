//! Streaming / Infinity mode: ordered frames that reassemble into exactly the
//! canonical image.
//!
//! A stream is a sequence of self-delimiting frames:
//!
//! ```text
//! Begin  { format version, flags, dialect }
//! Batch  { section id, bytes }        (one or more per section, in order)
//! End    { content hash, total size }
//! ```
//!
//! followed, for incremental updates, by any number of
//!
//! ```text
//! Delta  { operations }               (applied to the reassembled module)
//! End    { new content hash }
//! ```
//!
//! Reassembly is byte-exact: a stream produced from a module yields the same
//! bytes and the same Blake3 content hash as [`crate::encode::encode`] of that module,
//! because each batch carries a slice of the canonical section image. Deltas are
//! semantic (root, node content, bindings, annotations, provenance) and are
//! re-canonicalized after application, so an incremental update also lands on
//! the identical whole-module encoding.
//!
//! Every frame carries its own length and a truncated Blake3 checksum, so
//! corruption is detected at the frame boundary instead of surfacing as a
//! confusing parse error later.

// Module-level: item docs for this layer live in docs/spec/layout.md and
// docs/spec/streaming.md; the crate root keeps deny(missing_docs) for the
// hand-written public surface.
#![allow(missing_docs)]

use std::collections::VecDeque;
use std::fmt;

use crate::canonical::remap_node;
use crate::encode::{encode_with, hash_image};
use crate::error::{Error, Result};
use crate::ir::{Annotation, AnnotationKind, InfinityModule, NodeId, Provenance};
use crate::layout::{
    align8, read_u32, read_u64, EncodeOpts, Section, HEADER_SIZE, SECTION_COUNT, STREAM_MAGIC,
};
use crate::validate::Validated;

/// Stream frame magic is `AINS`; version 1.
pub const STREAM_VERSION: u8 = 1;
/// Fixed frame header size.
pub const FRAME_HEADER_SIZE: usize = 32;
/// Default batch chunk size (bytes of section payload per frame).
pub const DEFAULT_CHUNK: usize = 64 << 10;
/// Largest frame payload this reader accepts.
pub const MAX_FRAME_PAYLOAD: u32 = 64 << 20;

/// Frame kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// Opens a stream and declares format metadata.
    Begin,
    /// Carries bytes of one section.
    Batch,
    /// Carries semantic delta operations.
    Delta,
    /// Closes a generation with the expected content hash.
    End,
}

impl FrameKind {
    pub const fn code(self) -> u8 {
        match self {
            FrameKind::Begin => 1,
            FrameKind::Batch => 2,
            FrameKind::Delta => 3,
            FrameKind::End => 4,
        }
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(FrameKind::Begin),
            2 => Some(FrameKind::Batch),
            3 => Some(FrameKind::Delta),
            4 => Some(FrameKind::End),
            _ => None,
        }
    }
}

/// One stream frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(kind: FrameKind, sequence: u64, payload: Vec<u8>) -> Self {
        Frame {
            kind,
            sequence,
            payload,
        }
    }

    /// Serialize the frame with its header and checksum.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_HEADER_SIZE + self.payload.len());
        out.extend_from_slice(&STREAM_MAGIC);
        out.push(STREAM_VERSION);
        out.push(self.kind.code());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        let checksum = frame_checksum(&self.payload);
        out.extend_from_slice(&checksum[..8]);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse one frame, returning it and the number of bytes consumed.
    pub fn parse(buf: &[u8]) -> Result<(Frame, usize)> {
        if buf.len() < 4 || buf[0..4] != STREAM_MAGIC {
            return Err(Error::StreamMagic);
        }
        if buf.len() < FRAME_HEADER_SIZE {
            return Err(Error::Truncated {
                needed: FRAME_HEADER_SIZE as u64,
                found: buf.len() as u64,
            });
        }
        let version = buf[4];
        if version != STREAM_VERSION {
            return Err(Error::StreamVersion(version));
        }
        let kind = FrameKind::from_code(buf[5]).ok_or(Error::StreamFrameKind(buf[5]))?;
        let flags = u16::from_le_bytes([buf[6], buf[7]]);
        if flags != 0 {
            return Err(Error::UnknownFlags(flags));
        }
        let sequence = u64::from_le_bytes(buf[8..16].try_into().expect("8 bytes"));
        let len = u32::from_le_bytes(buf[16..20].try_into().expect("4 bytes"));
        if len > MAX_FRAME_PAYLOAD {
            return Err(Error::StreamFrameLen {
                declared: len,
                available: buf.len() as u64,
            });
        }
        let reserved = u32::from_le_bytes(buf[20..24].try_into().expect("4 bytes"));
        if reserved != 0 {
            return Err(Error::ReservedNonZero {
                section: "stream-frame",
                offset: 20,
            });
        }
        let payload_start = FRAME_HEADER_SIZE;
        let payload_end = payload_start + len as usize;
        if payload_end > buf.len() {
            return Err(Error::StreamFrameLen {
                declared: len,
                available: (buf.len() - payload_start) as u64,
            });
        }
        let payload = &buf[payload_start..payload_end];
        let expected = frame_checksum(payload);
        if buf[24..32] != expected[..8] {
            return Err(Error::HashMismatch);
        }
        Ok((
            Frame {
                kind,
                sequence,
                payload: payload.to_vec(),
            },
            payload_end,
        ))
    }
}

/// Truncated Blake3 checksum of a frame payload.
pub fn frame_checksum(payload: &[u8]) -> [u8; 32] {
    *blake3::hash(payload).as_bytes()
}

/// Encode a module into stream frames.
///
/// The frames carry the exact bytes of the module's canonical image, so
/// reassembly reproduces `encode(module)` byte for byte and therefore the same
/// content hash as the whole-module encoding.
pub fn encode_stream(module: &InfinityModule, chunk: usize) -> Result<Vec<Frame>> {
    encode_stream_with(module, chunk, EncodeOpts::default())
}

/// Encode a module into stream frames with explicit encoder options.
pub fn encode_stream_with(
    module: &InfinityModule,
    chunk: usize,
    opts: EncodeOpts,
) -> Result<Vec<Frame>> {
    if chunk == 0 {
        return Err(Error::InvalidArgument("chunk size must be non-zero"));
    }
    let image = encode_with(module, opts)?;
    let header = crate::layout::Header::parse(&image)?;
    let mut frames = Vec::new();
    let mut sequence = 0u64;
    let mut begin = Vec::with_capacity(24);
    begin.extend_from_slice(&header.major.to_le_bytes());
    begin.extend_from_slice(&header.minor.to_le_bytes());
    begin.extend_from_slice(&header.flags.to_le_bytes());
    begin.extend_from_slice(&0u16.to_le_bytes());
    begin.extend_from_slice(&header.dialect_hash.to_le_bytes());
    begin.extend_from_slice(&header.total_size.to_le_bytes());
    frames.push(Frame::new(FrameKind::Begin, sequence, begin));
    sequence += 1;

    // Split the image into section bodies in canonical order. The header is
    // regenerated on reassembly, so only section content travels.
    for section in Section::ALL {
        let span = header.span(section);
        let start = span.offset as usize;
        let len = section_body_len(&image, &header, section)?;
        let body = &image[start..start + len];
        if body.is_empty() {
            let mut payload = Vec::with_capacity(9);
            payload.push(section as u8);
            payload.extend_from_slice(&span.count.to_le_bytes());
            payload.extend_from_slice(&0u32.to_le_bytes());
            frames.push(Frame::new(FrameKind::Batch, sequence, payload));
            sequence += 1;
            continue;
        }
        for piece in body.chunks(chunk) {
            let mut payload = Vec::with_capacity(9 + piece.len());
            payload.push(section as u8);
            payload.extend_from_slice(&span.count.to_le_bytes());
            payload.extend_from_slice(&(piece.len() as u32).to_le_bytes());
            payload.extend_from_slice(piece);
            frames.push(Frame::new(FrameKind::Batch, sequence, payload));
            sequence += 1;
        }
    }

    let mut end = Vec::with_capacity(40);
    let hash = hash_image(&image)?;
    end.extend_from_slice(&hash);
    end.extend_from_slice(&(image.len() as u64).to_le_bytes());
    frames.push(Frame::new(FrameKind::End, sequence, end));
    Ok(frames)
}

fn section_body_len(
    image: &[u8],
    header: &crate::layout::Header,
    section: Section,
) -> crate::Result<usize> {
    let span = header.span(section);
    let start = span.offset as u64;
    let count = span.count as u64;
    let read_at = |offset: u64| -> crate::Result<usize> {
        usize::try_from(offset).map_err(|_| Error::TooLarge)
    };
    let end = match section {
        Section::Strings => {
            if count == 0 {
                start
            } else {
                let index = start
                    .checked_add(count.checked_mul(4).ok_or(Error::TooLarge)?)
                    .ok_or(Error::TooLarge)?;
                let heap = read_u32(image, read_at(index)?).unwrap_or(0) as u64;
                start
                    .checked_add(
                        count
                            .checked_add(1)
                            .ok_or(Error::TooLarge)?
                            .checked_mul(4)
                            .ok_or(Error::TooLarge)?,
                    )
                    .and_then(|value| value.checked_add(heap))
                    .ok_or(Error::TooLarge)?
            }
        }
        Section::Blobs => {
            let mut heap = 0u64;
            for index in 0..count {
                let offset = start
                    .checked_add(index.checked_mul(40).ok_or(Error::TooLarge)?)
                    .and_then(|value| value.checked_add(36))
                    .ok_or(Error::TooLarge)?;
                heap = heap
                    .checked_add(u64::from(read_u32(image, read_at(offset)?).unwrap_or(0)))
                    .ok_or(Error::TooLarge)?;
            }
            start
                .checked_add(count.checked_mul(40).ok_or(Error::TooLarge)?)
                .and_then(|value| value.checked_add(heap))
                .ok_or(Error::TooLarge)?
        }
        Section::Provenance => start.checked_add(count).ok_or(Error::TooLarge)?,
        Section::Secrets => {
            let mut heap = 0u64;
            for index in 0..count {
                let offset = start
                    .checked_add(index.checked_mul(8).ok_or(Error::TooLarge)?)
                    .and_then(|value| value.checked_add(4))
                    .ok_or(Error::TooLarge)?;
                heap = heap
                    .checked_add(u64::from(read_u32(image, read_at(offset)?).unwrap_or(0)))
                    .ok_or(Error::TooLarge)?;
            }
            start
                .checked_add(count.checked_mul(8).ok_or(Error::TooLarge)?)
                .and_then(|value| value.checked_add(heap))
                .ok_or(Error::TooLarge)?
        }
        Section::Extensions => {
            let directory = count.checked_mul(16).ok_or(Error::TooLarge)?;
            let mut end = start.checked_add(directory).ok_or(Error::TooLarge)?;
            for index in 0..count {
                let dir = start
                    .checked_add(index.checked_mul(16).ok_or(Error::TooLarge)?)
                    .ok_or(Error::TooLarge)?;
                let offset = u64::from(
                    read_u32(image, read_at(dir.checked_add(8).ok_or(Error::TooLarge)?)?)
                        .unwrap_or(0),
                );
                let len = u64::from(
                    read_u32(image, read_at(dir.checked_add(12).ok_or(Error::TooLarge)?)?)
                        .unwrap_or(0),
                );
                end = end.max(offset.checked_add(len).ok_or(Error::TooLarge)?);
            }
            end
        }
        Section::Nodes => start
            .checked_add(count.checked_mul(32).ok_or(Error::TooLarge)?)
            .ok_or(Error::TooLarge)?,
        Section::Children => start
            .checked_add(count.checked_mul(4).ok_or(Error::TooLarge)?)
            .ok_or(Error::TooLarge)?,
        Section::Fields => start
            .checked_add(count.checked_mul(16).ok_or(Error::TooLarge)?)
            .ok_or(Error::TooLarge)?,
        Section::Parts => start
            .checked_add(count.checked_mul(8).ok_or(Error::TooLarge)?)
            .ok_or(Error::TooLarge)?,
        Section::Edges => start
            .checked_add(count.checked_mul(8).ok_or(Error::TooLarge)?)
            .ok_or(Error::TooLarge)?,
        Section::Annotations => start
            .checked_add(count.checked_mul(16).ok_or(Error::TooLarge)?)
            .ok_or(Error::TooLarge)?,
        Section::Units => start
            .checked_add(count.checked_mul(8).ok_or(Error::TooLarge)?)
            .ok_or(Error::TooLarge)?,
        Section::Types => start
            .checked_add(count.checked_mul(16).ok_or(Error::TooLarge)?)
            .ok_or(Error::TooLarge)?,
        Section::Aux => start
            .checked_add(count.checked_mul(8).ok_or(Error::TooLarge)?)
            .ok_or(Error::TooLarge)?,
        Section::Numbers => start
            .checked_add(count.checked_mul(8).ok_or(Error::TooLarge)?)
            .ok_or(Error::TooLarge)?,
        Section::Hashes => start
            .checked_add(count.checked_mul(32).ok_or(Error::TooLarge)?)
            .ok_or(Error::TooLarge)?,
        Section::Bindings => start
            .checked_add(count.checked_mul(8).ok_or(Error::TooLarge)?)
            .ok_or(Error::TooLarge)?,
    };
    usize::try_from(end.saturating_sub(start)).map_err(|_| Error::TooLarge)
}

/// A semantic delta operation.
#[derive(Clone, PartialEq)]
pub enum DeltaOp {
    /// Replace the module root.
    SetRoot(Option<NodeId>),
    /// Replace the content of `target` with a fragment module's node 0.
    PutNode {
        target: NodeId,
        fragment: Box<InfinityModule>,
    },
    /// Bind (or rebind) a name.
    SetBinding { name: String, node: NodeId },
    /// Remove a binding by name (no-op when absent).
    RemoveBinding { name: String },
    /// Append an annotation.
    SetAnnotation { node: NodeId, kind: AnnotationKind },
    /// Drop every annotation.
    ClearAnnotations,
    /// Replace provenance.
    SetProvenance(Option<Provenance>),
}

impl fmt::Debug for DeltaOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeltaOp::SetRoot(root) => write!(f, "SetRoot({root:?})"),
            DeltaOp::PutNode { target, fragment } => write!(
                f,
                "PutNode {{ target: {target}, fragment: <{} nodes> }}",
                fragment.node_count()
            ),
            DeltaOp::SetBinding { node, .. } => {
                write!(f, "SetBinding {{ name: <redacted>, node: {node} }}")
            }
            DeltaOp::RemoveBinding { .. } => f.write_str("RemoveBinding { name: <redacted> }"),
            DeltaOp::SetAnnotation { node, kind } => {
                write!(f, "SetAnnotation {{ node: {node}, kind: {kind:?} }}")
            }
            DeltaOp::ClearAnnotations => f.write_str("ClearAnnotations"),
            DeltaOp::SetProvenance(provenance) => write!(f, "SetProvenance({provenance:?})"),
        }
    }
}

impl DeltaOp {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            DeltaOp::SetRoot(root) => {
                out.push(0);
                out.extend_from_slice(&root.map(|id| id.0).unwrap_or(u32::MAX).to_le_bytes());
            }
            DeltaOp::PutNode { target, fragment } => {
                out.push(1);
                out.extend_from_slice(&target.0.to_le_bytes());
                let image = encode_with(fragment, EncodeOpts::default())?;
                out.extend_from_slice(&(image.len() as u32).to_le_bytes());
                out.extend_from_slice(&image);
            }
            DeltaOp::SetBinding { name, node } => {
                out.push(3);
                let bytes = name.as_bytes();
                out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(bytes);
                out.extend_from_slice(&node.0.to_le_bytes());
            }
            DeltaOp::RemoveBinding { name } => {
                out.push(4);
                let bytes = name.as_bytes();
                out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(bytes);
            }
            DeltaOp::SetAnnotation { node, kind } => {
                out.push(5);
                out.extend_from_slice(&node.0.to_le_bytes());
                match kind {
                    AnnotationKind::Intent(text) => {
                        out.push(0);
                        write_string(out, text)?;
                    }
                    AnnotationKind::Constraint { source, expr } => {
                        out.push(1);
                        write_string(out, source)?;
                        out.extend_from_slice(&expr.0.to_le_bytes());
                    }
                    AnnotationKind::AiImmutable(flag) => {
                        out.push(2);
                        out.push(u8::from(*flag));
                    }
                }
            }
            DeltaOp::ClearAnnotations => out.push(6),
            DeltaOp::SetProvenance(prov) => {
                out.push(7);
                match prov {
                    None => out.push(0),
                    Some(prov) => {
                        out.push(1);
                        write_opt_string(out, prov.producer.as_deref())?;
                        write_opt_string(out, prov.model.as_deref())?;
                        write_opt_string(out, prov.tool.as_deref())?;
                        out.extend_from_slice(&prov.timestamp_ms.to_le_bytes());
                        match prov.parent {
                            None => out.push(0),
                            Some(hash) => {
                                out.push(1);
                                out.extend_from_slice(&hash);
                            }
                        }
                        out.extend_from_slice(&(prov.entries.len() as u32).to_le_bytes());
                        for entry in &prov.entries {
                            write_string(out, &entry.key)?;
                            match &entry.value {
                                crate::ir::ProvValue::Text(text) => {
                                    out.push(0);
                                    write_string(out, text)?;
                                }
                                crate::ir::ProvValue::Int(value) => {
                                    out.push(1);
                                    out.extend_from_slice(&value.to_le_bytes());
                                }
                                crate::ir::ProvValue::Flag(flag) => {
                                    out.push(2);
                                    out.push(u8::from(*flag));
                                }
                                crate::ir::ProvValue::Hash(hash) => {
                                    out.push(3);
                                    out.extend_from_slice(hash);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn decode(buf: &[u8], cursor: &mut usize, limits: crate::layout::Limits) -> Result<DeltaOp> {
        let tag = take_u8(buf, cursor)?;
        let op = match tag {
            0 => {
                let id = take_u32(buf, cursor)?;
                DeltaOp::SetRoot(if id == u32::MAX {
                    None
                } else {
                    Some(NodeId(id))
                })
            }
            1 => {
                let target = NodeId(take_u32(buf, cursor)?);
                let fragment = Box::new(decode_fragment(buf, cursor, limits)?);
                DeltaOp::PutNode { target, fragment }
            }
            3 => {
                let name = take_string(buf, cursor)?;
                let node = NodeId(take_u32(buf, cursor)?);
                DeltaOp::SetBinding { name, node }
            }
            4 => {
                let name = take_string(buf, cursor)?;
                DeltaOp::RemoveBinding { name }
            }
            5 => {
                let node = NodeId(take_u32(buf, cursor)?);
                let kind_tag = take_u8(buf, cursor)?;
                let kind = match kind_tag {
                    0 => AnnotationKind::Intent(take_string(buf, cursor)?),
                    1 => {
                        let source = take_string(buf, cursor)?;
                        let expr = NodeId(take_u32(buf, cursor)?);
                        AnnotationKind::Constraint { source, expr }
                    }
                    2 => AnnotationKind::AiImmutable(take_u8(buf, cursor)? != 0),
                    _ => return Err(Error::StreamDelta("unknown annotation kind")),
                };
                DeltaOp::SetAnnotation { node, kind }
            }
            6 => DeltaOp::ClearAnnotations,
            7 => {
                if take_u8(buf, cursor)? == 0 {
                    DeltaOp::SetProvenance(None)
                } else {
                    let producer = take_opt_string(buf, cursor)?;
                    let model = take_opt_string(buf, cursor)?;
                    let tool = take_opt_string(buf, cursor)?;
                    let timestamp_ms = take_u64(buf, cursor)?;
                    let parent = if take_u8(buf, cursor)? == 0 {
                        None
                    } else {
                        Some(take_hash(buf, cursor)?)
                    };
                    let count = take_u32(buf, cursor)?;
                    let mut entries = Vec::with_capacity(count.min(4096) as usize);
                    for _ in 0..count {
                        let key = take_string(buf, cursor)?;
                        let value = match take_u8(buf, cursor)? {
                            0 => crate::ir::ProvValue::Text(take_string(buf, cursor)?),
                            1 => crate::ir::ProvValue::Int(take_i64(buf, cursor)?),
                            2 => crate::ir::ProvValue::Flag(take_u8(buf, cursor)? != 0),
                            3 => crate::ir::ProvValue::Hash(take_hash(buf, cursor)?),
                            _ => return Err(Error::StreamDelta("unknown provenance value kind")),
                        };
                        entries.push(crate::ir::ProvEntry { key, value });
                    }
                    DeltaOp::SetProvenance(Some(Provenance {
                        producer,
                        timestamp_ms,
                        model,
                        tool,
                        parent,
                        entries,
                    }))
                }
            }
            _ => return Err(Error::StreamDelta("unknown delta operation")),
        };
        Ok(op)
    }
}

/// Apply delta operations to a module, returning the updated module.
pub fn apply_delta(module: &InfinityModule, ops: &[DeltaOp]) -> Result<InfinityModule> {
    let mut out = module.clone();
    apply_delta_in_place(&mut out, ops)?;
    Ok(out)
}

/// Apply delta operations in place.
///
/// This is the incremental path for a caller that already owns the module: it
/// avoids cloning the whole graph and only merges the fragment nodes actually
/// referenced by `PutNode`. Canonical encoding still runs once at the end,
/// because the canonical image is the identity boundary.
pub fn apply_delta_in_place(module: &mut InfinityModule, ops: &[DeltaOp]) -> Result<()> {
    for op in ops {
        match op {
            DeltaOp::SetRoot(root) => {
                if let Some(root) = root {
                    if module.get(*root).is_none() {
                        return Err(Error::StreamDelta("root node does not exist"));
                    }
                }
                module.set_root(*root);
            }
            DeltaOp::PutNode { target, fragment } => {
                if module.get(*target).is_none() {
                    return Err(Error::StreamDelta("target node does not exist"));
                }
                if fragment.node_count() == 0 {
                    return Err(Error::StreamDelta("fragment is empty"));
                }
                let replacement = merge_fragment(module, fragment)?;
                let content = module
                    .get(replacement)
                    .cloned()
                    .ok_or(Error::StreamDelta("fragment root missing"))?;
                *module.node_mut(*target)? = content;
            }
            DeltaOp::SetBinding { name, node } => {
                if module.get(*node).is_none() {
                    return Err(Error::StreamDelta("binding target does not exist"));
                }
                module.bind(name.clone(), *node);
            }
            DeltaOp::RemoveBinding { name } => {
                module.remove_binding(name);
            }
            DeltaOp::SetAnnotation { node, kind } => {
                if module.get(*node).is_none() {
                    return Err(Error::StreamDelta("annotation subject does not exist"));
                }
                module.annotate(*node, kind.clone());
            }
            DeltaOp::ClearAnnotations => module.clear_annotations(),
            DeltaOp::SetProvenance(prov) => module.set_provenance(prov.clone()),
        }
    }
    Ok(())
}

fn merge_fragment(base: &mut InfinityModule, fragment: &InfinityModule) -> Result<NodeId> {
    let base_count = base.node_count();
    let map: Vec<NodeId> = (0..fragment.node_count())
        .map(|index| NodeId(base_count as u32 + index as u32))
        .collect();
    for node in fragment.nodes() {
        base.push(remap_node(node, &map)?);
    }
    Ok(map[fragment.root().unwrap_or(NodeId(0)).index()])
}

/// A reassembled stream generation.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamedModule {
    pub module: InfinityModule,
    pub image: Vec<u8>,
    pub content_hash: [u8; 32],
}

/// Streaming decoder state.
#[derive(Debug, Default)]
pub struct StreamDecoder {
    limits: crate::layout::Limits,
    sections: [Vec<u8>; SECTION_COUNT],
    counts: [u32; SECTION_COUNT],
    seen: [bool; SECTION_COUNT],
    begun: bool,
    ended: bool,
    expected: u64,
    flags: u16,
    total_size: Option<u64>,
    module: Option<InfinityModule>,
    image: Option<Vec<u8>>,
    pending_deltas: Vec<DeltaOp>,
    frames: u64,
    partial: Vec<u8>,
    cursor: usize,
}

impl StreamDecoder {
    pub fn new() -> Self {
        Self {
            limits: crate::layout::Limits::default(),
            sections: Default::default(),
            counts: [0; SECTION_COUNT],
            seen: [false; SECTION_COUNT],
            begun: false,
            ended: false,
            expected: 0,
            flags: 0,
            total_size: None,
            module: None,
            image: None,
            pending_deltas: Vec::new(),
            frames: 0,
            partial: Vec::new(),
            cursor: 0,
        }
    }

    /// Use explicit decode limits for the reassembled image and for every
    /// intermediate bound.
    pub fn with_limits(mut self, limits: crate::layout::Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Feed raw frame bytes. Frames may be split across calls and several may
    /// arrive in one call; partial frames are buffered.
    pub fn push_bytes(&mut self, buf: &[u8]) -> Result<()> {
        self.partial.extend_from_slice(buf);
        loop {
            if self.partial.len() < FRAME_HEADER_SIZE {
                return Ok(());
            }
            match Frame::parse(&self.partial) {
                Ok((frame, consumed)) => {
                    self.push(&frame)?;
                    self.partial.drain(..consumed);
                }
                // A short buffer is not an error: wait for the rest of the
                // frame. A declared length above the frame ceiling is a real
                // error and `Frame::parse` reports it before this match.
                Err(Error::Truncated { .. }) => return Ok(()),
                Err(Error::StreamFrameLen { declared, .. }) if declared <= MAX_FRAME_PAYLOAD => {
                    return Ok(())
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Feed one parsed frame.
    pub fn push(&mut self, frame: &Frame) -> Result<()> {
        if frame.sequence != self.expected {
            return Err(Error::StreamSequence {
                expected: self.expected,
                found: frame.sequence,
            });
        }
        self.expected += 1;
        self.frames += 1;
        match frame.kind {
            FrameKind::Begin => {
                if self.begun {
                    return Err(Error::StreamState("duplicate begin frame"));
                }
                if self.ended {
                    return Err(Error::StreamState("begin after end"));
                }
                if frame.payload.len() != 24 {
                    return Err(Error::StreamFrameLen {
                        declared: 24,
                        available: frame.payload.len() as u64,
                    });
                }
                let major = u16::from_le_bytes([frame.payload[0], frame.payload[1]]);
                let minor = u16::from_le_bytes([frame.payload[2], frame.payload[3]]);
                if major != crate::layout::FORMAT_MAJOR || minor > crate::layout::FORMAT_MINOR {
                    return Err(Error::VersionMajor(major));
                }
                let flags = u16::from_le_bytes([frame.payload[4], frame.payload[5]]);
                if flags & !crate::layout::FLAG_KNOWN_MASK != 0 {
                    return Err(Error::UnknownFlags(flags & !crate::layout::FLAG_KNOWN_MASK));
                }
                if frame.payload[6..8] != [0, 0] {
                    return Err(Error::ReservedNonZero {
                        section: "stream-begin",
                        offset: 6,
                    });
                }
                let dialect = read_u64(&frame.payload, 8)?;
                if dialect != crate::layout::dialect_hash() {
                    return Err(Error::DialectMismatch(dialect));
                }
                let size = read_u64(&frame.payload, 16)?;
                // Bound the declared size with the *caller's* ceiling: a strict
                // decoder must not accept a generation sized for the defaults.
                if size > self.limits.max_total_bytes {
                    return Err(Error::Limit {
                        kind: "total bytes",
                        limit: self.limits.max_total_bytes,
                    });
                }
                self.total_size = Some(size);
                self.flags = flags;
                self.begun = true;
            }
            FrameKind::Batch => {
                if !self.begun || self.ended {
                    return Err(Error::StreamState("batch outside a generation"));
                }
                if frame.payload.len() < 9 {
                    return Err(Error::StreamFrameLen {
                        declared: 9,
                        available: frame.payload.len() as u64,
                    });
                }
                let section = frame.payload[0] as usize;
                if section >= SECTION_COUNT {
                    return Err(Error::StreamState("unknown section id"));
                }
                let count = read_u32(&frame.payload, 1)?;
                let len = read_u32(&frame.payload, 5)? as usize;
                if frame.payload.len() != 9 + len {
                    return Err(Error::StreamFrameLen {
                        declared: len as u32,
                        available: (frame.payload.len() - 9) as u64,
                    });
                }
                if section != self.cursor && section != self.cursor + 1 {
                    return Err(Error::StreamState("sections out of order"));
                }
                if section == self.cursor + 1 {
                    self.cursor = section;
                }
                if self.seen[section] && self.counts[section] != count {
                    return Err(Error::StreamState("section count changed mid-stream"));
                }
                self.seen[section] = true;
                self.counts[section] = count;
                self.sections[section].extend_from_slice(&frame.payload[9..]);
                // A generation cannot occupy more than it declared. Without
                // this bound, an endless run of batches for one section would
                // allocate until the process dies before `End` is seen.
                let accumulated: usize = self.sections.iter().map(|section| section.len()).sum();
                let declared = self
                    .total_size
                    .map(|size| size.min(usize::MAX as u64) as usize)
                    .unwrap_or(usize::MAX);
                if accumulated > declared {
                    return Err(Error::Limit {
                        kind: "stream bytes",
                        limit: declared as u64,
                    });
                }
                if accumulated as u64 > self.limits.max_total_bytes {
                    return Err(Error::Limit {
                        kind: "stream bytes",
                        limit: self.limits.max_total_bytes,
                    });
                }
            }
            FrameKind::Delta => {
                if !self.ended {
                    return Err(Error::StreamState("delta before end"));
                }
                let mut cursor = 0usize;
                let count = take_u32(&frame.payload, &mut cursor)?;
                // Only the caller's limits decide. A default-limits pre-check
                // here would refuse a delta that a caller explicitly widened.
                if self.pending_deltas.len().saturating_add(count as usize)
                    > self.limits.max_aux as usize
                {
                    return Err(Error::Limit {
                        kind: "delta operations",
                        limit: self.limits.max_aux as u64,
                    });
                }
                for _ in 0..count {
                    self.pending_deltas.push(DeltaOp::decode(
                        &frame.payload,
                        &mut cursor,
                        self.limits,
                    )?);
                }
                if cursor != frame.payload.len() {
                    return Err(Error::StreamDelta("trailing bytes in delta payload"));
                }
            }
            FrameKind::End => {
                if !self.begun {
                    return Err(Error::StreamState("end before begin"));
                }
                if frame.payload.len() != 40 {
                    return Err(Error::StreamFrameLen {
                        declared: 40,
                        available: frame.payload.len() as u64,
                    });
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&frame.payload[..32]);
                let size = read_u64(&frame.payload, 32)?;
                if self.ended {
                    // Incremental generation: apply pending deltas first.
                    let base = self
                        .module
                        .as_ref()
                        .ok_or(Error::StreamState("no module to patch"))?;
                    let updated = apply_delta(base, &self.pending_deltas)?;
                    self.pending_deltas.clear();
                    let image = encode_with(&updated, EncodeOpts::default())?;
                    if image.len() as u64 != size {
                        return Err(Error::StreamDelta("delta changed the declared size"));
                    }
                    if hash_image(&image)? != hash {
                        return Err(Error::StreamHashMismatch);
                    }
                    let validated = Validated::new(
                        &image,
                        crate::layout::DecodeOpts {
                            limits: self.limits,
                            verify_hash: true,
                            verify_canonical: false,
                        },
                    )?;
                    let module = crate::decode::decode_validated(&validated)?;
                    self.module = Some(module);
                    self.image = Some(image);
                    return Ok(());
                }
                let image = self.assemble(size)?;
                if hash_image(&image)? != hash {
                    return Err(Error::StreamHashMismatch);
                }
                let validated = Validated::new(
                    &image,
                    crate::layout::DecodeOpts {
                        limits: self.limits,
                        verify_hash: true,
                        verify_canonical: false,
                    },
                )?;
                let module = crate::decode::decode_validated(&validated)?;
                self.module = Some(module);
                self.image = Some(image);
                self.ended = true;
            }
        }
        Ok(())
    }

    fn assemble(&self, size: u64) -> Result<Vec<u8>> {
        if size < HEADER_SIZE as u64 {
            return Err(Error::StreamDelta("declared size smaller than a header"));
        }
        if self.seen.iter().any(|seen| !seen) {
            return Err(Error::StreamState("generation missing a section"));
        }
        let mut image = vec![0u8; HEADER_SIZE];
        let mut header = crate::layout::Header {
            major: crate::layout::FORMAT_MAJOR,
            minor: crate::layout::FORMAT_MINOR,
            flags: self.flags,
            header_size: HEADER_SIZE as u16,
            content_hash: [0u8; 32],
            dialect_hash: crate::layout::dialect_hash(),
            total_size: 0,
            sections: [crate::layout::SectionSpan::default(); SECTION_COUNT],
        };
        for section in Section::ALL {
            while image.len() % 8 != 0 {
                image.push(0);
            }
            header.span_mut(section).offset = image.len() as u32;
            header.span_mut(section).count = self.counts[section as usize];
            image.extend_from_slice(&self.sections[section as usize]);
        }
        while image.len() % 8 != 0 {
            image.push(0);
        }
        header.total_size = image.len() as u64;
        header.write(&mut image);
        let hash = hash_image(&image)?;
        image[16..48].copy_from_slice(&hash);
        if image.len() as u64 != size {
            return Err(Error::StreamDelta(
                "reassembled size disagrees with the end frame",
            ));
        }
        Ok(image)
    }

    /// The reassembled module, once a generation completed.
    pub fn module(&self) -> Option<&InfinityModule> {
        self.module.as_ref()
    }

    /// The reassembled canonical image, once a generation completed.
    pub fn image(&self) -> Option<&[u8]> {
        self.image.as_deref()
    }

    /// Finish the stream, requiring at least one completed generation and no
    /// half-received frame left over.
    pub fn finish(self) -> Result<StreamedModule> {
        if !self.partial.is_empty() {
            // A partial frame at the end of the stream. Read the declared
            // length only when the header itself arrived; never index past the
            // buffer.
            let needed = if self.partial.len() >= 20 {
                let declared = u32::from_le_bytes([
                    self.partial[16],
                    self.partial[17],
                    self.partial[18],
                    self.partial[19],
                ]) as u64;
                FRAME_HEADER_SIZE as u64 + declared
            } else {
                FRAME_HEADER_SIZE as u64
            };
            return Err(Error::Truncated {
                needed,
                found: self.partial.len() as u64,
            });
        }
        let module = self.module.ok_or(Error::StreamUnterminated)?;
        let image = self.image.ok_or(Error::StreamUnterminated)?;
        let hash = hash_image(&image)?;
        Ok(StreamedModule {
            module,
            image,
            content_hash: hash,
        })
    }

    /// Number of frames consumed.
    pub fn frames(&self) -> u64 {
        self.frames
    }
}

/// Stream encoder facade: prepares frames for a module and for deltas.
#[derive(Debug)]
pub struct StreamEncoder {
    frames: VecDeque<Frame>,
    sequence: u64,
}

impl StreamEncoder {
    /// Encode `module` as a complete generation.
    pub fn new(module: &InfinityModule, chunk: usize) -> Result<Self> {
        let frames = encode_stream(module, chunk)?;
        let sequence = frames.len() as u64;
        Ok(Self {
            frames: frames.into(),
            sequence,
        })
    }

    /// Append an incremental generation: the delta ops plus the closing end
    /// frame carrying the hash of the *whole* re-encoded module.
    pub fn push_delta(&mut self, base: &InfinityModule, ops: &[DeltaOp]) -> Result<()> {
        let updated = apply_delta(base, ops)?;
        let image = encode_with(&updated, EncodeOpts::default())?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&(ops.len() as u32).to_le_bytes());
        for op in ops {
            op.encode(&mut payload)?;
        }
        self.frames
            .push_back(Frame::new(FrameKind::Delta, self.sequence, payload));
        self.sequence += 1;
        let mut end = Vec::new();
        end.extend_from_slice(&hash_image(&image)?);
        end.extend_from_slice(&(image.len() as u64).to_le_bytes());
        self.frames
            .push_back(Frame::new(FrameKind::End, self.sequence, end));
        self.sequence += 1;
        Ok(())
    }

    /// All frames in order.
    pub fn frames(&self) -> Vec<Frame> {
        self.frames.iter().cloned().collect()
    }

    /// Concatenated frame bytes (a single byte stream).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for frame in &self.frames {
            out.extend_from_slice(&frame.to_bytes());
        }
        out
    }
}

fn write_string(out: &mut Vec<u8>, text: &str) -> Result<()> {
    let bytes = text.as_bytes();
    if bytes.len() > u16::MAX as usize {
        return Err(Error::TooLarge);
    }
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn write_opt_string(out: &mut Vec<u8>, text: Option<&str>) -> Result<()> {
    match text {
        None => {
            out.push(0);
            Ok(())
        }
        Some(text) => {
            out.push(1);
            write_string(out, text)
        }
    }
}

fn take_u8(buf: &[u8], cursor: &mut usize) -> Result<u8> {
    if *cursor >= buf.len() {
        return Err(Error::StreamDelta("truncated delta payload"));
    }
    let value = buf[*cursor];
    *cursor += 1;
    Ok(value)
}

fn take_u32(buf: &[u8], cursor: &mut usize) -> Result<u32> {
    if *cursor + 4 > buf.len() {
        return Err(Error::StreamDelta("truncated delta payload"));
    }
    let value = read_u32(buf, *cursor)?;
    *cursor += 4;
    Ok(value)
}

fn take_u64(buf: &[u8], cursor: &mut usize) -> Result<u64> {
    if *cursor + 8 > buf.len() {
        return Err(Error::StreamDelta("truncated delta payload"));
    }
    let value = read_u64(buf, *cursor)?;
    *cursor += 8;
    Ok(value)
}

fn take_i64(buf: &[u8], cursor: &mut usize) -> Result<i64> {
    take_u64(buf, cursor).map(|value| value as i64)
}

fn take_hash(buf: &[u8], cursor: &mut usize) -> Result<[u8; 32]> {
    if *cursor + 32 > buf.len() {
        return Err(Error::StreamDelta("truncated delta payload"));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&buf[*cursor..*cursor + 32]);
    *cursor += 32;
    Ok(hash)
}

fn take_string(buf: &[u8], cursor: &mut usize) -> Result<String> {
    if *cursor + 2 > buf.len() {
        return Err(Error::StreamDelta("truncated delta payload"));
    }
    let len = u16::from_le_bytes([buf[*cursor], buf[*cursor + 1]]) as usize;
    *cursor += 2;
    if *cursor + len > buf.len() {
        return Err(Error::StreamDelta("truncated delta payload"));
    }
    let text = std::str::from_utf8(&buf[*cursor..*cursor + len])
        .map_err(|_| Error::Utf8 {
            offset: *cursor as u64,
        })?
        .to_string();
    *cursor += len;
    Ok(text)
}

fn take_opt_string(buf: &[u8], cursor: &mut usize) -> Result<Option<String>> {
    match take_u8(buf, cursor)? {
        0 => Ok(None),
        1 => Ok(Some(take_string(buf, cursor)?)),
        _ => Err(Error::StreamDelta("invalid optional string tag")),
    }
}

fn decode_fragment(
    buf: &[u8],
    cursor: &mut usize,
    limits: crate::layout::Limits,
) -> Result<InfinityModule> {
    let len = take_u32(buf, cursor)? as usize;
    if *cursor + len > buf.len() {
        return Err(Error::StreamDelta("truncated fragment"));
    }
    let bytes = &buf[*cursor..*cursor + len];
    *cursor += len;
    // A fragment is a complete image: validate it under the *stream's* limits,
    // not the defaults, so a delta cannot smuggle a larger module past a strict
    // caller.
    crate::decode::decode_with(
        bytes,
        crate::layout::DecodeOpts {
            limits,
            verify_hash: true,
            verify_canonical: false,
        },
    )
}

/// Apply a list of delta operations and return the re-encoded hash.
pub fn delta_hash(module: &InfinityModule, ops: &[DeltaOp]) -> Result<[u8; 32]> {
    let updated = apply_delta(module, ops)?;
    let image = encode_with(&updated, EncodeOpts::default())?;
    hash_image(&image)
}

/// Reassemble a whole byte stream into a module.
pub fn decode_stream(bytes: &[u8]) -> Result<StreamedModule> {
    let mut decoder = StreamDecoder::new();
    decoder.push_bytes(bytes)?;
    decoder.finish()
}

/// Convenience: number of bytes a generation occupies after padding.
pub fn aligned_section_len(len: usize) -> usize {
    align8(len as u64) as usize
}

/// Test helper: annotations that a delta touched.
pub fn delta_annotations(ops: &[DeltaOp]) -> Vec<Annotation> {
    ops.iter()
        .filter_map(|op| match op {
            DeltaOp::SetAnnotation { node, kind } => Some(Annotation {
                node: *node,
                kind: kind.clone(),
            }),
            _ => None,
        })
        .collect()
}
