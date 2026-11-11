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
//! confusing parse error later. The checksum is integrity only: eight bytes
//! give a 2^32 birthday bound, so a colliding frame pair can be forged; it
//! detects random corruption, never forgery, and proves nothing about who
//! sent the frame. Authenticity comes only from a signature (a `SignedImage`
//! envelope) or the full 32-byte content hash verified at `End` — never
//! from the frame checksum (INF-L11(c)).

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

/// Work charged per byte of generation input (INF-13).
///
/// One generation does apply (clone the base module and merge), a re-encode,
/// `Validated::new` with `verify_canonical: true` (validate, hash, decode,
/// re-encode and re-validate) and a final `decode_validated`: roughly six
/// to eight image-sized passes. Measured on a 10 MiB image: one generation
/// costs 1.3-1.9x one `validate_canonical` in release (1.2-2.4x in debug
/// across runs; the `validate_canonical` baseline itself is noisy under
/// load), i.e. up to ~8 passes against the 4 charged here, so the charge
/// tracks the real work within a small constant factor (at most ~2x in the
/// worst measured case). The charge is applied at the `End` sites, which is
/// where a generation's work happens.
pub const GENERATION_WORK_FACTOR: u64 = 4;
/// Total generation-work budget, as a multiple of `Limits::max_total_bytes`
/// (INF-13).
///
/// The audit's example total (8x) cannot hold together with the suite's
/// legitimate-use floor: the marathon 40-generation stream charges 95,224
/// bytes of generation work against a 4 KiB budget (measured 2026-11-10),
/// so the multiplier must be at least 24x for that stream to complete.
/// 32x is the smallest power of two above that measured minimum, and it
/// fits the 40-generation stream with 27% margin. The total real work one
/// decoder can be made to do stays bounded at a few tens of
/// `max_total_bytes` (~60x in the worst measured case: 32x charged times
/// the ~1.9x worst measured real/charged ratio), against several hundred
/// times `max_total_bytes` before this fix (72 generations at a 1x charge
/// on the round-2 shape, each doing ~6-8 passes over the image).
pub const WORK_LIMIT_FACTOR: u64 = 32;

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
///
/// The payload is raw section bytes, including the secrets heap, so the type
/// has no derived `Debug` and no byte-wise equality: a log line or an equality
/// test would be an export path (see the crate's secret policy).
#[derive(Clone)]
pub struct Frame {
    pub kind: FrameKind,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("kind", &self.kind)
            .field("sequence", &self.sequence)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl Frame {
    /// # Panics
    ///
    /// Panics when `payload` is larger than [`MAX_FRAME_PAYLOAD`]: the frame
    /// length is a `u32` and a larger payload cannot be represented, so the
    /// infallible constructor refuses the caller bug instead of emitting a
    /// corrupt frame. `new` stays infallible on purpose: the crate is past
    /// 1.0, so making it fallible would be a breaking change for a Low,
    /// and the fallible form already exists — a caller that accepts a size
    /// from input uses [`Frame::try_new`] instead (INF-L11(b)).
    pub fn new(kind: FrameKind, sequence: u64, payload: Vec<u8>) -> Self {
        assert!(
            payload.len() <= MAX_FRAME_PAYLOAD as usize,
            "frame payload exceeds MAX_FRAME_PAYLOAD (use Frame::try_new for a payload size a caller cannot prove)"
        );
        Frame {
            kind,
            sequence,
            payload,
        }
    }

    /// Fallible form of [`Frame::new`] for a payload size a caller cannot prove.
    ///
    /// `new` panics on an oversized payload because it is a caller bug; a
    /// caller that accepts a size from input uses this instead and gets
    /// `infinity/too-large`.
    pub fn try_new(kind: FrameKind, sequence: u64, payload: Vec<u8>) -> Result<Self> {
        if payload.len() > MAX_FRAME_PAYLOAD as usize {
            return Err(Error::TooLarge);
        }
        Ok(Frame {
            kind,
            sequence,
            payload,
        })
    }

    /// Serialize the frame with its header and checksum.
    ///
    /// # Panics
    ///
    /// Panics when the payload is larger than [`MAX_FRAME_PAYLOAD`]: a
    /// `Frame` that large violates the type's invariant, and it can only
    /// exist because a caller built it by hand — the fields are public —
    /// or mutated one after construction. Hand-built frames use
    /// [`Frame::try_to_bytes`] instead (INF-L11(b)).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("frame payload exceeds MAX_FRAME_PAYLOAD (use Frame::try_to_bytes for a frame built by hand)")
    }

    /// Fallible form of [`Frame::to_bytes`] for a frame a caller built by hand.
    ///
    /// `to_bytes` panics on an oversized payload because the payload
    /// ceiling is the type's invariant; a caller that assembles a frame
    /// from input uses this instead and gets `infinity/too-large`.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        if self.payload.len() > MAX_FRAME_PAYLOAD as usize {
            return Err(Error::TooLarge);
        }
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
        Ok(out)
    }

    /// Parse one frame, returning it and the number of bytes consumed.
    ///
    /// A buffer shorter than four bytes is `infinity/truncated` (the wait
    /// signal a network reader needs); four bytes or more with a wrong magic is
    /// `infinity/stream-magic`. A buffer with the magic but not the whole header
    /// is also `infinity/truncated`.
    pub fn parse(buf: &[u8]) -> Result<(Frame, usize)> {
        if buf.len() < 4 {
            // Not enough bytes to identify the format: a network reader must
            // wait for more instead of reporting corruption on a one-byte read.
            return Err(Error::Truncated {
                needed: FRAME_HEADER_SIZE as u64,
                found: buf.len() as u64,
            });
        }
        if buf[0..4] != STREAM_MAGIC {
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
            return Err(Error::StreamFlags(u32::from(flags)));
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
            // A complete header whose payload has not fully arrived is a
            // truncated read: `push_bytes` waits for more instead of treating an
            // honest split as a fatal frame-length fault.
            return Err(Error::Truncated {
                needed: payload_end as u64,
                found: buf.len() as u64,
            });
        }
        let payload = &buf[payload_start..payload_end];
        let expected = frame_checksum(payload);
        if buf[24..32] != expected[..8] {
            // A frame checksum fault is a framing fault, not the image content
            // hash: a consumer that retries a frame must not be sent down the
            // "the image is corrupt" path (cross-cutting pass 1, #6).
            return Err(Error::StreamChecksum);
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
///
/// Integrity only: the caller takes the first 8 bytes, and eight bytes
/// give a 2^32 birthday bound, so a colliding frame pair can be forged.
/// A matching checksum says the bytes survived the transport
/// uncorrupted; it never says who sent them. Authenticity comes only
/// from a signature (a `SignedImage` envelope) or the full 32-byte
/// content hash verified at `End` (INF-L11(c)).
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
    // Batch payload = section id + count + chunk length + bytes (9 bytes of
    // framing). A larger chunk would emit a frame the decoder refuses.
    if chunk == 0 || chunk > MAX_FRAME_PAYLOAD as usize - 9 {
        return Err(Error::InvalidArgument(
            "chunk size must fit one frame payload",
        ));
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
                out.extend_from_slice(
                    &u32::try_from(image.len())
                        .map_err(|_| Error::TooLarge)?
                        .to_le_bytes(),
                );
                out.extend_from_slice(&image);
            }
            DeltaOp::SetBinding { name, node } => {
                out.push(3);
                write_delta_string(out, name)?;
                out.extend_from_slice(&node.0.to_le_bytes());
            }
            DeltaOp::RemoveBinding { name } => {
                out.push(4);
                write_delta_string(out, name)?;
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
            2 => {
                // Tag 2 (`PushNode`) was specified but retired before
                // release: it appended a fragment without a name, so its
                // nodes were unreachable and canonicalization dropped
                // them — a silent no-op (spec §3). The tag stays refused
                // with its own message, not the catch-all below, so a
                // future assignment is a deliberate change (INF-L11(a)).
                return Err(Error::StreamDelta("delta operation 2 is retired"));
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
                    2 => match take_u8(buf, cursor)? {
                        0 => AnnotationKind::AiImmutable(false),
                        1 => AnnotationKind::AiImmutable(true),
                        _ => {
                            return Err(Error::StreamDelta(
                                "immutable annotation flag must be 0 or 1",
                            ))
                        }
                    },
                    _ => return Err(Error::StreamDelta("unknown annotation kind")),
                };
                DeltaOp::SetAnnotation { node, kind }
            }
            6 => DeltaOp::ClearAnnotations,
            7 => {
                if !take_bool(buf, cursor)? {
                    DeltaOp::SetProvenance(None)
                } else {
                    let producer = take_opt_string(buf, cursor)?;
                    let model = take_opt_string(buf, cursor)?;
                    let tool = take_opt_string(buf, cursor)?;
                    let timestamp_ms = take_u64(buf, cursor)?;
                    let parent = if take_bool(buf, cursor)? {
                        Some(take_hash(buf, cursor)?)
                    } else {
                        None
                    };
                    let count = take_u32(buf, cursor)?;
                    if count > limits.max_prov_entries {
                        // A 64 MiB frame fits millions of tiny entries; the ceiling
                        // has to fire before the loop, not after it.
                        return Err(Error::Limit {
                            kind: "delta provenance entries",
                            limit: limits.max_prov_entries as u64,
                        });
                    }
                    let mut entries = Vec::with_capacity(count.min(4096) as usize);
                    for _ in 0..count {
                        let key = take_string(buf, cursor)?;
                        let value = match take_u8(buf, cursor)? {
                            0 => crate::ir::ProvValue::Text(take_string(buf, cursor)?),
                            1 => crate::ir::ProvValue::Int(take_i64(buf, cursor)?),
                            2 => crate::ir::ProvValue::Flag(take_bool(buf, cursor)?),
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
    apply_delta_with_limits(module, ops, crate::layout::Limits::default())
}

/// Report a delta-path fault as the delta fault it is.
///
/// The merge and the re-encode run on a peer-supplied frame, so an encoder
/// refusal is not "the caller's own module": a receiver that saw
/// `infinity/encode` would treat the frame as its own mistake and keep the
/// connection (cross-cutting pass 1, #6). Resource ceilings keep their code.
fn delta_fault(error: Error) -> Error {
    match error {
        Error::Limit { .. } | Error::TooLarge => error,
        Error::StreamDelta(_)
        | Error::StreamState(_)
        | Error::StreamHashMismatch
        | Error::StreamChecksum => error,
        _ => Error::StreamDelta("the delta does not produce a canonical module"),
    }
}

/// [`apply_delta`] under an explicit node ceiling.
///
/// A decoder built with strict limits must merge under the same ceiling it
/// validated the fragment with, not the defaults.
pub fn apply_delta_with_limits(
    module: &InfinityModule,
    ops: &[DeltaOp],
    limits: crate::layout::Limits,
) -> Result<InfinityModule> {
    let mut out = module.clone();
    apply_ops(&mut out, ops, limits)?;
    Ok(out)
}

/// Apply delta operations in place.
///
/// This is the incremental path for a caller that already owns the module: it
/// avoids cloning the whole graph and only merges the fragment nodes actually
/// referenced by `PutNode`. Canonical encoding still runs once at the end,
/// because the canonical image is the identity boundary.
///
/// A `PutNode` prunes unreachable nodes and compacts the arena (INF-14), so
/// node ids held from before the call can shift; re-resolve them from the
/// updated module (by binding or by content) instead of reusing old ids.
pub fn apply_delta_in_place(module: &mut InfinityModule, ops: &[DeltaOp]) -> Result<()> {
    apply_delta_in_place_with_limits(module, ops, crate::layout::Limits::default())
}

/// [`apply_delta_in_place`] under an explicit node ceiling.
///
/// Fail-closed: the ops run against a clone and the caller's module is replaced
/// only when every op succeeded, so a refused list cannot leave a partial
/// mutation behind.
pub fn apply_delta_in_place_with_limits(
    module: &mut InfinityModule,
    ops: &[DeltaOp],
    limits: crate::layout::Limits,
) -> Result<()> {
    let mut updated = module.clone();
    apply_ops(&mut updated, ops, limits)?;
    *module = updated;
    Ok(())
}

fn apply_ops(
    module: &mut InfinityModule,
    ops: &[DeltaOp],
    limits: crate::layout::Limits,
) -> Result<()> {
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
                let replacement = merge_fragment_with_limits(module, fragment, limits)?;
                // The fragment's root annotations now point at the imported
                // root copy. The copy is orphaned by the content move below,
                // so repoint them at the target that now holds the root's
                // content — otherwise the following prune would drop the
                // annotations with the copy (INF-14).
                module.repoint_annotations(replacement, *target);
                let content = module
                    .get(replacement)
                    .cloned()
                    .ok_or(Error::StreamDelta("fragment root missing"))?;
                *module.node_mut(*target)? = content;
                // Prune what the `PutNode` orphaned — the imported root copy
                // and the old target subtree — so the arena stays
                // proportional to the live module instead of growing to
                // `arena_limit` over a long stream (INF-14). One linear
                // pass, the same order as the validate/encode passes every
                // generation already pays (INF-13).
                module.prune_unreachable()?;
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
                if let AnnotationKind::Constraint { expr, .. } = kind {
                    if module.get(*expr).is_none() {
                        return Err(Error::StreamDelta("annotation expression does not exist"));
                    }
                }
                module.annotate(*node, kind.clone());
            }
            DeltaOp::ClearAnnotations => module.clear_annotations(),
            DeltaOp::SetProvenance(prov) => {
                if let Some(provenance) = prov {
                    for text in [
                        provenance.producer.as_deref(),
                        provenance.model.as_deref(),
                        provenance.tool.as_deref(),
                    ]
                    .into_iter()
                    .flatten()
                    {
                        if text.is_empty() {
                            // The encoder refuses an empty provenance text; a
                            // delta must report the same fault in stream terms.
                            return Err(Error::StreamDelta("empty provenance text"));
                        }
                    }
                }
                module.set_provenance(prov.clone());
            }
        }
    }
    Ok(())
}

pub(crate) fn merge_fragment(
    base: &mut InfinityModule,
    fragment: &InfinityModule,
) -> Result<NodeId> {
    merge_fragment_with_limits(base, fragment, crate::layout::Limits::default())
}

pub(crate) fn merge_fragment_with_limits(
    base: &mut InfinityModule,
    fragment: &InfinityModule,
    limits: crate::layout::Limits,
) -> Result<NodeId> {
    // A rootless fragment is refused before anything is pushed: the merge
    // is fail-atomic (INF-14 — the old code pushed the fragment first and
    // only then discovered the missing root, leaving the arena mutated on
    // the error path; the clone-then-swap callers contained it, but a
    // direct caller did not).
    let fragment_root = fragment
        .root()
        .ok_or(Error::StreamDelta("fragment has no root"))?;
    // Import only the nodes the graft can ever reach: the fragment root's
    // cone plus the cones of the fragment's annotation subjects and
    // constraint expressions (annotations are roots, so their subjects
    // must land for the carried annotations to stay valid). Fragment
    // BINDINGS are not grafted by `PutNode` (pinned by the marathon
    // round-7 tests), so a node reachable only through a binding is not
    // imported: it would be unreachable in the base the moment it lands
    // (INF-14).
    let import = fragment_import_set(fragment, fragment_root);
    let import_count = import.iter().filter(|keep| **keep).count();
    let base_count = base.node_count();
    // A fragment can be as large as a frame allows. The merged arena is
    // bounded by the node ceiling (well below the u32 id space) so a
    // stream of tiny fragments cannot turn a small wire budget into a huge
    // arena and an expensive canonical encode. The bound is on the
    // IMPORTED count, not the fragment's raw count: a fragment whose bulk
    // sits behind a binding cannot buy arena growth past the ceiling (and
    // cannot be refused for nodes it never imports).
    let arena_limit = limits.max_nodes as usize;
    let merged = base_count
        .checked_add(import_count)
        .filter(|total| *total <= arena_limit)
        .ok_or(Error::Limit {
            kind: "stream arena nodes",
            limit: arena_limit as u64,
        })?;
    // The fragment's provenance is the merged module's only provenance
    // record when the base has none; when both carry one and they differ,
    // the single provenance slot cannot hold both, so the delta is refused
    // explicitly instead of silently dropping the fragment's (INF-14).
    // Checked before any mutation, so the refusal leaves the base untouched.
    if let Some(fragment_provenance) = fragment.provenance() {
        if let Some(base_provenance) = base.provenance() {
            if base_provenance != fragment_provenance {
                return Err(Error::StreamDelta(
                    "fragment carries provenance that differs from the base module's provenance",
                ));
            }
        }
    }
    let mut map: Vec<NodeId> = vec![NodeId::NONE; fragment.node_count()];
    let mut next = base_count;
    for (index, keep) in import.iter().enumerate() {
        if *keep {
            map[index] = NodeId(next as u32);
            next += 1;
        }
    }
    debug_assert_eq!(next, merged);
    // Remap every node first: a failure must leave the caller's arena untouched.
    let mut remapped = Vec::with_capacity(import_count);
    for (index, node) in fragment.nodes().iter().enumerate() {
        if import[index] {
            remapped.push(remap_node(node, &map)?);
        }
    }
    for node in remapped {
        base.try_push(node)?;
    }
    // Carry the fragment's annotations, remapped into the base arena
    // (INF-14 — the old code used only the root content and silently
    // discarded them). Exact duplicates cannot arise here: every imported
    // id is fresh, so no pre-existing annotation can name one. An
    // annotation on the fragment root points at the imported root copy;
    // the `PutNode` caller repoints it at the target (see `apply_ops`),
    // where a duplicate can arise and is dropped.
    for annotation in fragment.annotations() {
        let subject = map
            .get(annotation.node.index())
            .copied()
            .filter(|id| !id.is_none())
            .ok_or(Error::StreamDelta(
                "fragment annotation subject was not imported",
            ))?;
        let kind = match &annotation.kind {
            AnnotationKind::Constraint { source, expr } => {
                let expr = map
                    .get(expr.index())
                    .copied()
                    .filter(|id| !id.is_none())
                    .ok_or(Error::StreamDelta(
                        "fragment annotation expression was not imported",
                    ))?;
                AnnotationKind::Constraint {
                    source: source.clone(),
                    expr,
                }
            }
            kind => kind.clone(),
        };
        base.annotate(subject, kind);
    }
    // Adopt the fragment's provenance when the base has none (INF-14).
    // When both carry the same provenance this is a no-op (checked above).
    if base.provenance().is_none() {
        if let Some(provenance) = fragment.provenance() {
            base.set_provenance(Some(provenance.clone()));
        }
    }
    map.get(fragment_root.index())
        .copied()
        .filter(|id| !id.is_none())
        .ok_or(Error::StreamDelta("fragment root was not imported"))
}

/// Nodes of `fragment` the graft can ever reach: the root's cone plus the
/// cones of the fragment's annotation subjects and constraint expressions.
///
/// Fragment bindings are deliberately NOT seeds: `PutNode` does not graft
/// bindings, so a binding-only node would land unreachable (INF-14, and
/// the marathon round-7 tests pin the no-graft rule). Out-of-range ids in
/// a hand-built fragment are skipped here and fail closed later, in the
/// remap, instead of panicking.
fn fragment_import_set(fragment: &InfinityModule, root: NodeId) -> Vec<bool> {
    let count = fragment.node_count();
    let mut keep = vec![false; count];
    let mut stack: Vec<NodeId> = vec![root];
    for annotation in fragment.annotations() {
        stack.push(annotation.node);
        if let AnnotationKind::Constraint { expr, .. } = &annotation.kind {
            stack.push(*expr);
        }
    }
    while let Some(id) = stack.pop() {
        if id.index() >= count || keep[id.index()] {
            continue;
        }
        keep[id.index()] = true;
        if let Some(node) = fragment.get(id) {
            for child in node.children() {
                if child.index() < count && !keep[child.index()] {
                    stack.push(child);
                }
            }
        }
    }
    keep
}

/// A reassembled stream generation.
#[derive(Clone)]
pub struct StreamedModule {
    pub module: InfinityModule,
    pub image: Vec<u8>,
    pub content_hash: [u8; 32],
}

impl std::fmt::Debug for StreamedModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Summary only: formatting the module clones the arena and scans
        // every text field against every secret (`InfinityModule`'s
        // `Debug`), which is work a log line must never do for a large
        // module — and a leak risk in miniature for a small one
        // (INF-L11(f)). Counts identify the module; contents never print.
        f.debug_struct("StreamedModule")
            .field("content_hash", &crate::ir::hash_hex(&self.content_hash))
            .field("image_len", &self.image.len())
            .field("node_count", &self.module.node_count())
            .field("root", &self.module.root())
            .finish()
    }
}

/// Streaming decoder state.
#[derive(Default)]
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
    /// Bytes held by the pending delta frames.
    pending_delta_bytes: u64,
    /// Image bytes of every completed generation in this decoder.
    generation_work: u64,
    /// Decoded bytes held by pending `PutNode` fragments.
    pending_decoded_bytes: u64,
    /// Set when the work ceiling fired; every later frame is refused without
    /// doing the work again.
    generation_stopped: bool,
    frames: u64,
    partial: Vec<u8>,
    cursor: usize,
}

impl std::fmt::Debug for StreamDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Counts and flags only: `partial` holds raw section bytes.
        f.debug_struct("StreamDecoder")
            .field("partial_len", &self.partial.len())
            .field("expected", &self.expected)
            .field("begun", &self.begun)
            .field("ended", &self.ended)
            .field(
                "sections_seen",
                &self.seen.iter().filter(|seen| **seen).count(),
            )
            .finish()
    }
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
            pending_delta_bytes: 0,
            generation_work: 0,
            pending_decoded_bytes: 0,
            generation_stopped: false,
            frames: 0,
            partial: Vec::new(),
            cursor: 0,
        }
    }

    /// Decoded bytes the pending delta state currently holds.
    ///
    /// Exposed so a caller can prove a refused frame left the accounting where
    /// it found it (audit AINF-001).
    pub fn pending_decoded_bytes(&self) -> u64 {
        self.pending_decoded_bytes
    }

    /// Cumulative generation work charged to this decoder (INF-13).
    ///
    /// Exposed so a caller (and a test) can prove the latch trips at the
    /// measured point instead of asserting it from the outside. The
    /// ceiling is [`WORK_LIMIT_FACTOR`] times `Limits::max_total_bytes`;
    /// each generation is charged at [`GENERATION_WORK_FACTOR`] times the
    /// image length, so the charged work also bounds the real work
    /// within a small constant factor.
    pub fn generation_work(&self) -> u64 {
        self.generation_work
    }

    /// Use explicit decode limits for the reassembled image and for every
    /// intermediate bound.
    ///
    /// The value is not validated here: a zero ceiling is discovered on the
    /// first input that touches it. Prefer [`StreamDecoder::try_with_limits`]
    /// when the limits come from configuration or a caller.
    pub fn with_limits(mut self, limits: crate::layout::Limits) -> Self {
        self.limits = limits;
        self
    }

    /// [`StreamDecoder::with_limits`] with the ceiling check at construction.
    ///
    /// A `Limits` with a zero anywhere is an argument error, not a limit the
    /// reader should discover as `infinity/limit` on a hostile frame; refusing it
    /// here names the field that is wrong.
    pub fn try_with_limits(mut self, limits: crate::layout::Limits) -> crate::Result<Self> {
        limits.check()?;
        self.limits = limits;
        Ok(self)
    }

    /// Feed raw frame bytes. Frames may be split across calls and several may
    /// arrive in one call; partial frames are buffered.
    ///
    /// Faults are recoverable per frame, not per buffer (spec §4): a
    /// refused frame is dropped from the buffer together with any tail
    /// parsed against it, and the decoder's semantic state is rolled back
    /// to before that frame, so the caller corrects the frame and resends
    /// from it in a fresh call — bytes already consumed before the fault
    /// are not replayed. This holds for parse faults (bad magic, version,
    /// kind, flags, checksum, frame length) as well as semantic faults:
    /// a parse fault used to leave the faulting bytes buffered, so every
    /// later `push_bytes` call re-failed with the same error and `finish`
    /// reported a misleading `infinity/truncated` (W7-NF-01). `push` (one
    /// frame) stays retryable per frame for the same reason.
    pub fn push_bytes(&mut self, buf: &[u8]) -> Result<()> {
        // The buffer is extended before any frame is parsed, so a caller-
        // controlled chunk must be bounded first: a single 1 GiB call used to
        // allocate it before the image ceiling could refuse a frame
        // (cross-cutting pass 3, #5). The ceiling allows a full image plus one
        // maximal frame and its header.
        let ceiling = self
            .limits
            .max_total_bytes
            .saturating_add(FRAME_HEADER_SIZE as u64)
            .saturating_add(MAX_FRAME_PAYLOAD as u64);
        if (self.partial.len() as u64).saturating_add(buf.len() as u64) > ceiling {
            return Err(Error::Limit {
                kind: "stream input bytes",
                limit: ceiling,
            });
        }
        self.partial.extend_from_slice(buf);
        // Parse against an offset and compact once: draining per frame moves the
        // remaining tail, which made this quadratic in frames per call.
        let mut consumed_total = 0usize;
        loop {
            let remaining = self.partial.len() - consumed_total;
            if remaining < 4 {
                break;
            }
            if self.partial[consumed_total..consumed_total + 4] != STREAM_MAGIC {
                // A wrong magic in a 4..31-byte tail would otherwise be reported
                // as a truncation and make the caller wait forever. The
                // faulting bytes are dropped, not kept: a magic fault is
                // final for these bytes, and keeping them would re-fail
                // every later call with the same error (INF-L11(e)).
                self.partial.clear();
                return Err(Error::StreamMagic);
            }
            if remaining < FRAME_HEADER_SIZE {
                break;
            }
            match Frame::parse(&self.partial[consumed_total..]) {
                Ok((frame, consumed)) => {
                    // Drain the frame even when its semantics are refused: the
                    // semantic state is rolled back inside `push`, and a caller
                    // that retries with corrected bytes must not have the bad
                    // frame replayed from the buffer first.
                    match self.push(&frame) {
                        Ok(()) => consumed_total += consumed,
                        Err(error) => {
                            // Sequence and semantic state are rolled back inside
                            // `push`, but the *tail* of this buffer was parsed
                            // against the frame that just failed, so it can
                            // never be delivered. Drop it: the caller corrects
                            // the failed frame and resends from it in a fresh
                            // call, and the decoder stays usable (INF-L11(e)).
                            self.partial.clear();
                            return Err(error);
                        }
                    }
                }
                // A short buffer is not an error: wait for the rest of the
                // frame. Every other parse fault is fatal for this buffer.
                Err(Error::Truncated { .. }) => {
                    // A frame whose declared payload can never fit the caller's
                    // image ceiling would be buffered up to MAX_FRAME_PAYLOAD.
                    // Header faults (flags, kind, reserved) were already reported
                    // by `parse`, so this only sees a well-formed header.
                    let at = consumed_total;
                    if self.partial.len() >= at + 20 {
                        let declared = u32::from_le_bytes([
                            self.partial[at + 16],
                            self.partial[at + 17],
                            self.partial[at + 18],
                            self.partial[at + 19],
                        ]) as u64;
                        if declared <= MAX_FRAME_PAYLOAD as u64
                            && declared > self.limits.max_total_bytes
                        {
                            // A frame whose declared length exceeds the
                            // caller's ceiling can never be accepted, so
                            // its bytes are dropped with the consumed
                            // prefix: a refused frame leaves nothing
                            // buffered (INF-L11(e)).
                            self.partial.clear();
                            return Err(Error::Limit {
                                kind: "stream frame bytes",
                                limit: self.limits.max_total_bytes,
                            });
                        }
                    }
                    break;
                }
                Err(error) => {
                    // A parse fault is final for these bytes: every
                    // non-`Truncated` verdict (bad magic, version, kind,
                    // flags, checksum, frame length) is decided on a
                    // complete header or a complete payload, so appending
                    // more bytes can never make the faulting frame valid.
                    // Drop it and its tail like the semantic path, so the
                    // caller corrects the frame and resends from it
                    // (INF-L11(e), W7-NF-01). Keeping the bytes poisoned
                    // the decoder: every later call re-failed with the
                    // same error and `finish` reported a misleading
                    // `Truncated`.
                    self.partial.clear();
                    return Err(error);
                }
            }
        }
        if consumed_total > 0 {
            self.partial.drain(..consumed_total);
        }
        Ok(())
    }

    /// Feed one parsed frame.
    ///
    /// A frame that fails semantic validation leaves the decoder exactly as it
    /// was: the sequence counter, the frame counter and any partially decoded
    /// deltas are restored, so the caller can fix the input and retry. A
    /// sequence mismatch is an ordinary semantic fault, not a fatal one: it
    /// rolls back like any other, and the corrected frame is accepted with
    /// its original sequence number (INF-L11(e) — the old "fatal, reopen
    /// the stream" wording contradicted the rollback above it).
    pub fn push(&mut self, frame: &Frame) -> Result<()> {
        if frame.sequence != self.expected {
            return Err(Error::StreamSequence {
                expected: self.expected,
                found: frame.sequence,
            });
        }
        let deltas_before = self.pending_deltas.len();
        let bytes_before = self.pending_delta_bytes;
        // The decoded-size charge happens while the frame decodes; a frame that
        // fails after charging must not poison the budget for a retry
        // (audit AINF-001).
        let decoded_before = self.pending_decoded_bytes;
        let expected_before = self.expected;
        let frames_before = self.frames;
        self.expected += 1;
        self.frames += 1;
        match self.push_inner(frame) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.expected = expected_before;
                self.frames = frames_before;
                self.pending_deltas.truncate(deltas_before);
                self.pending_delta_bytes = bytes_before;
                self.pending_decoded_bytes = decoded_before;
                Err(error)
            }
        }
    }

    fn push_inner(&mut self, frame: &Frame) -> Result<()> {
        if self.generation_stopped {
            // The ceiling is a latch: a peer must not be able to buy the same
            // assembly/encode work again by replaying one refused frame.
            return Err(Error::Limit {
                kind: "stream generation work",
                limit: self.work_limit(),
            });
        }
        // `Frame` fields are public, so `push` must enforce the wire ceiling
        // that `Frame::parse` enforces; otherwise a caller-built frame can carry
        // bytes no peer could ever send to this decoder.
        if frame.payload.len() > MAX_FRAME_PAYLOAD as usize {
            return Err(Error::StreamFrameLen {
                declared: u32::try_from(frame.payload.len()).unwrap_or(u32::MAX),
                available: frame.payload.len() as u64,
            });
        }
        if frame.payload.len() as u64 > self.limits.max_total_bytes {
            return Err(Error::Limit {
                kind: "stream frame bytes",
                limit: self.limits.max_total_bytes,
            });
        }
        match frame.kind {
            FrameKind::Begin => {
                if self.begun {
                    return Err(Error::StreamState("duplicate begin frame"));
                }
                if self.ended {
                    return Err(Error::StreamState("begin after end"));
                }
                if frame.payload.len() != 24 {
                    return Err(Error::StreamPayloadLen {
                        kind: frame.kind.code(),
                        expected: 24,
                        found: frame.payload.len() as u64,
                    });
                }
                let major = u16::from_le_bytes([frame.payload[0], frame.payload[1]]);
                let minor = u16::from_le_bytes([frame.payload[2], frame.payload[3]]);
                // The Begin payload carries the *image* header's generation and
                // flag word, so a mismatch is a file-format answer, not a
                // stream-frame one.
                if major != crate::layout::FORMAT_MAJOR {
                    return Err(Error::VersionMajor(major));
                }
                if minor > crate::layout::FORMAT_MINOR {
                    return Err(Error::VersionMinor(minor));
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
                // The same accepted set as the image path
                // (`validate::Validated::new`): the current dialect plus the
                // legacy 1.0 dialect (INF-03 / BND-F1 / R2-VER-03). The two
                // paths must agree, or a stream a peer accepts as a file is
                // refused as a stream (and vice versa).
                if !crate::layout::is_accepted_dialect(dialect) {
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
                    return Err(Error::StreamPayloadLen {
                        kind: frame.kind.code(),
                        expected: 9,
                        found: frame.payload.len() as u64,
                    });
                }
                let section = frame.payload[0] as usize;
                if section >= SECTION_COUNT {
                    return Err(Error::StreamState("unknown section id"));
                }
                let count = read_u32(&frame.payload, 1)?;
                let len = read_u32(&frame.payload, 5)? as usize;
                // `9 + len` overflows on a 32-bit target when `len` is near
                // `u32::MAX`; checked arithmetic keeps that a refusal, not a
                // panic on wasm32/i686.
                let expected = 9usize
                    .checked_add(len)
                    .ok_or(Error::StreamDelta("batch length overflow"))?;
                if frame.payload.len() != expected {
                    return Err(Error::StreamPayloadLen {
                        kind: frame.kind.code(),
                        expected: u32::try_from(expected).unwrap_or(u32::MAX),
                        found: frame.payload.len() as u64,
                    });
                }
                let any_seen = self.seen.iter().any(|seen| *seen);
                if !any_seen {
                    // A generation starts at section 0; starting later would leave
                    // a hole that only fails at `End`, with a worse code.
                    if section != 0 {
                        return Err(Error::StreamState("sections out of order"));
                    }
                } else if section != self.cursor && section != self.cursor + 1 {
                    return Err(Error::StreamState("sections out of order"));
                }
                if self.seen[section] && self.counts[section] != count {
                    return Err(Error::StreamState("section count changed mid-stream"));
                }
                // A generation cannot occupy more than it declared. Without this
                // bound, an endless run of batches for one section would allocate
                // until the process dies before `End` is seen. The check runs
                // before the append, and the sums saturate instead of wrapping.
                let accumulated = self
                    .sections
                    .iter()
                    .fold(0usize, |total, section| total.saturating_add(section.len()));
                let declared = self
                    .total_size
                    .map(|size| size.min(usize::MAX as u64) as usize)
                    .unwrap_or(usize::MAX);
                let prospective = accumulated.saturating_add(frame.payload.len() - 9);
                if prospective > declared {
                    return Err(Error::Limit {
                        kind: "stream bytes",
                        limit: declared as u64,
                    });
                }
                if prospective as u64 > self.limits.max_total_bytes {
                    return Err(Error::Limit {
                        kind: "stream bytes",
                        limit: self.limits.max_total_bytes,
                    });
                }
                // Advance only now: a refused batch must leave the decoder
                // believing the previous section is current, or the next frame
                // jumps a section and leaves a hole.
                if section == self.cursor + 1 {
                    self.cursor = section;
                }
                self.seen[section] = true;
                self.counts[section] = count;
                self.sections[section].extend_from_slice(&frame.payload[9..]);
            }
            FrameKind::Delta => {
                if !self.ended {
                    return Err(Error::StreamState("delta before end"));
                }
                let mut cursor = 0usize;
                let count = take_u32(&frame.payload, &mut cursor)?;
                // Decoding is work even when the frame is later refused, and a
                // replayed frame must not be free.
                self.charge_generation(frame.payload.len())?;
                if count == 0 {
                    // A zero-op delta still opens a generation that a closing
                    // `End` re-encodes and re-validates: refuse it instead.
                    return Err(Error::StreamDelta("empty delta"));
                }
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
                // `DeltaOp` is far larger than its wire form (a `SetRoot` is 5
                // bytes and 144 bytes decoded). The bound is on decoded state,
                // not on wire bytes: one frame otherwise buys a 54x amplifier.
                let decoded = self
                    .pending_deltas
                    .len()
                    .saturating_add(count as usize)
                    .saturating_mul(std::mem::size_of::<DeltaOp>());
                let held = decoded
                    .saturating_add(usize::try_from(self.pending_delta_bytes).unwrap_or(usize::MAX))
                    .saturating_add(
                        usize::try_from(self.pending_decoded_bytes).unwrap_or(usize::MAX),
                    ) as u64;
                if held > self.limits.max_total_bytes {
                    return Err(Error::Limit {
                        kind: "delta decoded bytes",
                        limit: self.limits.max_total_bytes,
                    });
                }
                self.pending_delta_bytes = self
                    .pending_delta_bytes
                    .saturating_add(frame.payload.len() as u64);
                if self.pending_delta_bytes > self.limits.max_total_bytes {
                    // A stream can carry many delta frames; the operation count is
                    // not the resource that matters, the bytes are.
                    return Err(Error::Limit {
                        kind: "delta bytes",
                        limit: self.limits.max_total_bytes,
                    });
                }
                for _ in 0..count {
                    let op = DeltaOp::decode(&frame.payload, &mut cursor, self.limits)?;
                    if let DeltaOp::PutNode { fragment, .. } = &op {
                        // A fragment is a full module; its decoded nodes,
                        // field entries and payload bytes are the memory this
                        // delta buys (a table of a million fields is two
                        // nodes). The payload bytes are the dominant term: a
                        // 64 KiB string shared by 2000 nodes decodes to
                        // ~128 MiB while the node count charges ~272 KiB
                        // (INF-05) — charging nodes alone let a fragment buy
                        // ~470x its charge in decoded state. The payload is
                        // counted per reference, as decode materialises it.
                        let entries: u64 = fragment
                            .nodes()
                            .iter()
                            .map(|node| match node {
                                crate::ir::Inode::Table { fields }
                                | crate::ir::Inode::SchemaTable { fields, .. } => {
                                    fields.len() as u64
                                }
                                _ => 0,
                            })
                            .fold(0u64, |total, count| total.saturating_add(count));
                        let decoded_nodes = (fragment.node_count() as u64)
                            .saturating_mul(std::mem::size_of::<crate::ir::Inode>() as u64 + 32)
                            .saturating_add(entries.saturating_mul(40))
                            .saturating_add(fragment.decoded_payload_bytes());
                        self.pending_decoded_bytes =
                            self.pending_decoded_bytes.saturating_add(decoded_nodes);
                        let held = self
                            .pending_decoded_bytes
                            .saturating_add(self.pending_delta_bytes);
                        if held > self.limits.max_total_bytes {
                            return Err(Error::Limit {
                                kind: "delta decoded bytes",
                                limit: self.limits.max_total_bytes,
                            });
                        }
                    }
                    self.pending_deltas.push(op);
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
                    return Err(Error::StreamPayloadLen {
                        kind: frame.kind.code(),
                        expected: 40,
                        found: frame.payload.len() as u64,
                    });
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&frame.payload[..32]);
                let size = read_u64(&frame.payload, 32)?;
                if self.ended && self.pending_deltas.is_empty() {
                    // A repeat `End` with no delta would re-encode and
                    // re-validate the same module forever (measured 22 s from
                    // 800 wire bytes).
                    return Err(Error::StreamState("end without delta"));
                }
                if self.ended {
                    // Incremental generation: charge before the clone, merge
                    // and encode. The apply loop's cost is proportional to the
                    // decoded op count as well as to the image size.
                    let estimate = self.image.as_ref().map(|image| image.len()).unwrap_or(0);
                    let ops = self
                        .pending_deltas
                        .len()
                        .saturating_mul(std::mem::size_of::<DeltaOp>());
                    // The merge re-processes the pending fragments on every
                    // retry, and their cost is their bytes: a `PutNode` decoy
                    // otherwise buys an arbitrarily expensive merge for the
                    // price of the base image.
                    let pending =
                        usize::try_from(self.pending_delta_bytes).map_err(|_| Error::TooLarge)?;
                    // Charge the generation at the generation rate (INF-13):
                    // apply + encode + canonical validation + decode is
                    // ~6-8 image-sized passes, not the ~1x charged before.
                    self.charge_generation(
                        estimate
                            .max(ops)
                            .max(pending)
                            .saturating_mul(GENERATION_WORK_FACTOR as usize),
                    )?;
                    let base = self
                        .module
                        .as_ref()
                        .ok_or(Error::StreamState("no module to patch"))?;
                    let updated = apply_delta_with_limits(base, &self.pending_deltas, self.limits)
                        .map_err(delta_fault)?;
                    // A `PutNode` merge already prunes the replaced subtree
                    // and the imported root copy (INF-14), so the merged
                    // module holds no unreachable nodes from that op; the
                    // `drop_unreachable` opt-in stays as a safety net for
                    // the other ops (a `RemoveBinding` or `SetRoot` can
                    // still orphan a subtree, INF-04).
                    let image = encode_with(
                        &updated,
                        EncodeOpts {
                            drop_unreachable: true,
                            ..EncodeOpts::default()
                        },
                    )
                    .map_err(delta_fault)?;
                    if image.len() > estimate {
                        // The new image is bigger, so the validation and
                        // decode passes cost more: the growth is charged at
                        // the generation rate too (INF-13).
                        self.charge_generation(
                            (image.len() - estimate)
                                .saturating_mul(GENERATION_WORK_FACTOR as usize),
                        )?;
                    }
                    if self.image.as_ref() == Some(&image) {
                        // A delta that changes nothing still costs a full
                        // clone, merge and encode: refuse it (also closes the
                        // `SetRoot(current)` / `RemoveBinding(absent)` bypass).
                        return Err(Error::StreamDelta("delta did not change the module"));
                    }
                    if image.len() as u64 != size {
                        // The hash covers `total_size`, so a separate size fault
                        // would be a one-bit oracle over the receiver's private
                        // module (its exact encoded size, secret heap included).
                        return Err(Error::StreamHashMismatch);
                    }
                    if hash_image(&image)? != hash {
                        return Err(Error::StreamHashMismatch);
                    }
                    let validated = Validated::new(
                        &image,
                        crate::layout::DecodeOpts {
                            limits: self.limits,
                            verify_hash: true,
                            verify_canonical: true,
                        },
                    )?;
                    let module = crate::decode::decode_validated(&validated)?;
                    // Only a proven generation consumes the pending ops: a bad
                    // hash or size must leave them for a corrected retry.
                    self.pending_deltas.clear();
                    // The budget covers one generation's pending deltas; a
                    // long-lived session must not accumulate across generations.
                    self.pending_delta_bytes = 0;
                    self.pending_decoded_bytes = 0;
                    self.module = Some(module);
                    self.image = Some(image);
                    return Ok(());
                }
                // Charge the *accumulated* size, not the peer's `End.size`: the
                // declared number is untrusted, and charging it let a lie buy a
                // full assembly for 224 bytes of budget. The assembled length is
                // computable from the section buffers before allocating.
                let expected = self.assembled_len()?;
                // Charge first: the length is the work the assembly would do,
                // and a disagreement below must still cost it.
                let charge = usize::try_from(expected).map_err(|_| Error::TooLarge)?;
                // A first generation assembles, hashes, fully validates
                // (canonical proof) and decodes: charge it at the
                // generation rate (INF-13), not at 1x the image length.
                self.charge_generation(charge.saturating_mul(GENERATION_WORK_FACTOR as usize))?;
                if expected != size {
                    // The hash covers `total_size`, so a distinct size fault
                    // would be a one-bit oracle; it is also the fuel for the
                    // free-assembly loop.
                    return Err(Error::StreamHashMismatch);
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
                        verify_canonical: true,
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

    /// Total generation-work budget for this decoder (INF-13).
    ///
    /// This ceiling bounds the *cumulative* work across generations; the
    /// per-generation peak transient is bounded separately by INF-06:
    /// every generation's validate passes run through `Validated::new`
    /// under these same `Limits`, so each generation's validate transient
    /// fits `Limits::max_working_bytes`, and this ceiling counts every
    /// such generation at the validate-canonical rate. The two budgets
    /// compose instead of conflicting: a generation too big for the
    /// working budget is refused with "working bytes", and a stream of
    /// affordable generations is stopped by this ceiling.
    fn work_limit(&self) -> u64 {
        self.limits
            .max_total_bytes
            .saturating_mul(WORK_LIMIT_FACTOR)
    }

    /// Charge bytes against the stream's work ceiling.
    ///
    /// The `End` sites charge at `GENERATION_WORK_FACTOR` times the bytes
    /// they process (INF-13); a `Delta` frame charges its wire bytes at
    /// 1x. The split is deliberate, not an oversight: the closing `End`
    /// re-charges the pending delta bytes at the generation rate
    /// (`estimate.max(ops).max(pending)`), which pays for the fragment
    /// decode and validation the `Delta` frame already did -- charging the
    /// `Delta` at 4x as well would bill the same fragment work twice and
    /// refuse legitimate large-fragment streams. The `Delta` charge exists
    /// so a refused or replayed delta still costs the budget, and so a
    /// generation abandoned without its `End` cannot buy unbounded
    /// fragment validation: accepted-but-unclosed deltas are capped by the
    /// pending budgets (`pending_delta_bytes` and `pending_decoded_bytes`,
    /// each at most `max_total_bytes`), so the unclosed exposure is
    /// bounded at ~4x `max_total_bytes` of real work per generation cycle.
    /// Every generation applies the pending deltas, re-encodes and fully
    /// re-validates the module, so the charge is taken *before* that work: a
    /// replay of a refused frame costs the ceiling, not another encode. A
    /// tripped ceiling latches (`generation_stopped`), and every later frame is
    /// refused before it can do anything.
    fn charge_generation(&mut self, bytes: usize) -> Result<()> {
        let limit = self.work_limit();
        self.generation_work = self.generation_work.saturating_add(bytes as u64);
        if self.generation_work > limit {
            self.generation_stopped = true;
            return Err(Error::Limit {
                kind: "stream generation work",
                limit,
            });
        }
        Ok(())
    }

    /// Length `assemble` would produce, computed from the section buffers.
    ///
    /// No allocation, so the work charge can be taken from the real size before
    /// the assembly runs.
    fn assembled_len(&self) -> Result<u64> {
        if self.seen.iter().any(|seen| !seen) {
            return Err(Error::StreamState("generation missing a section"));
        }
        let mut total = HEADER_SIZE as u64;
        for section in Section::ALL {
            let body = self.sections[section as usize].len() as u64;
            total = total
                .checked_add(body)
                .and_then(|sum| sum.checked_add(7))
                .ok_or(Error::TooLarge)?
                & !7u64;
        }
        Ok(total)
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
            header.span_mut(section).offset = u32::try_from(image.len()).map_err(|_| {
                Error::StreamDelta("reassembled image exceeds the u32 offset space")
            })?;
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
            // Unreachable after `assembled_len`'s pre-check; kept as a guard and
            // classified like the hash fault it really is.
            return Err(Error::StreamHashMismatch);
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
    ///
    /// A refused frame leaves nothing buffered (see [`StreamDecoder::push_bytes`]),
    /// so a `Truncated` here means the stream really did end mid-frame —
    /// not that an earlier fault is still buffered (INF-L11(e), W7-NF-01).
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
        if !self.pending_deltas.is_empty() {
            // Deltas that never reached their closing `End` frame describe a
            // generation this stream did not produce.
            return Err(Error::StreamUnterminated);
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
pub struct StreamEncoder {
    frames: VecDeque<Frame>,
    sequence: u64,
}

impl std::fmt::Debug for StreamEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamEncoder")
            .field("frames", &self.frames.len())
            .field("sequence", &self.sequence)
            .finish()
    }
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
        // Both sides opt in to the drop (INF-04): the delta orphans the
        // replaced subtree on purpose, and the no-op check compares the
        // canonical images, so both must be produced the same way.
        let drop = EncodeOpts {
            drop_unreachable: true,
            ..EncodeOpts::default()
        };
        let image = encode_with(&updated, drop)?;
        if image == encode_with(base, drop)? {
            // The decoder refuses a no-op generation; emitting one would produce
            // a stream the producer's own peer rejects.
            return Err(Error::StreamDelta("delta did not change the module"));
        }
        let mut payload = Vec::new();
        payload.extend_from_slice(
            &u32::try_from(ops.len())
                .map_err(|_| Error::StreamDelta("too many delta operations"))?
                .to_le_bytes(),
        );
        for op in ops {
            op.encode(&mut payload)?;
        }
        if payload.len() > MAX_FRAME_PAYLOAD as usize {
            // The decoder refuses a frame over the ceiling, so emitting one would
            // produce a stream that cannot be read. Delta frames carry one op set;
            // a caller with more work sends another generation. This is a stream
            // fault, not an image-address-space one.
            return Err(Error::StreamDelta("delta frame exceeds the frame ceiling"));
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
        // This helper only writes delta payloads (annotation and provenance
        // ops), so the fault is the delta's, not the image address space.
        return Err(Error::StreamDelta(
            "delta string exceeds the u16 length space",
        ));
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

/// A wire boolean is exactly 0 or 1; any other byte is a delta fault.
fn take_bool(buf: &[u8], cursor: &mut usize) -> Result<bool> {
    match take_u8(buf, cursor)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::StreamDelta("invalid boolean tag")),
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

/// Write a delta string: `u16` length, then the bytes (spec §4).
fn write_delta_string(out: &mut Vec<u8>, text: &str) -> Result<()> {
    let len = u16::try_from(text.len())
        .map_err(|_| Error::StreamDelta("delta string exceeds the u16 length space"))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(())
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
        .map_err(|_| Error::StreamDelta("invalid UTF-8 in a delta string"))?
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
    // On a 32-bit target `*cursor + len` wraps for a `u32`-sized length, which
    // would build a slice with `start > end` and panic in release.
    let end = cursor
        .checked_add(len)
        .filter(|end| *end <= buf.len())
        .ok_or(Error::StreamDelta("truncated fragment"))?;
    let bytes = &buf[*cursor..end];
    *cursor = end;
    // A fragment is a complete image: validate it under the *stream's* limits,
    // not the defaults, so a delta cannot smuggle a larger module past a strict
    // caller.
    crate::decode::decode_with(
        bytes,
        crate::layout::DecodeOpts {
            limits,
            verify_hash: true,
            verify_canonical: true,
        },
    )
}

/// Apply a list of delta operations and return the re-encoded hash.
pub fn delta_hash(module: &InfinityModule, ops: &[DeltaOp]) -> Result<[u8; 32]> {
    let updated = apply_delta(module, ops)?;
    // A `PutNode` merge already prunes the replaced subtree (INF-14), but
    // the other ops can still orphan nodes (INF-04), so the re-encode
    // keeps the `drop_unreachable` opt-in.
    let image = encode_with(
        &updated,
        EncodeOpts {
            drop_unreachable: true,
            ..EncodeOpts::default()
        },
    )?;
    hash_image(&image)
}

/// Reassemble a whole byte stream into a module.
pub fn decode_stream(bytes: &[u8]) -> Result<StreamedModule> {
    decode_stream_with_limits(bytes, crate::layout::Limits::default())
}

/// Reassemble a whole byte stream into a module under explicit limits.
///
/// The strict caller that today hand-rolls a [`StreamDecoder`] to get
/// non-default limits uses this instead: the limits bound the
/// reassembled image and every intermediate check, exactly as
/// [`StreamDecoder::with_limits`] does. A limits value with a zero
/// ceiling is refused up front as `infinity/invalid-argument`
/// ([`crate::layout::Limits::check`]) instead of surfacing as
/// `infinity/limit` on the first hostile frame (INF-L11(d)).
pub fn decode_stream_with_limits(
    bytes: &[u8],
    limits: crate::layout::Limits,
) -> Result<StreamedModule> {
    let mut decoder = StreamDecoder::new().try_with_limits(limits)?;
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
