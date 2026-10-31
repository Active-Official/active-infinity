//! Optional proof-carrying sidecars.
//!
//! An image stays self-describing: its Blake3 content hash is over its canonical
//! bytes. A sidecar adds the properties a consumer usually wants to check
//! before decoding — size, node and edge counts, whether secrets are present,
//! the dialect, and an optional companion schema's hash — so a verifier can
//! confirm the claims without trusting the producer's word.
//!
//! The sidecar is not authority: it never grants anything, and a proof that
//! does not match its image is refused with `infinity/proof`.

use crate::layout::Meta;
use crate::schema::Schema;
use crate::{content_hash, validate_canonical, Error, Limits, Result};

/// Format tag carried by the JSON sidecar.
pub const PROOF_FORMAT: &str = "active-infinity/proof/1";

/// A proof sidecar for one canonical image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// Blake3 content hash of the canonical image.
    pub content_hash: [u8; 32],
    /// Total image size, in bytes.
    pub size: u64,
    /// Node count.
    pub nodes: u32,
    /// Edge count.
    pub edges: u32,
    /// Secret-table entries (the redaction obligation: zero means none).
    pub secrets: u32,
    /// AINF major version.
    pub major: u16,
    /// AINF minor version.
    pub minor: u16,
    /// Dialect hash the image was encoded with.
    pub dialect_hash: u64,
    /// Whether the image re-encodes to the same bytes.
    pub canonical: bool,
    /// Content hash of the companion schema, when one was checked.
    pub schema_hash: Option<[u8; 32]>,
}

impl Proof {
    /// Issue a proof for a canonical image.
    pub fn issue(image: &[u8]) -> Result<Proof> {
        Proof::issue_with_schema(image, None)
    }

    /// Issue a proof and verify the image against a companion schema.
    ///
    /// The schema's own content hash is recorded so a verifier can require the
    /// exact schema that was used.
    pub fn issue_with_schema(image: &[u8], schema: Option<&[u8]>) -> Result<Proof> {
        let meta = validate_canonical(image, Limits::default())?;
        let schema_hash = match schema {
            Some(bytes) => {
                let schema = Schema::from_bytes(bytes)?;
                schema.validate_bytes(image)?;
                Some(content_hash(bytes)?)
            }
            None => None,
        };
        Ok(Proof::from_meta(&meta, schema_hash))
    }

    /// Verify that this proof describes `image`.
    ///
    /// When the proof records a schema hash, the matching schema bytes must be
    /// supplied and must still accept the image.
    pub fn verify(&self, image: &[u8]) -> Result<()> {
        self.verify_with_schema(image, None)
    }

    /// Verify a proof that may carry a schema hash.
    pub fn verify_with_schema(&self, image: &[u8], schema: Option<&[u8]>) -> Result<()> {
        let meta = validate_canonical(image, Limits::default())?;
        let actual = Proof::from_meta(&meta, self.schema_hash);
        if actual.content_hash != self.content_hash {
            return Err(Error::Proof("content hash differs"));
        }
        if actual.size != self.size
            || actual.nodes != self.nodes
            || actual.edges != self.edges
            || actual.secrets != self.secrets
            || actual.major != self.major
            || actual.minor != self.minor
            || actual.dialect_hash != self.dialect_hash
        {
            return Err(Error::Proof("metadata differs"));
        }
        match (self.schema_hash, schema) {
            (Some(expected), Some(bytes)) => {
                let actual = content_hash(bytes)?;
                if actual != expected {
                    return Err(Error::Proof("schema hash differs"));
                }
                let schema = Schema::from_bytes(bytes)?;
                schema.validate_bytes(image)?;
            }
            (Some(_), None) => {
                return Err(Error::Proof("the proof requires its companion schema"));
            }
            (None, Some(_)) => {
                return Err(Error::Proof("the proof carries no schema hash"));
            }
            (None, None) => {}
        }
        Ok(())
    }

    /// Whether the image carries secret values and therefore must be redacted
    /// on every projection.
    pub fn requires_redaction(&self) -> bool {
        self.secrets > 0
    }

    /// Render the sidecar as JSON.
    #[cfg(feature = "json")]
    pub fn to_json(&self) -> String {
        let mut map = serde_json::Map::new();
        map.insert("format".to_string(), PROOF_FORMAT.into());
        map.insert("content_hash".to_string(), hex(&self.content_hash).into());
        map.insert("size".to_string(), self.size.into());
        map.insert("nodes".to_string(), self.nodes.into());
        map.insert("edges".to_string(), self.edges.into());
        map.insert("secrets".to_string(), self.secrets.into());
        map.insert("major".to_string(), self.major.into());
        map.insert("minor".to_string(), self.minor.into());
        map.insert("dialect_hash".to_string(), self.dialect_hash.into());
        map.insert("canonical".to_string(), self.canonical.into());
        map.insert(
            "schema_hash".to_string(),
            match self.schema_hash {
                Some(hash) => serde_json::Value::String(hex(&hash)),
                None => serde_json::Value::Null,
            },
        );
        serde_json::Value::Object(map).to_string()
    }

    /// Parse a JSON sidecar.
    #[cfg(feature = "json")]
    pub fn from_json(text: &str) -> Result<Proof> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|_| Error::Proof("sidecar is not JSON"))?;
        if value.get("format").and_then(|v| v.as_str()) != Some(PROOF_FORMAT) {
            return Err(Error::Proof("unknown sidecar format"));
        }
        let hash = value
            .get("content_hash")
            .and_then(|v| v.as_str())
            .ok_or(Error::Proof("missing content hash"))?;
        let content_hash = parse_hex32(hash)?;
        let number = |key: &str| -> Result<u64> {
            value
                .get(key)
                .and_then(|v| v.as_u64())
                .ok_or(Error::Proof("missing numeric field"))
        };
        let u32_field = |key: &str| -> Result<u32> {
            u32::try_from(number(key)?).map_err(|_| Error::Proof("field out of range"))
        };
        let schema_hash = match value.get("schema_hash") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(text)) => Some(parse_hex32(text)?),
            Some(_) => return Err(Error::Proof("schema hash is not a string")),
        };
        Ok(Proof {
            content_hash,
            size: number("size")?,
            nodes: u32_field("nodes")?,
            edges: u32_field("edges")?,
            secrets: u32_field("secrets")?,
            major: u16::try_from(number("major")?)
                .map_err(|_| Error::Proof("major out of range"))?,
            minor: u16::try_from(number("minor")?)
                .map_err(|_| Error::Proof("minor out of range"))?,
            dialect_hash: number("dialect_hash")?,
            canonical: value
                .get("canonical")
                .and_then(|v| v.as_bool())
                .ok_or(Error::Proof("missing canonical flag"))?,
            schema_hash,
        })
    }

    fn from_meta(meta: &Meta, schema_hash: Option<[u8; 32]>) -> Proof {
        Proof {
            content_hash: meta.content_hash,
            size: meta.total_size,
            nodes: meta.nodes,
            edges: meta.edges,
            secrets: meta.secrets,
            major: meta.major,
            minor: meta.minor,
            dialect_hash: meta.dialect_hash,
            canonical: true,
            schema_hash,
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_hex32(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 {
        return Err(Error::Proof("hash must be 64 hex characters"));
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| Error::Proof("hash is not hex"))?;
    }
    Ok(out)
}
