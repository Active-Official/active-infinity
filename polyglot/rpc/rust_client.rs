//! Thin Active RPC client over native ARP1 on TCP, standard library only.
//!
//! This is the Rust row of the thin-client matrix: it encodes and decodes ARP1
//! by hand, without `active_rpc`, so it is an independent implementation of the
//! wire format rather than a second use of the kernel's codec.
//!
//! ```text
//! ACTIVE_RPC_ADDR=127.0.0.1:54321 \
//! ACTIVE_RPC_CAP=<32 hex chars> \
//! ACTIVE_RPC_PAYLOAD=tests/vectors/valid/full.ainf \
//! rustc -O polyglot/rpc/rust_client.rs -o /tmp/rpc-client-rust && /tmp/rpc-client-rust
//! ```

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::time::Duration;

const MAGIC: &[u8; 4] = b"ARP1";
const VERSION: u8 = 1;
const KIND_REQUEST: u8 = 1;
const KIND_RESPONSE: u8 = 2;
const KIND_ERROR: u8 = 3;

/// Default budget ceilings, in the descriptor's fixed order.
const BUDGET: [u64; 7] = [
    10_000,
    64 * 1024 * 1024,
    5_000,
    100_000,
    256,
    100_000,
    10_000_000,
];

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_str(out: &mut Vec<u8>, text: &str) {
    put_u32(out, text.len() as u32);
    out.extend_from_slice(text.as_bytes());
}

fn put_descriptor(out: &mut Vec<u8>, cap: [u8; 16]) {
    out.extend_from_slice(&cap);
    put_u32(out, 1);
    put_str(out, "echo");
    for ceiling in BUDGET {
        put_u64(out, ceiling);
    }
    out.push(0); // read_only
    out.push(0); // redact
    out.push(0); // no path scope
}

fn request(id: u64, method: &str, payload: &[u8], cap: Option<[u8; 16]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + payload.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(KIND_REQUEST);
    put_u16(&mut out, 0); // flags
    put_u64(&mut out, id);
    put_str(&mut out, method);
    put_u32(&mut out, 0); // no arguments
    put_u32(&mut out, payload.len() as u32);
    out.extend_from_slice(payload);
    match cap {
        None => put_u32(&mut out, 0),
        Some(id) => {
            put_u32(&mut out, 1);
            put_descriptor(&mut out, id);
        }
    }
    out
}

fn read_u32(data: &[u8], cursor: usize) -> io::Result<u32> {
    data.get(cursor..cursor + 4)
        .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated u32"))
}

fn read_u64(data: &[u8], cursor: usize) -> io::Result<u64> {
    let slice = data
        .get(cursor..cursor + 8)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated u64"))?;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(slice);
    Ok(u64::from_le_bytes(bytes))
}

/// Skip one value body, returning the cursor after it.
fn skip_value(data: &[u8], mut cursor: usize) -> io::Result<usize> {
    let tag = *data
        .get(cursor)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated value"))?;
    cursor += 1;
    match tag {
        0 | 7 => Ok(cursor),     // null, secret
        1 => Ok(cursor + 1),     // bool
        2 | 3 => Ok(cursor + 8), // int, float
        4 | 8 | 9 => {
            // text, module, path
            let length = read_u32(data, cursor)? as usize;
            Ok(cursor + 4 + length)
        }
        5 => {
            // list
            let count = read_u32(data, cursor)? as usize;
            cursor += 4;
            for _ in 0..count {
                cursor = skip_value(data, cursor)?;
            }
            Ok(cursor)
        }
        6 => {
            // map
            let count = read_u32(data, cursor)? as usize;
            cursor += 4;
            for _ in 0..count {
                let key = read_u32(data, cursor)? as usize;
                cursor += 4 + key;
                cursor = skip_value(data, cursor)?;
            }
            Ok(cursor)
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown value tag {other}"),
        )),
    }
}

struct Envelope {
    kind: u8,
    request_id: u64,
    method: String,
    payload: Vec<u8>,
}

fn decode(body: &[u8]) -> io::Result<Envelope> {
    if body.len() < 20 || &body[0..4] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad envelope magic",
        ));
    }
    if body[4] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad envelope version",
        ));
    }
    let kind = body[5];
    let request_id = read_u64(body, 8)?;
    let method_len = read_u32(body, 16)? as usize;
    let method_bytes = body
        .get(20..20 + method_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated method"))?;
    let method = String::from_utf8_lossy(method_bytes).into_owned();
    let mut cursor = 20 + method_len;
    let args = read_u32(body, cursor)? as usize;
    cursor += 4;
    for _ in 0..args {
        let tag = *body
            .get(cursor)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated argument"))?;
        cursor += 1;
        match tag {
            0 => cursor = skip_value(body, cursor)?,
            1 => cursor += 8,
            2 => cursor += 16,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown argument tag {other}"),
                ))
            }
        }
    }
    let payload_len = read_u32(body, cursor)? as usize;
    cursor += 4;
    let payload = body
        .get(cursor..cursor + payload_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated payload"))?
        .to_vec();
    Ok(Envelope {
        kind,
        request_id,
        method,
        payload,
    })
}

fn call(address: &str, envelope: &[u8]) -> io::Result<Envelope> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut frame = Vec::with_capacity(4 + envelope.len());
    put_u32(&mut frame, envelope.len() as u32);
    frame.extend_from_slice(envelope);
    stream.write_all(&frame)?;
    stream.flush()?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_le_bytes(header) as usize;
    if length > 64 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds the ceiling",
        ));
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    decode(&body)
}

fn parse_cap(text: &str) -> Result<[u8; 16], String> {
    if text.len() != 32 {
        return Err("ACTIVE_RPC_CAP must be 32 hex characters".to_string());
    }
    let mut id = [0u8; 16];
    for (index, slot) in id.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| "ACTIVE_RPC_CAP is not hex".to_string())?;
    }
    Ok(id)
}

fn run() -> Result<(), String> {
    let address = env::var("ACTIVE_RPC_ADDR").map_err(|_| "ACTIVE_RPC_ADDR is required")?;
    let cap_text = env::var("ACTIVE_RPC_CAP").map_err(|_| "ACTIVE_RPC_CAP is required")?;
    let payload_path = env::var("ACTIVE_RPC_PAYLOAD")
        .unwrap_or_else(|_| "tests/vectors/valid/full.ainf".to_string());
    let payload = fs::read(&payload_path).map_err(|error| format!("payload: {error}"))?;
    let cap = parse_cap(&cap_text)?;
    let io_error = |error: io::Error| format!("transport: {error}");

    let echoed = call(&address, &request(42, "echo", &payload, Some(cap))).map_err(io_error)?;
    if echoed.kind != KIND_RESPONSE || echoed.request_id != 42 {
        return Err(format!(
            "echo: kind {} id {}",
            echoed.kind, echoed.request_id
        ));
    }
    if echoed.payload != payload {
        return Err("echo: the AINF payload was not echoed".to_string());
    }

    let refused = call(&address, &request(43, "refuse", &payload, Some(cap))).map_err(io_error)?;
    if refused.kind != KIND_ERROR || refused.method != "rpc/method-not-granted" {
        return Err(format!(
            "refusal: kind {} method {}",
            refused.kind, refused.method
        ));
    }

    let anonymous = call(&address, &request(44, "echo", &payload, None)).map_err(io_error)?;
    if anonymous.kind != KIND_ERROR || anonymous.method != "rpc/unknown-capability" {
        return Err(format!(
            "missing capability: kind {} method {}",
            anonymous.kind, anonymous.method
        ));
    }

    println!("Rust thin RPC PASS (echo, refusal, missing capability)");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
