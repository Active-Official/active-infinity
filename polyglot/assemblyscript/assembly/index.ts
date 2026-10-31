// Active Infinity for AssemblyScript.
//
// AssemblyScript cannot host another WASM module directly, so this module is the
// typed shim: it forwards pointers into its own linear memory to host functions
// that the loader binds to the shared reference module. The loader
// (`host.js`) copies across the boundary; the codec, hashes and redaction stay
// in the Rust reference.

@external("active_infinity", "validate")
declare function hostValidate(pointer: usize, length: usize): i32;

@external("active_infinity", "content_hash")
declare function hostHash(pointer: usize, length: usize, output: usize): i32;

@external("active_infinity", "reencode")
declare function hostReencode(
  pointer: usize,
  length: usize,
  output: usize,
  outputLength: usize,
): i32;

@external("active_infinity", "redacted_json")
declare function hostRedactedJson(
  pointer: usize,
  length: usize,
  output: usize,
  outputLength: usize,
): i32;

@external("active_infinity", "from_active")
declare function hostFromActive(
  source: usize,
  sourceLength: usize,
  name: usize,
  nameLength: usize,
  output: usize,
  outputLength: usize,
): i32;

// Buffers handed to the host must stay alive while the call runs.
const retained: Uint8Array[] = [];

export function abiVersion(): i32 {
  return 1;
}

/** Allocate `length` bytes and retain them until `releaseAll`. */
export function allocate(length: i32): usize {
  const buffer = new Uint8Array(length);
  retained.push(buffer);
  return buffer.dataStart;
}

export function releaseAll(): void {
  retained.length = 0;
}

export function validate(pointer: usize, length: i32): i32 {
  return hostValidate(pointer, length);
}

export function contentHash(pointer: usize, length: i32, output: usize): i32 {
  return hostHash(pointer, length, output);
}

export function reencode(pointer: usize, length: i32, output: usize, outputLength: usize): i32 {
  return hostReencode(pointer, length, output, outputLength);
}

export function redactedJson(pointer: usize, length: i32, output: usize, outputLength: usize): i32 {
  return hostRedactedJson(pointer, length, output, outputLength);
}

export function fromActive(
  source: usize,
  sourceLength: i32,
  name: usize,
  nameLength: i32,
  output: usize,
  outputLength: usize,
): i32 {
  return hostFromActive(source, sourceLength, name, nameLength, output, outputLength);
}
