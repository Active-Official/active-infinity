/**
 * Shared AssemblyScript encoder glue for the thin RPC client and its golden
 * vector test.
 *
 * The AS module (`as_request.ts`) owns the byte layout; this host code only
 * allocates, copies and reads back. `as_client.js` and `as_golden.js` both go
 * through `encodeRequest`, so a golden mismatch points at the module.
 */

const fs = require("node:fs");

async function loadEncoder(wasmPath) {
	const imports = {
		env: {
			abort: (message, file, line, column) => {
				throw new Error(
					`AssemblyScript abort at ${file}:${line}:${column}: ${message}`,
				);
			},
		},
	};
	const { instance } = await WebAssembly.instantiate(
		fs.readFileSync(wasmPath),
		imports,
	);
	return instance.exports;
}

function writeBytes(memory, pointer, bytes) {
	new Uint8Array(memory.buffer, pointer, bytes.length).set(bytes);
}

/**
 * Encode one ARP1 request through the AssemblyScript module.
 *
 * Returns a copy: later allocations can grow the module memory and detach the
 * views taken here.
 */
function encodeRequest(exports, { id, method, payload, capId, capMethods }) {
	const memory = exports.memory;
	const methodBytes = Buffer.from(method, "utf8");
	const cap = capId ? Buffer.from(capId, "hex") : null;
	if (cap && cap.length !== 16)
		throw new Error("capability id must be 32 hex characters");

	const methodPointer = exports.allocate(methodBytes.length);
	writeBytes(memory, methodPointer, methodBytes);
	const payloadPointer = exports.allocate(payload.length);
	writeBytes(memory, payloadPointer, payload);
	let capPointer = 0;
	let methodsPointer = 0;
	let methodsLength = 0;
	let methodsCount = 0;
	if (cap) {
		capPointer = exports.allocate(cap.length);
		writeBytes(memory, capPointer, cap);
		const methods = capMethods || ["echo"];
		const parts = [];
		for (const name of methods) {
			const bytes = Buffer.from(name, "utf8");
			const length = Buffer.alloc(4);
			length.writeUInt32LE(bytes.length);
			parts.push(length, bytes);
		}
		const blob = Buffer.concat(parts);
		methodsPointer = exports.allocate(blob.length);
		writeBytes(memory, methodsPointer, blob);
		methodsLength = blob.length;
		methodsCount = methods.length;
	}
	const outCapacity = payload.length + 4096;
	const outPointer = exports.allocate(outCapacity);

	const length = exports.buildRequest(
		BigInt(id),
		methodPointer,
		methodBytes.length,
		payloadPointer,
		payload.length,
		capPointer,
		methodsPointer,
		methodsCount,
		methodsLength,
		outPointer,
		outCapacity,
	);
	if (length <= 0)
		throw new Error(
			`AssemblyScript encoded ${length} bytes (buffer too small)`,
		);
	return Buffer.from(new Uint8Array(memory.buffer, outPointer, length));
}

module.exports = { loadEncoder, encodeRequest };
