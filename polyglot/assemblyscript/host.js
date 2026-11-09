/**
 * AssemblyScript host: binds the AS shim to the shared reference WASM module.
 *
 * The host owns both linear memories. For each call it copies the input from
 * the AS memory into the reference module, invokes the reference, and copies
 * the result back. The codec, hashes and redaction stay in the Rust reference.
 */

const fs = require("node:fs");

class Reference {
	constructor(instance) {
		this.exports = instance.exports;
		this.memory = () => new Uint8Array(instance.exports.memory.buffer);
	}

	static async load(bytes) {
		let instanceRef = null;
		const imports = {
			env: {
				active_random_fill: (dest, len) => {
					// INF-POLY-01: WebCrypto caps one getRandomValues call at
					// 65,536 bytes; a larger fill threw QuotaExceededError into
					// the WASM import and trapped the instance. Chunk at the cap
					// and return non-zero on any failure -- the Rust side treats
					// non-zero as a clean getrandom error. (Keep in sync with the
					// twin in polyglot/js/active-infinity.js.)
					try {
						for (let offset = 0; offset < len; offset += 65536) {
							const chunk = Math.min(65536, len - offset);
							crypto.getRandomValues(
								new Uint8Array(
									instanceRef.exports.memory.buffer,
									dest + offset,
									chunk,
								),
						);
						}
						return 0;
					} catch {
						return 1;
					}
				},
			},
		};
		const { instance } = await WebAssembly.instantiate(bytes, imports);
		instanceRef = instance;
		return new Reference(instance);
	}

	alloc(length) {
		return this.exports.active_infinity_alloc(length);
	}

	free(pointer, length) {
		if (pointer !== 0) this.exports.active_infinity_free(pointer, length);
	}

	copyIn(bytes) {
		if (bytes.length === 0) return 0;
		const pointer = this.alloc(bytes.length);
		if (!pointer) throw new Error("infinity/limit: allocation failed");
		this.memory().set(bytes, pointer);
		return pointer;
	}

	u32(pointer) {
		return new DataView(this.exports.memory.buffer).getUint32(pointer, true);
	}

	setU32(pointer, value) {
		new DataView(this.exports.memory.buffer).setUint32(pointer, value, true);
	}

	lastError() {
		const pointer = this.exports.active_infinity_last_error();
		// A null error pointer means "unavailable", not address zero: scanning
		// from zero would return arbitrary module memory as an error string.
		if (!pointer) return "infinity/unknown";
		const memory = this.memory();
		let end = pointer;
		while (end < memory.length && memory[end] !== 0) end += 1;
		return new TextDecoder().decode(memory.subarray(pointer, end));
	}
}

function bind(reference, getAssemblyMemory) {
	const asMemory = () => new Uint8Array(getAssemblyMemory().buffer);
	// Copy an AssemblyScript range into the reference. The range is clipped to
	// the AssemblyScript heap and the *clipped* length is returned: passing the
	// caller's length would make the reference read past its own allocation.
	const copyFromAs = (pointer, length) => {
		if (length === 0) return { pointer: 0, length: 0 };
		if (!Number.isInteger(length) || length < 0 || length > 0x7fffffff) {
			// A negative or oversized length is a caller bug, not a heap range.
			throw new Error("infinity/limit: length out of range");
		}
		if (!pointer) {
			// Address zero is not a buffer. Hand the null pointer to the
			// reference so the caller gets infinity/null-input, never a read of
			// the module's static data.
			return { pointer: 0, length };
		}
		const view = asMemory();
		const end = Math.min(pointer + length, view.length);
		const slice = view.subarray(pointer, Math.max(pointer, end));
		return { pointer: reference.copyIn(slice), length: slice.length };
	};
	const allocOrThrow = (length) => {
		const pointer = reference.alloc(length);
		if (!pointer && length > 0) {
			throw new Error("infinity/limit: allocation failed");
		}
		return pointer;
	};
	const writeToAs = (pointer, bytes) => {
		asMemory().set(bytes, pointer);
	};
	const writeU32 = (pointer, value) => {
		new DataView(getAssemblyMemory().buffer).setUint32(pointer, value, true);
	};
	const readU32 = (pointer) => {
		return new DataView(getAssemblyMemory().buffer).getUint32(pointer, true);
	};

	const runOutput = (input, inputLength, output, outputLength, invoke) => {
		if (!outputLength) {
			// A null out_len cannot carry a size. Let the reference refuse it
			// (infinity/null-out-len) instead of writing at AS address zero.
			return invoke(0, 0);
		}
		// The caller declares the capacity at *outputLength; a result larger than
		// that must be reported as -2 with the required size, never copied.
		const capacity = readU32(outputLength);
		const sizePointer = allocOrThrow(8);
		try {
			reference.setU32(sizePointer, 0);
			let status = invoke(0, sizePointer);
			const required = reference.u32(sizePointer);
			writeU32(outputLength, required);
			if (status !== -2) return status;
			if (required > capacity || !output) {
				// The caller must provide a real buffer with enough capacity; a
				// null pointer is not AS address zero.
				return -2;
			}
			const buffer = allocOrThrow(required);
			try {
				reference.setU32(sizePointer, required);
				status = invoke(buffer, sizePointer);
				if (status !== 0) return status;
				const written = Math.min(reference.u32(sizePointer), capacity);
				writeU32(outputLength, written);
				writeToAs(
					output,
					new Uint8Array(reference.exports.memory.buffer, buffer, written),
				);
				return 0;
			} finally {
				reference.free(buffer, required);
			}
		} finally {
			reference.free(sizePointer, 8);
		}
	};

	return {
		active_infinity: {
			validate: (pointer, length) => {
				const input = copyFromAs(pointer, length);
				try {
					return reference.exports.active_infinity_validate(
						input.pointer,
						input.length,
					);
				} finally {
					reference.free(input.pointer, input.length);
				}
			},
			// INF-POLY-03: `validate` already proves the canonical form
			// (INF-02); this states the requirement explicitly.
			validate_canonical: (pointer, length) => {
				const input = copyFromAs(pointer, length);
				try {
					return reference.exports.active_infinity_validate_canonical(
						input.pointer,
						input.length,
					);
				} finally {
					reference.free(input.pointer, input.length);
				}
			},
			content_hash: (pointer, length, output) => {
				const input = copyFromAs(pointer, length);
				try {
					if (!output) {
						// The reference owns this contract: a null 32-byte output
						// is infinity/null-output, never a silent success with an
						// unwritten hash.
						return reference.exports.active_infinity_content_hash(
							input.pointer,
							input.length,
							0,
						);
					}
					const hash = allocOrThrow(32);
					try {
						const status = reference.exports.active_infinity_content_hash(
							input.pointer,
							input.length,
							hash,
						);
						if (status === 0)
							writeToAs(
								output,
								new Uint8Array(reference.exports.memory.buffer, hash, 32),
							);
						return status;
					} finally {
						reference.free(hash, 32);
					}
				} finally {
					reference.free(input.pointer, input.length);
				}
			},
			reencode: (pointer, length, output, outputLength) => {
				const input = copyFromAs(pointer, length);
				try {
					return runOutput(
						input.pointer,
						input.length,
						output,
						outputLength,
						(buffer, size) =>
							reference.exports.active_infinity_reencode(
								input.pointer,
								input.length,
								buffer,
								size,
							),
					);
				} finally {
					reference.free(input.pointer, input.length);
				}
			},
			redacted_json: (pointer, length, output, outputLength) => {
				const input = copyFromAs(pointer, length);
				try {
					return runOutput(
						input.pointer,
						input.length,
						output,
						outputLength,
						(buffer, size) =>
							reference.exports.active_infinity_redacted_json(
								input.pointer,
								input.length,
								buffer,
								size,
							),
					);
				} finally {
					reference.free(input.pointer, input.length);
				}
			},
			from_active: (
				source,
				sourceLength,
				name,
				nameLength,
				output,
				outputLength,
			) => {
				const input = copyFromAs(source, sourceLength);
				if (
					!name ||
					!Number.isInteger(nameLength) ||
					nameLength < 0 ||
					nameLength > 4096
				) {
					// A missing, negative or oversized name range must not
					// silently become an empty name. The reference refuses the
					// null pointer with infinity/null-name.
					try {
						return reference.exports.active_infinity_from_active(
							input.pointer,
							input.length,
							0,
							0,
							0,
						);
					} finally {
						reference.free(input.pointer, input.length);
					}
				}
				const nameBytes = asMemory().slice(name, name + nameLength);
				const nameWithNul = new Uint8Array(nameBytes.length + 1);
				nameWithNul.set(nameBytes);
				const namePointer = reference.copyIn(nameWithNul);
				try {
					return runOutput(
						input.pointer,
						input.length,
						output,
						outputLength,
						(buffer, size) =>
							reference.exports.active_infinity_from_active(
								input.pointer,
								input.length,
								namePointer,
								buffer,
								size,
							),
					);
				} finally {
					reference.free(namePointer, nameWithNul.length);
					reference.free(input.pointer, input.length);
				}
			},
		},
	};
}

async function load(referenceWasm, assemblyWasm) {
	const reference = await Reference.load(fs.readFileSync(referenceWasm));
	let assembly = null;
	const imports = bind(reference, () => assembly.exports.memory);
	imports.env = {
		abort: (message, file, line, column) => {
			throw new Error(
				`AssemblyScript abort at ${file}:${line}:${column}: ${message}`,
			);
		},
	};
	const { instance } = await WebAssembly.instantiate(
		fs.readFileSync(assemblyWasm),
		imports,
	);
	assembly = instance;
	return { reference, assembly };
}

module.exports = { load, Reference };
