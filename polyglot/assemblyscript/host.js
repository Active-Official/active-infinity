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
					const buffer = new Uint8Array(
						instanceRef.exports.memory.buffer,
						dest,
						len,
					);
					crypto.getRandomValues(buffer);
					return 0;
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
		const memory = this.memory();
		let end = pointer;
		while (end < memory.length && memory[end] !== 0) end += 1;
		return new TextDecoder().decode(memory.subarray(pointer, end));
	}
}

function bind(reference, getAssemblyMemory) {
	const asMemory = () => new Uint8Array(getAssemblyMemory().buffer);
	const copyFromAs = (pointer, length) => {
		if (length === 0) return 0;
		return reference.copyIn(asMemory().subarray(pointer, pointer + length));
	};
	const writeToAs = (pointer, bytes) => {
		asMemory().set(bytes, pointer);
	};
	const writeU32 = (pointer, value) => {
		new DataView(getAssemblyMemory().buffer).setUint32(pointer, value, true);
	};

	const runOutput = (input, inputLength, output, outputLength, invoke) => {
		const sizePointer = reference.alloc(8);
		try {
			reference.setU32(sizePointer, 0);
			let status = invoke(0, sizePointer);
			const required = reference.u32(sizePointer);
			writeU32(outputLength, required);
			if (status !== -2) return status;
			const buffer = reference.alloc(required);
			try {
				reference.setU32(sizePointer, required);
				status = invoke(buffer, sizePointer);
				if (status !== 0) return status;
				const written = reference.u32(sizePointer);
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
					return reference.exports.active_infinity_validate(input, length);
				} finally {
					reference.free(input, length);
				}
			},
			content_hash: (pointer, length, output) => {
				const input = copyFromAs(pointer, length);
				const hash = reference.alloc(32);
				try {
					const status = reference.exports.active_infinity_content_hash(
						input,
						length,
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
					reference.free(input, length);
				}
			},
			reencode: (pointer, length, output, outputLength) => {
				const input = copyFromAs(pointer, length);
				try {
					return runOutput(
						input,
						length,
						output,
						outputLength,
						(buffer, size) =>
							reference.exports.active_infinity_reencode(
								input,
								length,
								buffer,
								size,
							),
					);
				} finally {
					reference.free(input, length);
				}
			},
			redacted_json: (pointer, length, output, outputLength) => {
				const input = copyFromAs(pointer, length);
				try {
					return runOutput(
						input,
						length,
						output,
						outputLength,
						(buffer, size) =>
							reference.exports.active_infinity_redacted_json(
								input,
								length,
								buffer,
								size,
							),
					);
				} finally {
					reference.free(input, length);
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
				const nameBytes = asMemory().slice(name, name + nameLength);
				const nameWithNul = new Uint8Array(nameBytes.length + 1);
				nameWithNul.set(nameBytes);
				const namePointer = reference.copyIn(nameWithNul);
				try {
					return runOutput(
						input,
						sourceLength,
						output,
						outputLength,
						(buffer, size) =>
							reference.exports.active_infinity_from_active(
								input,
								sourceLength,
								namePointer,
								buffer,
								size,
							),
					);
				} finally {
					reference.free(namePointer, nameWithNul.length);
					reference.free(input, sourceLength);
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
