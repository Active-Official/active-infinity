/**
 * Active Infinity for JavaScript (Node and browsers).
 *
 * A thin wrapper over the shared WASM module: one canonicalizer, one validator,
 * one content hash. A failure throws `ActiveInfinityError` with the stable
 * `infinity/...` code.
 */

const ABI_VERSION = 1;

class ActiveInfinityError extends Error {
	constructor(code, status) {
		super(`${code} (status ${status})`);
		this.name = "ActiveInfinityError";
		this.code = code;
		this.status = status;
	}
}

// INF-FFI-02: caller-supplied budget. A Limits holds the 112-byte C
// `active_infinity_limits` struct in WASM memory: 21 uint32 ceilings,
// then max_total_bytes and max_decoded_bytes (uint64, at offsets 88 and
// 96), then max_depth (uint32, at offset 104). Build one with
// `Limits.defaults(ai)`, set a ceiling with `set(field, value)`, pass it
// to `validateWithLimits` / `decodeWithLimits`, and free it with `free()`.
// The offsets are the ABI: the struct layout is fixed by the C header.
const LIMITS_SIZE = 112;
const LIMITS_FIELDS = {
	max_nodes: [0, "u32"],
	max_edges: [4, "u32"],
	max_children: [8, "u32"],
	max_fields: [12, "u32"],
	max_parts: [16, "u32"],
	max_strings: [20, "u32"],
	max_string_bytes: [24, "u32"],
	max_blobs: [28, "u32"],
	max_blob_bytes: [32, "u32"],
	max_annotations: [36, "u32"],
	max_units: [40, "u32"],
	max_types: [44, "u32"],
	max_aux: [48, "u32"],
	max_numbers: [52, "u32"],
	max_secrets: [56, "u32"],
	max_secret_bytes: [60, "u32"],
	max_extensions: [64, "u32"],
	max_prov_bytes: [68, "u32"],
	max_prov_entries: [72, "u32"],
	max_hashes: [76, "u32"],
	max_bindings: [80, "u32"],
	max_total_bytes: [88, "u64"],
	max_decoded_bytes: [96, "u64"],
	max_depth: [104, "u32"],
};

class Limits {
	constructor(ai, pointer) {
		this.ai = ai;
		this.pointer = pointer;
	}

	static defaults(ai) {
		const pointer = ai._alloc(LIMITS_SIZE);
		const status = ai.exports.active_infinity_limits_default(pointer);
		if (status !== 0) {
			ai.exports.active_infinity_free(pointer, LIMITS_SIZE);
			ai._fail(status);
		}
		return new Limits(ai, pointer);
	}

	set(field, value) {
		const entry = LIMITS_FIELDS[field];
		if (!entry) throw new Error(`unknown limits field ${field}`);
		const [offset, kind] = entry;
		const view = new DataView(this.ai.memory.buffer, this.pointer + offset, 8);
		if (kind === "u64") view.setBigUint64(0, BigInt(value), true);
		else view.setUint32(0, value, true);
		return this;
	}

	free() {
		if (this.pointer !== 0) {
			this.ai.exports.active_infinity_free(this.pointer, LIMITS_SIZE);
			this.pointer = 0;
		}
	}
}

class ActiveInfinity {
	constructor(instance) {
		this.exports = instance.exports;
		this.memory = instance.exports.memory;
		const abi = this.exports.active_infinity_abi_version();
		if (abi !== ABI_VERSION) {
			throw new Error(`ABI mismatch: module ${abi}, wrapper ${ABI_VERSION}`);
		}
	}

	/**
	 * Instantiate from bytes (Uint8Array/ArrayBuffer) or a URL/path when the
	 * runtime supports `fetch`/fs loading through the caller.
	 */
	static async instantiate(bytes) {
		const imports = { env: {} };
		const module = await WebAssembly.compile(bytes);
		// The callback needs the instance memory, which does not exist until
		// instantiation. Resolve it lazily through the instance object below.
		let instanceRef = null;
		imports.env.active_random_fill = (dest, len) => {
			// INF-POLY-01: WebCrypto caps one getRandomValues call at
			// 65,536 bytes; a larger fill threw QuotaExceededError into
			// the WASM import and trapped the instance. Chunk at the cap
			// and return non-zero on any failure -- the Rust side treats
			// non-zero as a clean getrandom error. (Keep in sync with the
			// twin in polyglot/assemblyscript/host.js.)
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
		};
		const instance = await WebAssembly.instantiate(module, imports);
		instanceRef = instance;
		return new ActiveInfinity(instance);
	}

	_lastError() {
		const pointer = this.exports.active_infinity_last_error();
		// A null error pointer means "unavailable", not address zero: scanning
		// from zero would return arbitrary module memory as an error string.
		if (!pointer) return "infinity/unknown";
		const memory = new Uint8Array(this.memory.buffer);
		let end = pointer;
		while (end < memory.length && memory[end] !== 0) end += 1;
		return new TextDecoder().decode(memory.subarray(pointer, end));
	}

	_fail(status) {
		throw new ActiveInfinityError(this._lastError(), status);
	}

	_alloc(length) {
		const pointer = this.exports.active_infinity_alloc(length);
		// A null pointer is the FFI's refusal (1 GiB cap), not address zero.
		if (pointer === 0 && length > 0) {
			throw new ActiveInfinityError("infinity/limit", -1);
		}
		return pointer;
	}

	_withInput(bytes, op) {
		const input = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
		const pointer = input.length === 0 ? 0 : this._alloc(input.length);
		try {
			if (input.length > 0) {
				new Uint8Array(this.memory.buffer, pointer, input.length).set(input);
			}
			return op(pointer, input.length);
		} finally {
			if (pointer !== 0)
				this.exports.active_infinity_free(pointer, input.length);
		}
	}

	_output(pointer, capacity) {
		const view = new Uint8Array(this.memory.buffer, pointer, capacity);
		return new Uint8Array(view);
	}

	/** True when the image is structurally valid; otherwise throws. */
	validate(bytes) {
		const status = this._withInput(bytes, (pointer, length) =>
			this.exports.active_infinity_validate(pointer, length),
		);
		if (status !== 0) this._fail(status);
		return true;
	}

	/**
	 * True when the image is the canonical encoding of its own content;
	 * otherwise throws. `validate` already proves this (INF-02); this
	 * states the requirement explicitly. (INF-POLY-03)
	 */
	validateCanonical(bytes) {
		const status = this._withInput(bytes, (pointer, length) =>
			this.exports.active_infinity_validate_canonical(pointer, length),
		);
		if (status !== 0) this._fail(status);
		return true;
	}

	/**
	 * True when the image is the canonical encoding of its own content
	 * under the caller's budget; otherwise throws. A null limits means the
	 * library defaults. (INF-FFI-02)
	 */
	validateWithLimits(bytes, limits = null) {
		const status = this._withInput(bytes, (pointer, length) =>
			this.exports.active_infinity_validate_with_limits(
				pointer,
				length,
				limits === null ? 0 : limits.pointer,
			),
		);
		if (status !== 0) this._fail(status);
		return true;
	}

	/** Canonical AINF bytes for a valid image, under the caller's budget. */
	decodeWithLimits(bytes, limits = null) {
		return this._withInput(bytes, (pointer, length) =>
			this._callOutput((out, outLen) =>
				this.exports.active_infinity_decode_with_limits(
					pointer,
					length,
					limits === null ? 0 : limits.pointer,
					out,
					outLen,
					),
			),
		);
	}

	/** 32-byte Blake3 content hash of a valid image. */
	contentHash(bytes) {
		const hashPointer = this._alloc(32);
		try {
			const status = this._withInput(bytes, (pointer, length) =>
				this.exports.active_infinity_content_hash(pointer, length, hashPointer),
			);
			if (status !== 0) this._fail(status);
			return this._output(hashPointer, 32);
		} finally {
			this.exports.active_infinity_free(hashPointer, 32);
		}
	}

	/** Canonical AINF bytes for a valid image. */
	reencode(bytes) {
		return this._withInput(bytes, (pointer, length) =>
			this._callOutput((out, outLen) =>
				this.exports.active_infinity_reencode(pointer, length, out, outLen),
			),
		);
	}

	/** Compile Active text into canonical AINF. */
	fromActive(source, name = "module.active") {
		const text =
			typeof source === "string" ? new TextEncoder().encode(source) : source;
		const nameBytes = new TextEncoder().encode(`${name}\0`);
		const namePointer = this._alloc(nameBytes.length);
		new Uint8Array(this.memory.buffer, namePointer, nameBytes.length).set(
			nameBytes,
		);
		try {
			return this._withInput(text, (pointer, length) =>
				this._callOutput((out, outLen) =>
					this.exports.active_infinity_from_active(
						pointer,
						length,
						namePointer,
						out,
						outLen,
					),
				),
			);
		} finally {
			this.exports.active_infinity_free(namePointer, nameBytes.length);
		}
	}

	/** Redacted JSON projection; secret values become ***SECRET***. */
	redactedJson(bytes) {
		const output = this._withInput(bytes, (pointer, length) =>
			this._callOutput((out, outLen) =>
				this.exports.active_infinity_redacted_json(
					pointer,
					length,
					out,
					outLen,
				),
			),
		);
		return new TextDecoder().decode(output);
	}

	_callOutput(invoke) {
		// Size query: a null output reports the required length.
		const lengthPointer = this._alloc(8);
		try {
			new DataView(this.memory.buffer, lengthPointer, 8).setUint32(0, 0, true);
			let status = invoke(0, lengthPointer);
			const required = new DataView(
				this.memory.buffer,
				lengthPointer,
				8,
			).getUint32(0, true);
			if (status !== -2 || required === 0) {
				if (status !== 0) this._fail(status);
				return new Uint8Array(0);
			}
			const outputPointer = this._alloc(required);
			try {
				new DataView(this.memory.buffer, lengthPointer, 8).setUint32(
					0,
					required,
					true,
				);
				status = invoke(outputPointer, lengthPointer);
				if (status !== 0) this._fail(status);
				const written = new DataView(
					this.memory.buffer,
					lengthPointer,
					8,
				).getUint32(0, true);
				return this._output(outputPointer, written);
			} finally {
				this.exports.active_infinity_free(outputPointer, required);
			}
		} finally {
			this.exports.active_infinity_free(lengthPointer, 8);
		}
	}
}

module.exports = { ActiveInfinity, ActiveInfinityError, Limits, ABI_VERSION };
