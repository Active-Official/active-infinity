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
			const buffer = new Uint8Array(
				instanceRef.exports.memory.buffer,
				dest,
				len,
			);
			crypto.getRandomValues(buffer);
			return 0;
		};
		const instance = await WebAssembly.instantiate(module, imports);
		instanceRef = instance;
		return new ActiveInfinity(instance);
	}

	_lastError() {
		const pointer = this.exports.active_infinity_last_error();
		const memory = new Uint8Array(this.memory.buffer);
		let end = pointer;
		while (end < memory.length && memory[end] !== 0) end += 1;
		return new TextDecoder().decode(memory.subarray(pointer, end));
	}

	_fail(status) {
		throw new ActiveInfinityError(this._lastError(), status);
	}

	_withInput(bytes, op) {
		const input = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
		const pointer =
			input.length === 0 ? 0 : this.exports.active_infinity_alloc(input.length);
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

	/** 32-byte Blake3 content hash of a valid image. */
	contentHash(bytes) {
		const hashPointer = this.exports.active_infinity_alloc(32);
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
		const namePointer = this.exports.active_infinity_alloc(nameBytes.length);
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
		const lengthPointer = this.exports.active_infinity_alloc(8);
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
			const outputPointer = this.exports.active_infinity_alloc(required);
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

module.exports = { ActiveInfinity, ActiveInfinityError, ABI_VERSION };
