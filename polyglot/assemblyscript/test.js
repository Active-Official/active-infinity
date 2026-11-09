/**
 * AssemblyScript conformance test.
 *
 * Build the AS module first:
 *   npx --yes -p assemblyscript@0.27.31 asc \
 *     polyglot/assemblyscript/assembly/index.ts \
 *     -o polyglot/assemblyscript/build/conformance.wasm --optimize
 *
 * Then, from the repository root:
 *   node polyglot/assemblyscript/test.js
 */

const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const { load } = require("./host");

const ROOT = path.resolve(__dirname, "..", "..");
const REFERENCE = path.join(
	ROOT,
	"ffi",
	"active-infinity-ffi",
	"target",
	"wasm32-unknown-unknown",
	"release",
	"active_infinity_ffi.wasm",
);
const ASSEMBLY = path.join(__dirname, "build", "conformance.wasm");

async function main() {
	const { reference, assembly } = await load(REFERENCE, ASSEMBLY);
	const exports = assembly.exports;
	const memory = () => new Uint8Array(exports.memory.buffer);
	assert.strictEqual(exports.abiVersion(), 1);
	// A negative allocation request is the null pointer, not an allocator trap.
	assert.strictEqual(exports.allocate(-1), 0, "a negative allocation is null");

	const alloc = (bytes) => {
		const pointer = exports.allocate(bytes.length);
		memory().set(bytes, pointer);
		return pointer;
	};

	const manifest = JSON.parse(
		fs.readFileSync(path.join(ROOT, "conformance", "manifest.json"), "utf8"),
	);

	let checked = 0;
	for (const entry of manifest.cases) {
		if (entry.kind !== "valid") continue;
		const image = new Uint8Array(fs.readFileSync(path.join(ROOT, entry.path)));
		const pointer = alloc(image);
		const hash = exports.allocate(32);
		if (entry.name === "non_canonical") {
			// NF-INF02-01: validate and content_hash prove the canonical
			// form (INF-02), so a non-canonical image is refused; reencode
			// is the repair path.
			assert.strictEqual(exports.validate(pointer, image.length), -1, entry.name);
			assert.strictEqual(reference.lastError(), "infinity/not-canonical", entry.name);
			assert.strictEqual(exports.contentHash(pointer, image.length, hash), -1, entry.name);
			assert.strictEqual(reference.lastError(), "infinity/not-canonical", entry.name);
		} else {
			assert.strictEqual(exports.validate(pointer, image.length), 0, entry.name);
			assert.strictEqual(exports.contentHash(pointer, image.length, hash), 0);
			const hex = Buffer.from(memory().slice(hash, hash + 32)).toString("hex");
			assert.strictEqual(hex, entry.content_hash, entry.name);
		}

		const capacity = image.length * 2 + 1024;
		const outLength = exports.allocate(4);
		const output = exports.allocate(capacity);
		// The host honours the caller's declared capacity; a fresh allocation
		// is zeroed, so it must be written before the call.
		new DataView(exports.memory.buffer).setUint32(outLength, capacity, true);
		assert.strictEqual(
			exports.reencode(pointer, image.length, output, outLength),
			0,
			entry.name,
		);
		const written = new DataView(exports.memory.buffer).getUint32(
			outLength,
			true,
		);
		const canonical = Buffer.from(memory().slice(output, output + written));
		if (entry.name === "non_canonical") {
			assert.notDeepStrictEqual(canonical, Buffer.from(image));
			const repaired = alloc(canonical);
			assert.strictEqual(exports.validate(repaired, canonical.length), 0, entry.name);
		} else {
			assert.deepStrictEqual(canonical, Buffer.from(image), entry.name);
		}
		checked += 1;
	}

	// A capacity smaller than the result must return -2 with the required size
	// and must not write into the caller's buffer.
	{
		const image = fs.readFileSync(
			path.join(ROOT, "tests/vectors/valid/full.ainf"),
		);
		const input = alloc(image);
		const tinyLength = exports.allocate(4);
		const tinyBuffer = exports.allocate(8);
		new DataView(exports.memory.buffer).setUint32(tinyLength, 8, true);
		assert.strictEqual(
			exports.reencode(input, image.length, tinyBuffer, tinyLength),
			-2,
			"a small capacity is refused",
		);
		const required = new DataView(exports.memory.buffer).getUint32(
			tinyLength,
			true,
		);
		assert.ok(required > 8, `required size reported (${required})`);

		// A null output pointer (AS address zero) is not a buffer: the output
		// functions refuse it with -2 and the exact required size, and never
		// write at address zero.
		const nullLength = exports.allocate(4);
		new DataView(exports.memory.buffer).setUint32(nullLength, 0, true);
		assert.strictEqual(
			exports.reencode(input, image.length, 0, nullLength),
			-2,
			"a null output pointer is refused",
		);
		assert.strictEqual(
			new DataView(exports.memory.buffer).getUint32(nullLength, true),
			required,
			"a null output reports the required size",
		);

		assert.strictEqual(
			exports.contentHash(input, image.length, 0),
			-1,
			"a null hash output is refused",
		);
		assert.strictEqual(
			reference.lastError(),
			"infinity/null-output",
			"the hash refusal carries the reference code",
		);

		// A null out_len cannot carry a size; the reference refuses it instead of
		// writing at AS address zero.
		assert.strictEqual(
			exports.reencode(input, image.length, tinyBuffer, 0),
			-1,
			"a null out_len is refused",
		);
		assert.strictEqual(reference.lastError(), "infinity/null-out-len");

		// A null input pointer with a non-zero length is invalid input, never a
		// read of the module's static data.
		assert.strictEqual(exports.validate(0, 4), -1);
		assert.strictEqual(reference.lastError(), "infinity/null-input");
	}

	const source = Buffer.from('port = 8080\nname = "assemblyscript"\n');
	const name = Buffer.from("as.active");
	const sourcePointer = alloc(source);
	const namePointer = alloc(name);
	const jsonLength = exports.allocate(4);
	const jsonBuffer = exports.allocate(1 << 18);
	new DataView(exports.memory.buffer).setUint32(jsonLength, 1 << 18, true);
	assert.strictEqual(
		exports.fromActive(
			sourcePointer,
			source.length,
			namePointer,
			name.length,
			jsonBuffer,
			jsonLength,
		),
		0,
	);
	const encodedLength = new DataView(exports.memory.buffer).getUint32(
		jsonLength,
		true,
	);
	const encoded = Uint8Array.from(
		memory().slice(jsonBuffer, jsonBuffer + encodedLength),
	);
	const encodedPointer = alloc(encoded);
	assert.strictEqual(exports.validate(encodedPointer, encoded.length), 0);
	assert.strictEqual(exports.validate(encodedPointer, encoded.length), 0);

	// A negative name length must be refused, not silently compiled as an empty
	// name.
	const badNameLength = exports.allocate(4);
	new DataView(exports.memory.buffer).setUint32(badNameLength, 1 << 16, true);
	const badNameOut = exports.allocate(1 << 16);
	assert.strictEqual(
		exports.fromActive(
			sourcePointer,
			source.length,
			namePointer,
			-1,
			badNameOut,
			badNameLength,
		),
		-1,
		"a negative name length is refused",
	);
	assert.strictEqual(reference.lastError(), "infinity/null-name");

	const full = new Uint8Array(
		fs.readFileSync(path.join(ROOT, "tests/vectors/valid/full.ainf")),
	);
	const fullPointer = alloc(full);
	const redactedLength = exports.allocate(4);
	const redactedBuffer = exports.allocate(1 << 18);
	new DataView(exports.memory.buffer).setUint32(
		redactedLength,
		1 << 18,
		true,
	);
	assert.strictEqual(
		exports.redactedJson(
			fullPointer,
			full.length,
			redactedBuffer,
			redactedLength,
		),
		0,
	);
	const redactedWritten = new DataView(exports.memory.buffer).getUint32(
		redactedLength,
		true,
	);
	const json = Buffer.from(
		memory().slice(redactedBuffer, redactedBuffer + redactedWritten),
	).toString();
	assert.ok(!json.includes("CANARY_SECRET_"));
	JSON.parse(json);

	const junk = alloc(Buffer.from([0xff, 0xff]));
	assert.notStrictEqual(exports.validate(junk, 2), 0);

	exports.releaseAll();
	console.log(`AssemblyScript conformance PASS (${checked} vectors)`);
}

main().catch((error) => {
	console.error(error);
	process.exit(1);
});
