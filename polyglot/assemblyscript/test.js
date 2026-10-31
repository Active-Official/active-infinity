/**
 * AssemblyScript conformance test.
 *
 * Build the AS module first:
 *   npx --yes assemblyscript@0.27.31 asc \
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
	const { assembly } = await load(REFERENCE, ASSEMBLY);
	const exports = assembly.exports;
	const memory = () => new Uint8Array(exports.memory.buffer);
	assert.strictEqual(exports.abiVersion(), 1);

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
		assert.strictEqual(exports.validate(pointer, image.length), 0, entry.name);

		const hash = exports.allocate(32);
		assert.strictEqual(exports.contentHash(pointer, image.length, hash), 0);
		const hex = Buffer.from(memory().slice(hash, hash + 32)).toString("hex");
		assert.strictEqual(hex, entry.content_hash, entry.name);

		const outLength = exports.allocate(4);
		const capacity = image.length * 2 + 1024;
		const output = exports.allocate(capacity);
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
		} else {
			assert.deepStrictEqual(canonical, Buffer.from(image), entry.name);
		}
		checked += 1;
	}

	const source = Buffer.from('port = 8080\nname = "assemblyscript"\n');
	const name = Buffer.from("as.active");
	const sourcePointer = alloc(source);
	const namePointer = alloc(name);
	const jsonLength = exports.allocate(4);
	const jsonBuffer = exports.allocate(1 << 18);
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

	const full = new Uint8Array(
		fs.readFileSync(path.join(ROOT, "tests/vectors/valid/full.ainf")),
	);
	const fullPointer = alloc(full);
	const redactedLength = exports.allocate(4);
	const redactedBuffer = exports.allocate(1 << 18);
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
