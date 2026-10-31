/**
 * Conformance test for the JavaScript binding.
 *
 * Run from the repository root:
 *   node polyglot/js/test.js
 *
 * It drives the shipped WASM module, compares content hashes with the shared
 * conformance manifest, and checks the redaction canary.
 */

const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const { ActiveInfinity } = require("./active-infinity.js");

const ROOT = path.resolve(__dirname, "..", "..");
const WASM = path.join(
	ROOT,
	"ffi",
	"active-infinity-ffi",
	"target",
	"wasm32-unknown-unknown",
	"release",
	"active_infinity_ffi.wasm",
);

async function main() {
	const module = await ActiveInfinity.instantiate(fs.readFileSync(WASM));
	const manifest = JSON.parse(
		fs.readFileSync(path.join(ROOT, "conformance", "manifest.json"), "utf8"),
	);

	let checked = 0;
	for (const entry of manifest.cases) {
		if (entry.kind !== "valid") continue;
		const image = fs.readFileSync(path.join(ROOT, entry.path));
		module.validate(image);
		const hash = Buffer.from(module.contentHash(image)).toString("hex");
		assert.strictEqual(hash, entry.content_hash, `${entry.name}: content hash`);

		const canonical = Buffer.from(module.reencode(image));
		if (entry.name === "non_canonical") {
			assert.notStrictEqual(
				canonical.toString("hex"),
				image.toString("hex"),
				"non-canonical input is re-encoded",
			);
			module.validate(canonical);
		} else {
			assert.deepStrictEqual(
				canonical,
				image,
				`${entry.name}: canonical bytes`,
			);
		}
		checked += 1;
	}
	assert.ok(checked >= 4, "the manifest exercised valid vectors");

	const source = 'port = 8080\nname = "js"\n';
	const first = Buffer.from(module.fromActive(source, "js.active"));
	const second = Buffer.from(module.fromActive(source, "js.active"));
	assert.deepStrictEqual(
		first,
		second,
		"Active source encoding is deterministic",
	);
	module.validate(first);
	assert.strictEqual(
		Buffer.from(module.contentHash(first)).toString("hex"),
		Buffer.from(module.contentHash(second)).toString("hex"),
	);

	const full = fs.readFileSync(
		path.join(ROOT, "tests/vectors/valid/full.ainf"),
	);
	const json = module.redactedJson(full);
	assert.ok(!json.includes("CANARY_SECRET_"), "secret canary must not survive");
	JSON.parse(json);

	assert.throws(
		() => module.validate(Buffer.from([0xff, 0xff, 0xff])),
		(error) => error.code.startsWith("infinity/"),
		"malformed input reports a stable code",
	);

	console.log(`JS conformance PASS (${checked} vectors)`);
}

main().catch((error) => {
	console.error(error);
	process.exit(1);
});
