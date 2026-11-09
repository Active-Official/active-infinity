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
		if (entry.name === "non_canonical") {
			// NF-INF02-01: validate and content_hash prove the canonical
			// form (INF-02), so a non-canonical image is refused; reencode
			// is the repair path.
			assert.throws(
				() => module.validate(image),
				(error) => error.code === "infinity/not-canonical",
				`${entry.name}: validate must refuse a non-canonical image`,
			);
			assert.throws(
				() => module.contentHash(image),
				(error) => error.code === "infinity/not-canonical",
				`${entry.name}: contentHash must refuse a non-canonical image`,
			);
			// INF-POLY-03: the binding surfaces validateCanonical; it must
			// refuse the non-canonical image with the same code.
			assert.throws(
				() => module.validateCanonical(image),
				(error) => error.code === "infinity/not-canonical",
				`${entry.name}: validateCanonical must refuse a non-canonical image`,
			);
		} else {
			module.validate(image);
			module.validateCanonical(image);
			const hash = Buffer.from(module.contentHash(image)).toString("hex");
			assert.strictEqual(hash, entry.content_hash, `${entry.name}: content hash`);
		}

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
	// INF-POLY-03: pin the exact count, derived from the manifest -- a
	// slack `>=` let a dropped vector pass silently.
	const valid = manifest.cases.filter((entry) => entry.kind === "valid").length;
	assert.strictEqual(checked, valid, "the manifest exercised valid vectors");

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

	// A refused allocation must raise infinity/limit instead of writing at
	// address zero (the FFI caps one allocation at 1 GiB).
	const refused = new ActiveInfinity({
		exports: {
			memory: new WebAssembly.Memory({ initial: 1 }),
			active_infinity_abi_version: () => 1,
			active_infinity_alloc: () => 0,
			active_infinity_free: () => {},
		},
	});
	assert.throws(
		() => refused.validate(new Uint8Array([1, 2, 3, 4])),
		(error) => error.code === "infinity/limit",
		"a refused allocation raises infinity/limit",
	);

	console.log(`JS conformance PASS (${checked} vectors)`);
}

main().catch((error) => {
	console.error(error);
	process.exit(1);
});
