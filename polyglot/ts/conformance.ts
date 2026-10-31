/**
 * TypeScript conformance test for the typed wrapper.
 *
 * Compile and run from the repository root:
 *   npx -p typescript@5.7.2 tsc -p polyglot/ts/tsconfig.json
 *   node polyglot/ts/out/conformance.js
 */

declare const require: any;
declare const process: any;
declare const __dirname: string;
declare const Buffer: any;

const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

import { ActiveInfinity, ActiveInfinityError } from "../js/active-infinity";

const ROOT = path.resolve(process.cwd());

async function main(): Promise<void> {
	const wasm = fs.readFileSync(
		path.join(
			ROOT,
			"ffi",
			"active-infinity-ffi",
			"target",
			"wasm32-unknown-unknown",
			"release",
			"active_infinity_ffi.wasm",
		),
	) as Uint8Array;
	const binding: ActiveInfinity = await ActiveInfinity.instantiate(wasm);
	const manifest = JSON.parse(
		fs.readFileSync(path.join(ROOT, "conformance", "manifest.json"), "utf8"),
	) as {
		cases: Array<{
			kind: string;
			name: string;
			path: string;
			content_hash: string;
		}>;
	};

	let checked = 0;
	for (const entry of manifest.cases) {
		if (entry.kind !== "valid") continue;
		const image = new Uint8Array(fs.readFileSync(path.join(ROOT, entry.path)));
		binding.validate(image);
		const hash = Buffer.from(binding.contentHash(image)).toString("hex");
		assert.strictEqual(hash, entry.content_hash, entry.name);
		const canonical = Buffer.from(binding.reencode(image));
		if (entry.name === "non_canonical") {
			assert.notStrictEqual(
				canonical.toString("hex"),
				Buffer.from(image).toString("hex"),
			);
		} else {
			assert.deepStrictEqual(canonical, Buffer.from(image), entry.name);
		}
		checked += 1;
	}

	const source = 'port = 8080\nname = "ts"\n';
	const first = binding.fromActive(source, "ts.active");
	const second = binding.fromActive(source, "ts.active");
	assert.deepStrictEqual(first, second);

	const full = new Uint8Array(
		fs.readFileSync(path.join(ROOT, "tests/vectors/valid/full.ainf")),
	);
	const json: string = binding.redactedJson(full);
	assert.ok(!json.includes("CANARY_SECRET_"));
	JSON.parse(json);

	assert.throws(
		() => binding.validate(new Uint8Array([0xff, 0xff])),
		(error: unknown) =>
			error instanceof ActiveInfinityError &&
			error.code.startsWith("infinity/"),
	);

	console.log(`TypeScript conformance PASS (${checked} vectors)`);
}

main().catch((error) => {
	console.error(error);
	process.exit(1);
});
