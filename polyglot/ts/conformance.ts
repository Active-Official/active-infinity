/**
 * TypeScript conformance test for the typed wrapper.
 *
 * Compile and run from the repository root:
 *   npx -p typescript@5.7.2 tsc -p polyglot/ts/tsconfig.json
 *   node polyglot/ts-build/conformance.js
 * (tsconfig.json sets outDir to ../ts-build.)
 */

declare const require: any;
declare const process: any;
declare const __dirname: string;
declare const Buffer: any;

const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

import { ActiveInfinity, ActiveInfinityError, Limits } from "../js/active-infinity";

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
			// INF-POLY-02: only valid cases carry a content_hash; only
			// invalid and invalid_stream cases carry an expected_code.
			content_hash?: string;
			expected_code?: string;
			options?: { limits?: string };
		}>;
	};

	let checked = 0;
	for (const entry of manifest.cases) {
		if (entry.kind !== "valid") continue;
		const image = new Uint8Array(fs.readFileSync(path.join(ROOT, entry.path)));
		if (entry.name === "non_canonical") {
			// NF-INF02-01: validate and content_hash prove the canonical
			// form (INF-02), so a non-canonical image is refused; reencode
			// is the repair path.
			assert.throws(
				() => binding.validate(image),
				(error: unknown) =>
					error instanceof ActiveInfinityError &&
					error.code === "infinity/not-canonical",
			);
			assert.throws(
				() => binding.contentHash(image),
				(error: unknown) =>
					error instanceof ActiveInfinityError &&
					error.code === "infinity/not-canonical",
			);
			// INF-POLY-03: the binding surfaces validateCanonical; it must
			// refuse the non-canonical image with the same code.
			assert.throws(
				() => binding.validateCanonical(image),
				(error: unknown) =>
					error instanceof ActiveInfinityError &&
					error.code === "infinity/not-canonical",
			);
		} else {
			binding.validate(image);
			binding.validateCanonical(image);
			const hash = Buffer.from(binding.contentHash(image)).toString("hex");
			assert.strictEqual(hash, entry.content_hash, entry.name);
		}
		const canonical = Buffer.from(binding.reencode(image));
		if (entry.name === "non_canonical") {
			assert.notStrictEqual(
				canonical.toString("hex"),
				Buffer.from(image).toString("hex"),
			);
			binding.validate(canonical);
		} else {
			assert.deepStrictEqual(canonical, Buffer.from(image), entry.name);
		}
		checked += 1;
	}

	// INF-POLY-03: pin the exact count, derived from the manifest -- the test
	// used to have no floor at all, so an empty run could PASS.
	const valid = manifest.cases.filter((entry) => entry.kind === "valid").length;
	assert.strictEqual(checked, valid, "the manifest exercised valid vectors");

	// INF-POLY-02: every invalid vector must be refused with exactly the
	// manifest's expected_code. INF-FFI-02: the two limits-dependent ones
	// (limit, too_deep) go through validateWithLimits with the narrowed
	// budget from the entry's options.limits (max_nodes:1, max_depth:8);
	// the rest go through validateCanonical. invalid_stream vectors are
	// CLI-only: no stream decode exists in the FFI.
	let invalidChecked = 0;
	for (const entry of manifest.cases) {
		if (entry.kind !== "invalid") continue;
		const image = fs.readFileSync(path.join(ROOT, entry.path));
		const limitsSpec = entry.options?.limits;
		if (limitsSpec) {
			const [field, value] = limitsSpec.split(":");
			const limits = Limits.defaults(binding);
			try {
				limits.set(field, Number(value));
				assert.throws(
					() => binding.validateWithLimits(image, limits),
					(error: unknown) =>
						error instanceof ActiveInfinityError &&
						error.code === entry.expected_code,
					`${entry.name}: validateWithLimits must refuse the image with ${entry.expected_code}`,
				);
			} finally {
				limits.free();
			}
		} else {
			assert.throws(
				() => binding.validateCanonical(image),
				(error: unknown) =>
					error instanceof ActiveInfinityError &&
					error.code === entry.expected_code,
				`${entry.name}: validateCanonical must refuse the image with ${entry.expected_code}`,
			);
		}
		invalidChecked += 1;
	}
	const invalidTotal = manifest.cases.filter((entry) => entry.kind === "invalid").length;
	assert.strictEqual(
		invalidChecked,
		invalidTotal,
		"the manifest exercised invalid vectors",
	);

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
