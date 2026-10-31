/**
 * Byte-exact golden check for the AssemblyScript ARP1 encoder.
 *
 * Prints the request hex produced by `as_request.wasm` for the fixed
 * thin-client call. `polyglot/rpc/check_golden.sh` compares it with the output
 * of the Rust reference encoder (`active-rpc/examples/arp1_request_vector.rs`).
 *
 *   node polyglot/rpc/as_golden.js <payload-file> <cap-hex>
 */

const fs = require("node:fs");
const path = require("node:path");
const { encodeRequest, loadEncoder } = require("./as_encoder");

const WASM = path.join(__dirname, "build", "as_request.wasm");

async function main() {
	const [payloadPath, capHex] = process.argv.slice(2);
	if (!payloadPath || !capHex)
		throw new Error("usage: as_golden.js <payload-file> <cap-hex>");
	const payload = fs.readFileSync(payloadPath);
	const exports = await loadEncoder(WASM);
	const request = encodeRequest(exports, {
		id: 42,
		method: "echo",
		payload,
		capId: capHex,
	});
	exports.releaseAll();
	console.log(request.toString("hex"));
}

main().catch((error) => {
	console.error(error);
	process.exit(1);
});
