/**
 * AssemblyScript thin RPC client: the AS module builds the ARP1 request and the
 * host performs TCP I/O against the real Active RPC kernel.
 *
 * Build the module first:
 *   npx --yes -p assemblyscript@0.27.31 asc polyglot/rpc/as_request.ts \
 *     -o polyglot/rpc/build/as_request.wasm --optimize
 * Then:
 *   node polyglot/rpc/as_client.js
 *
 * Environment (set by polyglot/rpc/run_clients.sh):
 *   ACTIVE_RPC_ADDR     host:port of the peer
 *   ACTIVE_RPC_CAP      32 hex characters, the server-minted capability id
 *   ACTIVE_RPC_PAYLOAD  AINF payload path
 */

const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const { encodeRequest, loadEncoder } = require("./as_encoder");

const WASM = path.join(__dirname, "build", "as_request.wasm");

function call(address, requestBuffer) {
	const [host, port] = address.split(":");
	return new Promise((resolve, reject) => {
		const socket = net.createConnection({ host, port: Number(port) }, () => {
			const header = Buffer.alloc(4);
			header.writeUInt32LE(requestBuffer.length);
			socket.write(Buffer.concat([header, requestBuffer]));
		});
		let received = Buffer.alloc(0);
		socket.on("data", (chunk) => {
			received = Buffer.concat([received, chunk]);
			if (received.length < 4) return;
			const length = received.readUInt32LE(0);
			if (received.length < 4 + length) return;
			socket.end();
			resolve(received.subarray(4, 4 + length));
		});
		socket.on("error", reject);
	});
}

function errorCode(envelope) {
	const length = envelope.readUInt32LE(16);
	return envelope.subarray(20, 20 + length).toString();
}

async function main() {
	const address = process.env.ACTIVE_RPC_ADDR;
	const capHex = process.env.ACTIVE_RPC_CAP;
	const payloadPath = process.env.ACTIVE_RPC_PAYLOAD;
	if (!address || !capHex || !payloadPath)
		throw new Error(
			"ACTIVE_RPC_ADDR, ACTIVE_RPC_CAP and ACTIVE_RPC_PAYLOAD are required",
		);
	const payload = fs.readFileSync(payloadPath);
	const exports = await loadEncoder(WASM);

	const body = await call(
		address,
		encodeRequest(exports, { id: 42, method: "echo", payload, capId: capHex }),
	);
	if (body[5] !== 2 || body.readBigUInt64LE(8) !== 42n)
		throw new Error(`echo: kind ${body[5]}`);
	const echoed =
		body.readUInt32LE(body.length - 4) === 0 &&
		body
			.subarray(body.length - 4 - payload.length, body.length - 4)
			.equals(payload);
	if (!echoed) throw new Error("payload was not echoed");

	const refused = await call(
		address,
		encodeRequest(exports, {
			id: 43,
			method: "refuse",
			payload,
			capId: capHex,
		}),
	);
	if (refused[5] !== 3 || errorCode(refused) !== "rpc/method-not-granted")
		throw new Error(`refusal mismatch: ${errorCode(refused)}`);

	const anonymous = await call(
		address,
		encodeRequest(exports, { id: 44, method: "echo", payload, capId: null }),
	);
	if (anonymous[5] !== 3 || errorCode(anonymous) !== "rpc/unknown-capability")
		throw new Error(`missing capability mismatch: ${errorCode(anonymous)}`);

	exports.releaseAll();
	console.log(
		"AssemblyScript thin RPC PASS (echo, refusal, missing capability)",
	);
}

main().catch((error) => {
	console.error(error);
	process.exit(1);
});
