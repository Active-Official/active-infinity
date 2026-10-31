/**
 * Thin Active RPC client over native ARP1 on TCP (Node.js).
 *
 *   node polyglot/rpc/js_client.js
 */

const net = require("node:net");
const fs = require("node:fs");

function putString(buffer, text) {
	const bytes = Buffer.from(text, "utf8");
	const header = Buffer.alloc(4);
	header.writeUInt32LE(bytes.length);
	return Buffer.concat([buffer, header, bytes]);
}

function request(id, method, payload, capId) {
	let buffer = Buffer.alloc(0);
	buffer = Buffer.concat([buffer, Buffer.from("ARP1")]);
	buffer = Buffer.concat([buffer, Buffer.from([1, 1])]); // version, request
	const flags = Buffer.alloc(2);
	buffer = Buffer.concat([buffer, flags]);
	const requestId = Buffer.alloc(8);
	requestId.writeBigUInt64LE(BigInt(id));
	buffer = Buffer.concat([buffer, requestId]);
	buffer = putString(buffer, method);
	const noArgs = Buffer.alloc(4);
	buffer = Buffer.concat([buffer, noArgs]);
	const payloadLength = Buffer.alloc(4);
	payloadLength.writeUInt32LE(payload.length);
	buffer = Buffer.concat([buffer, payloadLength, payload]);
	const caps = Buffer.alloc(4);
	caps.writeUInt32LE(capId ? 1 : 0);
	buffer = Buffer.concat([buffer, caps]);
	if (capId) {
		buffer = Buffer.concat([buffer, capId]);
		const methods = Buffer.alloc(4);
		methods.writeUInt32LE(1);
		buffer = Buffer.concat([buffer, methods]);
		buffer = putString(buffer, "echo");
		const budget = Buffer.alloc(8 * 7);
		const values = [
			10000,
			64 * 1024 * 1024,
			5000,
			100000,
			256,
			100000,
			10000000,
		];
		values.forEach((value, index) =>
			budget.writeBigUInt64LE(BigInt(value), index * 8),
		);
		buffer = Buffer.concat([buffer, budget, Buffer.from([0, 0, 0])]);
	}
	return buffer;
}

function call(address, envelope) {
	const [host, port] = address.split(":");
	return new Promise((resolve, reject) => {
		const socket = net.createConnection({ host, port: Number(port) }, () => {
			const header = Buffer.alloc(4);
			header.writeUInt32LE(envelope.length);
			socket.write(Buffer.concat([header, envelope]));
		});
		let received = Buffer.alloc(0);
		socket.on("data", (chunk) => {
			received = Buffer.concat([received, chunk]);
			if (received.length < 4) return;
			const length = received.readUInt32LE(0);
			if (received.length < 4 + length) return;
			const body = received.subarray(4, 4 + length);
			socket.end();
			if (body.subarray(0, 4).toString() !== "ARP1" || body[4] !== 1) {
				reject(new Error("bad envelope magic"));
				return;
			}
			const kind = body[5];
			const methodLength = body.readUInt32LE(16);
			const method = body.subarray(20, 20 + methodLength).toString();
			resolve({ kind, method, body });
		});
		socket.on("error", reject);
	});
}

async function main() {
	const address = process.env.ACTIVE_RPC_ADDR;
	const capHex = process.env.ACTIVE_RPC_CAP;
	const payloadPath = process.env.ACTIVE_RPC_PAYLOAD;
	if (!address || !capHex || !payloadPath) {
		throw new Error(
			"ACTIVE_RPC_ADDR, ACTIVE_RPC_CAP and ACTIVE_RPC_PAYLOAD are required",
		);
	}
	const capId = Buffer.from(capHex, "hex");
	if (capId.length !== 16)
		throw new Error("ACTIVE_RPC_CAP must be 32 hex characters");
	const payload = fs.readFileSync(payloadPath);

	const echo = await call(address, request(42, "echo", payload, capId));
	const echoed =
		echo.body.readUInt32LE(echo.body.length - 4) === 0 &&
		echo.body
			.subarray(echo.body.length - 4 - payload.length, echo.body.length - 4)
			.equals(payload);
	if (echo.kind !== 2 || echo.body.readBigUInt64LE(8) !== 42n || !echoed)
		throw new Error(`echo: ${echo.kind} ${echo.method}`);

	const refused = await call(address, request(43, "refuse", payload, capId));
	if (refused.kind !== 3 || refused.method !== "rpc/method-not-granted") {
		throw new Error(`refusal: ${JSON.stringify(refused)}`);
	}

	const anonymous = await call(address, request(44, "echo", payload, null));
	if (anonymous.kind !== 3 || anonymous.method !== "rpc/unknown-capability") {
		throw new Error(`missing capability: ${JSON.stringify(anonymous)}`);
	}

	console.log("JavaScript thin RPC PASS (echo, refusal, missing capability)");
}

main().catch((error) => {
	console.error(error);
	process.exit(1);
});
