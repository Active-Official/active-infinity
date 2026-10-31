/**
 * Thin Active RPC client over native ARP1 on TCP (TypeScript).
 *
 * The JavaScript row runs a hand-written CommonJS script; this row is a typed
 * implementation compiled with `tsc --strict`, so the language is exercised as
 * a language (types, narrowing, classes), not by re-running the JS file.
 *
 *   ACTIVE_RPC_ADDR=127.0.0.1:54321 \
 *   ACTIVE_RPC_CAP=<32 hex chars> \
 *   ACTIVE_RPC_PAYLOAD=tests/vectors/valid/full.ainf \
 *   node polyglot/rpc/build/ts_client.js
 *
 * `require`, `process` and `TextEncoder` are declared locally so the compiler
 * needs no `@types/node`; the shapes used here are the Node ones.
 */

declare function require(name: string): any;
declare const process: {
	env: Record<string, string | undefined>;
	exitCode?: number;
};
declare const TextEncoder: { new (): { encode(input: string): Uint8Array } };
declare const TextDecoder: { new (): { decode(input: Uint8Array): string } };
declare const console: {
	log(message: string): void;
	error(message: string): void;
};

const net: any = require("node:net");
const fs: any = require("node:fs");

const MAGIC = "ARP1";
const VERSION = 1;
const KIND_REQUEST = 1;
const KIND_RESPONSE = 2;
const KIND_ERROR = 3;

/** Default budget ceilings, in the descriptor's fixed order. */
const BUDGET: readonly bigint[] = [
	10_000n,
	67_108_864n,
	5_000n,
	100_000n,
	256n,
	100_000n,
	10_000_000n,
];

/** Growable little-endian writer. */
class Writer {
	private readonly out: number[] = [];

	u8(value: number): this {
		this.out.push(value & 0xff);
		return this;
	}

	u16(value: number): this {
		this.out.push(value & 0xff, (value >>> 8) & 0xff);
		return this;
	}

	u32(value: number): this {
		this.out.push(
			value & 0xff,
			(value >>> 8) & 0xff,
			(value >>> 16) & 0xff,
			(value >>> 24) & 0xff,
		);
		return this;
	}

	u64(value: bigint): this {
		let rest = value;
		for (let index = 0; index < 8; index += 1) {
			this.out.push(Number(rest & 0xffn));
			rest >>= 8n;
		}
		return this;
	}

	bytes(value: Uint8Array): this {
		for (const byte of value) this.out.push(byte);
		return this;
	}

	str(text: string): this {
		const encoded = new TextEncoder().encode(text);
		this.u32(encoded.length);
		this.bytes(encoded);
		return this;
	}

	finish(): Uint8Array {
		return Uint8Array.from(this.out);
	}
}

interface Descriptor {
	readonly cap: Uint8Array;
}

function descriptor(writer: Writer, { cap }: Descriptor): Writer {
	if (cap.length !== 16) throw new Error("capability id must be 16 bytes");
	writer.bytes(cap).u32(1).str("echo");
	for (const ceiling of BUDGET) writer.u64(ceiling);
	return writer.u8(0).u8(0).u8(0); // read_only, redact, no path scope
}

function request(
	id: bigint,
	method: string,
	payload: Uint8Array,
	cap: Uint8Array | null,
): Uint8Array {
	const writer = new Writer();
	writer
		.bytes(new TextEncoder().encode(MAGIC))
		.u8(VERSION)
		.u8(KIND_REQUEST)
		.u16(0)
		.u64(id)
		.str(method)
		.u32(0)
		.u32(payload.length)
		.bytes(payload);
	if (cap === null) return writer.u32(0).finish();
	return descriptor(writer.u32(1), { cap }).finish();
}

interface Decoded {
	readonly kind: number;
	readonly requestId: bigint;
	readonly method: string;
	readonly payload: Uint8Array;
}

class Reader {
	constructor(
		private readonly data: Uint8Array,
		private cursor = 0,
	) {}

	u8(): number {
		this.require(1);
		return this.data[this.cursor++];
	}

	u32(): number {
		this.require(4);
		const { data, cursor } = this;
		const value =
			data[cursor] |
			(data[cursor + 1] << 8) |
			(data[cursor + 2] << 16) |
			(data[cursor + 3] << 24);
		this.cursor += 4;
		return value >>> 0;
	}

	u64(): bigint {
		this.require(8);
		let value = 0n;
		for (let index = 0; index < 8; index += 1) {
			value |= BigInt(this.data[this.cursor + index]) << BigInt(index * 8);
		}
		this.cursor += 8;
		return value;
	}

	take(length: number): Uint8Array {
		this.require(length);
		const slice = this.data.subarray(this.cursor, this.cursor + length);
		this.cursor += length;
		return slice;
	}

	skipValue(): void {
		const tag = this.u8();
		switch (tag) {
			case 0:
			case 7:
				return;
			case 1:
				this.take(1);
				return;
			case 2:
			case 3:
				this.take(8);
				return;
			case 4:
			case 8:
			case 9:
				this.take(this.u32());
				return;
			case 5: {
				const count = this.u32();
				for (let index = 0; index < count; index += 1) this.skipValue();
				return;
			}
			case 6: {
				const count = this.u32();
				for (let index = 0; index < count; index += 1) {
					this.take(this.u32());
					this.skipValue();
				}
				return;
			}
			default:
				throw new Error(`unknown value tag ${tag}`);
		}
	}

	private require(length: number): void {
		if (this.cursor + length > this.data.length) {
			throw new Error("truncated envelope");
		}
	}
}

function decode(body: Uint8Array): Decoded {
	const reader = new Reader(body);
	const magic = new TextDecoder().decode(reader.take(4));
	if (magic !== MAGIC) throw new Error("bad envelope magic");
	const version = reader.u8();
	if (version !== VERSION) throw new Error("bad envelope version");
	const kind = reader.u8();
	reader.take(2); // flags
	const requestId = reader.u64();
	const method = new TextDecoder().decode(reader.take(reader.u32()));
	const args = reader.u32();
	for (let index = 0; index < args; index += 1) {
		const tag = reader.u8();
		if (tag === 0) reader.skipValue();
		else if (tag === 1) reader.take(8);
		else if (tag === 2) reader.take(16);
		else throw new Error(`unknown argument tag ${tag}`);
	}
	const payload = reader.take(reader.u32());
	return { kind, requestId, method, payload };
}

function call(address: string, envelope: Uint8Array): Promise<Decoded> {
	const separator = address.lastIndexOf(":");
	const host = address.slice(0, separator);
	const port = Number(address.slice(separator + 1));
	return new Promise((resolve, reject) => {
		const socket = net.createConnection({ host, port }, () => {
			const header = new Writer().u32(envelope.length).finish();
			const frame = new Uint8Array(header.length + envelope.length);
			frame.set(header, 0);
			frame.set(envelope, header.length);
			socket.write(frame);
		});
		let received = new Uint8Array(0);
		const append = (chunk: Uint8Array): void => {
			const merged = new Uint8Array(received.length + chunk.length);
			merged.set(received, 0);
			merged.set(chunk, received.length);
			received = merged;
		};
		socket.on("data", (chunk: Uint8Array) => {
			append(new Uint8Array(chunk));
			if (received.length < 4) return;
			const length =
				received[0] |
				(received[1] << 8) |
				(received[2] << 16) |
				(received[3] << 24);
			if (received.length < 4 + (length >>> 0)) return;
			socket.end();
			try {
				resolve(decode(received.subarray(4, 4 + (length >>> 0))));
			} catch (error) {
				reject(error);
			}
		});
		socket.on("error", (error: Error) => reject(error));
	});
}

function sameBytes(first: Uint8Array, second: Uint8Array): boolean {
	if (first.length !== second.length) return false;
	for (let index = 0; index < first.length; index += 1) {
		if (first[index] !== second[index]) return false;
	}
	return true;
}

async function main(): Promise<void> {
	const address = process.env.ACTIVE_RPC_ADDR;
	const capHex = process.env.ACTIVE_RPC_CAP;
	const payloadPath =
		process.env.ACTIVE_RPC_PAYLOAD ?? "tests/vectors/valid/full.ainf";
	if (!address || !capHex) {
		throw new Error("ACTIVE_RPC_ADDR and ACTIVE_RPC_CAP are required");
	}
	if (capHex.length !== 32) {
		throw new Error("ACTIVE_RPC_CAP must be 32 hex characters");
	}
	const cap = new Uint8Array(16);
	for (let index = 0; index < 16; index += 1) {
		cap[index] = Number.parseInt(capHex.slice(index * 2, index * 2 + 2), 16);
	}
	const payload: Uint8Array = new Uint8Array(fs.readFileSync(payloadPath));

	const echoed = await call(address, request(42n, "echo", payload, cap));
	if (echoed.kind !== KIND_RESPONSE || echoed.requestId !== 42n) {
		throw new Error(`echo: kind ${echoed.kind} id ${echoed.requestId}`);
	}
	if (!sameBytes(echoed.payload, payload)) {
		throw new Error("echo: the AINF payload was not echoed");
	}

	const refused = await call(address, request(43n, "refuse", payload, cap));
	if (
		refused.kind !== KIND_ERROR ||
		refused.method !== "rpc/method-not-granted"
	) {
		throw new Error(`refusal: kind ${refused.kind} method ${refused.method}`);
	}

	const anonymous = await call(address, request(44n, "echo", payload, null));
	if (
		anonymous.kind !== KIND_ERROR ||
		anonymous.method !== "rpc/unknown-capability"
	) {
		throw new Error(
			`missing capability: kind ${anonymous.kind} method ${anonymous.method}`,
		);
	}

	console.log("TypeScript thin RPC PASS (echo, refusal, missing capability)");
}

main().catch((error: Error) => {
	console.error(error.message);
	process.exitCode = 1;
});
