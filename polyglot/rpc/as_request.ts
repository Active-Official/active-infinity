// AssemblyScript request encoder for the thin RPC client.
//
// The AS module builds ARP1 bytes; the JavaScript host (as_client.js) performs
// the socket I/O and hands the bytes to the reference peer.

const retained: Uint8Array[] = [];

export function allocate(length: i32): usize {
	const buffer = new Uint8Array(length);
	retained.push(buffer);
	return buffer.dataStart;
}

export function releaseAll(): void {
	retained.length = 0;
}

function putU32(pointer: usize, value: u32): usize {
	store<u32>(pointer, value);
	return pointer + 4;
}

function putU64(pointer: usize, value: u64): usize {
	store<u64>(pointer, value);
	return pointer + 8;
}

/** Encode a request. `cap` may be 0 for "no capability". */
export function buildRequest(
	id: u64,
	methodPointer: usize,
	methodLength: i32,
	payloadPointer: usize,
	payloadLength: i32,
	capPointer: usize,
	capMethodsPointer: usize,
	capMethodsCount: i32,
	capMethodsLength: i32,
	outPointer: usize,
	outCapacity: i32,
): i32 {
	// Refuse rather than write past the caller's output buffer: a raw store
	// overflow would corrupt other module memory.
	let needed = 16 + 4 + methodLength + 4 + 4 + payloadLength + 4;
	if (capPointer != 0) {
		needed += 16 + 4 + capMethodsLength + 56 + 3;
	}
	if (needed > outCapacity) {
		return -1;
	}

	let cursor = outPointer;
	store<u8>(cursor++, 0x41); // A
	store<u8>(cursor++, 0x52); // R
	store<u8>(cursor++, 0x50); // P
	store<u8>(cursor++, 0x31); // 1
	store<u8>(cursor++, 1); // version
	store<u8>(cursor++, 1); // kind request
	store<u16>(cursor, 0); // flags (u16)
	cursor += 2;
	cursor = putU64(cursor, id);
	cursor = putU32(cursor, u32(methodLength));
	memory.copy(cursor, methodPointer, methodLength);
	cursor += methodLength;
	cursor = putU32(cursor, 0); // args
	cursor = putU32(cursor, u32(payloadLength));
	memory.copy(cursor, payloadPointer, payloadLength);
	cursor += payloadLength;
	if (capPointer == 0) {
		cursor = putU32(cursor, 0);
		return i32(cursor - outPointer);
	}
	cursor = putU32(cursor, 1);
	memory.copy(cursor, capPointer, 16);
	cursor += 16;
	cursor = putU32(cursor, u32(capMethodsCount));
	memory.copy(cursor, capMethodsPointer, capMethodsLength);
	cursor += capMethodsLength;
	const budget: u64[] = [10000, 67108864, 5000, 100000, 256, 100000, 10000000];
	for (let index = 0; index < budget.length; index++) {
		cursor = putU64(cursor, budget[index]);
	}
	store<u8>(cursor++, 0); // read_only
	store<u8>(cursor++, 0); // redact
	store<u8>(cursor++, 0); // no path scope
	return i32(cursor - outPointer);
}
