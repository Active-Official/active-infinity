/** Active Infinity WASM binding. */

export declare const ABI_VERSION: 1;

export declare class ActiveInfinityError extends Error {
	readonly code: string;
	readonly status: number;
}

export declare class ActiveInfinity {
	static instantiate(bytes: Uint8Array | ArrayBuffer): Promise<ActiveInfinity>;
	validate(bytes: Uint8Array | ArrayBuffer): true;
	contentHash(bytes: Uint8Array | ArrayBuffer): Uint8Array;
	reencode(bytes: Uint8Array | ArrayBuffer): Uint8Array;
	fromActive(source: string | Uint8Array, name?: string): Uint8Array;
	redactedJson(bytes: Uint8Array | ArrayBuffer): string;
}
