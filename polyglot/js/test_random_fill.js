// Regression test for INF-POLY-01: the `active_random_fill` host import
// must fill more than 64 KiB without trapping.
//
// WebCrypto caps one `crypto.getRandomValues` call at 65,536 bytes. Both
// host implementations (the JS binding's `ActiveInfinity.instantiate` and
// the AssemblyScript host's `Reference.load`) used to issue a single call
// with no chunking and no try/catch, so any fill above 64 KiB threw
// QuotaExceededError into the WASM import and trapped the instance
// instead of returning the documented non-zero error code. The fix chunks
// at 65,536 bytes and returns 1 on any failure.
//
// No exported codec entry point currently reaches getrandom (see
// polyglot/go/activeinfinity_test.go), so the import itself is exercised
// through a synthetic WASM module: it imports env.active_random_fill,
// exports its memory, `active_infinity_abi_version` (= 1, so the JS
// binding accepts it) and `call_fill(dest, len)`, which invokes the
// import and returns its code.
//
// Run from the repository root: node polyglot/js/test_random_fill.js
// Exit 0 = every length fills and returns 0 in both bindings;
// exit 1 = a length throws or returns non-zero.
"use strict";

const path = require("node:path");

const ROOT = process.argv[2] || path.resolve(__dirname, "..", "..");

// --- Minimal WASM builder (LEB128 unsigned) ---
function uleb(n) {
  const out = [];
  do {
    let b = n & 0x7f;
    n >>= 7;
    if (n) b |= 0x80;
    out.push(b);
  } while (n);
  return out;
}
function section(id, payload) {
  return [id, ...uleb(payload.length), ...payload];
}
function vec(items) {
  return [...uleb(items.length), ...items.flat()];
}
function str(s) {
  const bytes = [...Buffer.from(s, "utf8")];
  return [...uleb(bytes.length), ...bytes];
}

function tinyModule() {
  const types = section(1, vec([
    [0x60, 0x00, 0x01, 0x7f], // () -> i32
    [0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f], // (i32, i32) -> i32
  ]));
  const imports = section(2, vec([
    [...str("env"), ...str("active_random_fill"), 0x00, 0x01],
  ]));
  const funcs = section(3, vec([[0x00], [0x01]]));
  const memory = section(5, vec([[0x00, 0x14]])); // min 20 pages (1,310,720 B)
  const exports = section(7, vec([
    [...str("memory"), 0x02, 0x00],
    [...str("active_infinity_abi_version"), 0x00, 0x01],
    [...str("call_fill"), 0x00, 0x02],
  ]));
  const code = section(10, vec([
    [...uleb(4), 0x00, 0x41, 0x01, 0x0b], // i32.const 1; end
    [...uleb(8), 0x00, 0x20, 0x00, 0x20, 0x01, 0x10, 0x00, 0x0b], // call_fill
  ]));
  return new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...types, ...imports, ...funcs, ...memory, ...exports, ...code,
  ]);
}

async function checkBinding(name, load) {
  const { callFill, memory } = await load();
  let failed = 0;
  for (const len of [65536, 65537, 70000, 1 << 20]) {
    // Zero the region first so "filled" is observable, not leftover bytes.
    memory().fill(0, 0, len);
    let code;
    try {
      code = callFill(0, len);
    } catch (error) {
      console.log(`${name} ${len} bytes: THROWS ${error.name}: ${error.message}`);
      failed += 1;
      continue;
    }
    if (code !== 0) {
      console.log(`${name} ${len} bytes: returned non-zero code ${code}`);
      failed += 1;
      continue;
    }
    const region = memory().subarray(0, len);
    let nonZero = 0;
    for (let i = 0; i < len; i++) if (region[i] !== 0) nonZero += 1;
    // Random bytes are ~255/256 non-zero; a fill that wrote nothing (or a
    // single first chunk only) is far below that.
    if (nonZero < len * 0.9) {
      console.log(`${name} ${len} bytes: returned 0 but only ${nonZero}/${len} bytes non-zero (incomplete fill)`);
      failed += 1;
      continue;
    }
    console.log(`${name} ${len} bytes: filled OK (code 0, ${nonZero}/${len} non-zero)`);
  }
  return failed;
}

async function main() {
  const bytes = tinyModule();
  // Sanity: the module itself must compile and export what we need.
  const check = await WebAssembly.instantiate(bytes, {
    env: { active_random_fill: () => 0 },
  });
  if (typeof check.instance.exports.call_fill !== "function") {
    throw new Error("synthetic module lacks call_fill");
  }

  let failed = 0;
  const { ActiveInfinity } = require(path.join(ROOT, "polyglot", "js", "active-infinity.js"));
  failed += await checkBinding("js", async () => {
    const ai = await ActiveInfinity.instantiate(bytes);
    return {
      callFill: (dest, len) => ai.exports.call_fill(dest, len),
      memory: () => new Uint8Array(ai.memory.buffer),
    };
  });
  const { Reference } = require(path.join(ROOT, "polyglot", "assemblyscript", "host.js"));
  failed += await checkBinding("as", async () => {
    const ref = await Reference.load(bytes);
    return {
      callFill: (dest, len) => ref.exports.call_fill(dest, len),
      memory: () => new Uint8Array(ref.exports.memory.buffer),
    };
  });
  if (failed > 0) {
    console.log(`FAIL: ${failed} length(s) trap or fail (INF-POLY-01)`);
    process.exit(1);
  }
  console.log("PASS: every length fills without trapping in both bindings");
  process.exit(0);
}

main().catch((error) => {
  console.error(`ERROR: ${error.stack || error}`);
  process.exit(2);
});
