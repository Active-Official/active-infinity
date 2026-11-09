@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

import kotlinx.cinterop.*
import platform.posix.*

/**
 * Kotlin/Native conformance over the C ABI, loaded with the platform
 * loader (`dlopen` on POSIX, `LoadLibrary` on Windows; see
 * PosixLoader.kt / WindowsLoader.kt, selected by build.sh).
 *
 * Dynamic loading keeps the binding independent of the compiler's bundled
 * sysroot: the executable only links libc, and the reference library is resolved
 * at run time from ACTIVE_INFINITY_LIB (or the system loader).
 */

/** A stable `infinity/...` failure from the reference codec. */
private class ActiveInfinityException(val code: String, val status: Int) :
    Exception("$code (status $status)")

private class Abi {
    val abiVersion: CPointer<CFunction<() -> UInt>> = symbol("active_infinity_abi_version")
    val lastError: CPointer<CFunction<() -> CPointer<ByteVar>?>> = symbol("active_infinity_last_error")
    val alloc: CPointer<CFunction<(ULong) -> CPointer<UByteVar>?>> = symbol("active_infinity_alloc")
    val free: CPointer<CFunction<(CPointer<UByteVar>?, ULong) -> Unit>> = symbol("active_infinity_free")
    val allocGen: CPointer<CFunction<(ULong, CPointer<ULongVar>?) -> CPointer<UByteVar>?>> =
        symbol("active_infinity_alloc_gen")
    val freeGen: CPointer<CFunction<(CPointer<UByteVar>?, ULong, ULong) -> Int>> =
        symbol("active_infinity_free_gen")
    val validate: CPointer<CFunction<(CPointer<UByteVar>?, ULong) -> Int>> =
        symbol("active_infinity_validate")
    // INF-POLY-03: `validate` already proves the canonical form (INF-02);
    // this states the requirement explicitly.
    val validateCanonical: CPointer<CFunction<(CPointer<UByteVar>?, ULong) -> Int>> =
        symbol("active_infinity_validate_canonical")
    // INF-FFI-02: caller-supplied budget. The limits struct is 112 bytes in
    // native memory (21 uint32 ceilings, then max_total_bytes and
    // max_decoded_bytes as uint64, then max_depth as uint32); a null limits
    // pointer means the library defaults.
    val limitsDefault: CPointer<CFunction<(CPointer<ByteVar>?) -> Int>> =
        symbol("active_infinity_limits_default")
    val validateWithLimits: CPointer<CFunction<(CPointer<UByteVar>?, ULong, CPointer<ByteVar>?) -> Int>> =
        symbol("active_infinity_validate_with_limits")
    val hash: CPointer<CFunction<(CPointer<UByteVar>?, ULong, CPointer<UByteVar>?) -> Int>> =
        symbol("active_infinity_content_hash")
    val reencode: CPointer<CFunction<(CPointer<UByteVar>?, ULong, CPointer<UByteVar>?, CPointer<ULongVar>?) -> Int>> =
        symbol("active_infinity_reencode")
    val redactedJson: CPointer<CFunction<(CPointer<UByteVar>?, ULong, CPointer<UByteVar>?, CPointer<ULongVar>?) -> Int>> =
        symbol("active_infinity_redacted_json")
    val fromActive: CPointer<CFunction<(CPointer<UByteVar>?, ULong, CPointer<ByteVar>?, CPointer<UByteVar>?, CPointer<ULongVar>?) -> Int>> =
        symbol("active_infinity_from_active")

    private fun <T : CFunction<*>> symbol(name: String): CPointer<T> =
        loadSymbol(handle, name)

    companion object {
        // XPL-INF-06: the library name and the load mechanism are per-OS.
        // The default used to be a hardcoded `libactive_infinity_ffi.so`
        // loaded with `dlopen`, which names no `.dll` and does not even
        // exist on the Windows (mingw) target. PosixLoader.kt and
        // WindowsLoader.kt implement openNativeLibrary/loadSymbol for
        // their platform; build.sh compiles exactly one of them.
        val handle: COpaquePointer by lazy { openNativeLibrary() }
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun readFile(path: String): ByteArray {
    val file = fopen(path, "rb") ?: error("cannot open $path")
    try {
        fseek(file, 0, SEEK_END)
        val size = ftell(file).toInt()
        check(size >= 0) { "cannot size $path" }
        rewind(file)
        val buffer = ByteArray(size)
        if (size > 0) {
            buffer.usePinned { pinned ->
                val read = fread(pinned.addressOf(0), 1u, size.toULong(), file)
                check(read.toInt() == size) { "short read on $path" }
            }
        }
        return buffer
    } finally {
        fclose(file)
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun lastError(abi: Abi): String {
    val pointer = abi.lastError() ?: return "infinity/unknown"
    return pointer.toKString()
}

private fun failure(abi: Abi, status: Int): Nothing =
    throw ActiveInfinityException(lastError(abi), status)

// INF-FFI-01: allocates generationally and returns the pointer with the
// generation the FFI handed out with it. The generation out-pointer is a
// memScoped ULongVar (not an FFI allocation), so the legacy pair is not
// involved. Free it with freeGen, never with the legacy free. A refused
// free_gen (stale handle) is a binding bug; it is ignored in the finally
// blocks rather than thrown, where it would mask the operation's own error.
@OptIn(ExperimentalForeignApi::class)
private fun allocGen(abi: Abi, length: ULong): Pair<CPointer<UByteVar>?, ULong> = memScoped {
    val generation = alloc<ULongVar>()
    generation.value = 0u
    val pointer = abi.allocGen(length, generation.ptr)
        ?: throw ActiveInfinityException("infinity/limit", -1)
    pointer to generation.value
}

@OptIn(ExperimentalForeignApi::class)
private fun freeGen(abi: Abi, allocation: Pair<CPointer<UByteVar>?, ULong>, length: ULong) {
    abi.freeGen(allocation.first, length, allocation.second)
}

@OptIn(ExperimentalForeignApi::class)
private fun withInput(abi: Abi, bytes: ByteArray, action: (CPointer<UByteVar>?, ULong) -> Unit) {
    if (bytes.isEmpty()) {
        action(null, 0u)
        return
    }
    val allocation = allocGen(abi, bytes.size.toULong())
    val pointer = allocation.first
    try {
        bytes.usePinned { pinned ->
            memcpy(pointer, pinned.addressOf(0), bytes.size.toULong())
        }
        action(pointer, bytes.size.toULong())
    } finally {
        freeGen(abi, allocation, bytes.size.toULong())
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun output(
    abi: Abi,
    bytes: ByteArray,
    call: (CPointer<UByteVar>?, ULong, CPointer<UByteVar>?, CPointer<ULongVar>?) -> Int,
): ByteArray = memScoped {
    var result = ByteArray(0)
    withInput(abi, bytes) { input, length ->
        val size = alloc<ULongVar>()
        size.value = 0u
        var status = call(input, length, null, size.ptr)
        if (status == 0) return@withInput // an empty result needs no buffer
        if (status != -2) failure(abi, status)
        val required = size.value.toInt()
        if (required > 0) {
            val allocation = allocGen(abi, required.toULong())
            val buffer = allocation.first
            try {
                size.value = required.toULong()
                status = call(input, length, buffer, size.ptr)
                if (status != 0) failure(abi, status)
                val written = size.value.toInt()
                result = ByteArray(written)
                result = buffer!!.reinterpret<ByteVar>().readBytes(written)
            } finally {
                freeGen(abi, allocation, required.toULong())
            }
        }
    }
    result
}

@OptIn(ExperimentalForeignApi::class)
private fun fromActive(abi: Abi, source: ByteArray, name: String): ByteArray = memScoped {
    var result = ByteArray(0)
    withInput(abi, source) { input, length ->
        val size = alloc<ULongVar>()
        size.value = 0u
        var status = abi.fromActive(input, length, name.cstr.ptr, null, size.ptr)
        if (status == 0) return@withInput
        if (status != -2) failure(abi, status)
        val required = size.value.toInt()
        if (required > 0) {
            val allocation = allocGen(abi, required.toULong())
            val buffer = allocation.first
            try {
                size.value = required.toULong()
                status = abi.fromActive(input, length, name.cstr.ptr, buffer, size.ptr)
                if (status != 0) failure(abi, status)
                val written = size.value.toInt()
                result = ByteArray(written)
                result = buffer!!.reinterpret<ByteVar>().readBytes(written)
            } finally {
                freeGen(abi, allocation, required.toULong())
            }
        }
    }
    result
}

@OptIn(ExperimentalForeignApi::class)
fun main() {
    val abi = Abi()
    if (abi.abiVersion() != 1u) {
        throw ActiveInfinityException("infinity/abi-mismatch", -1)
    }

    val root = "."
    val manifest = readFile("$root/conformance/manifest.json").decodeToString()
    val case = Regex("(?s)\"path\"\\s*:\\s*\"([^\"]+)\".*?\"content_hash\"\\s*:\\s*\"([^\"]+)\"")
    // INF-POLY-02: the invalid-case pattern. It anchors on
    // `"kind": "invalid"` with the closing quote, so it never matches
    // `"kind": "invalid_stream"`; the `.*?` spans the options object,
    // which sits between path and expected_code and never contains an
    // expected_code of its own.
    val invalidCase = Regex("(?s)\"kind\"\\s*:\\s*\"invalid\".*?\"name\"\\s*:\\s*\"([^\"]+)\".*?\"path\"\\s*:\\s*\"([^\"]+)\".*?\"options\"\\s*:\\s*\\{([^}]*)\\}.*?\"expected_code\"\\s*:\\s*\"([^\"]+)\"")
    val limitsOption = Regex("\"limits\"\\s*:\\s*\"([^\"]+)\"")

    var checked = 0
    for (match in case.findAll(manifest)) {
        val path = match.groupValues[1]
        val expected = match.groupValues[2]
        if (!path.contains("/valid/")) continue
        val image = readFile("$root/$path")
        if (path.contains("non_canonical")) {
            // NF-INF02-01: validate and content_hash prove the canonical
            // form (INF-02), so a non-canonical image is refused; reencode
            // is the repair path.
            withInput(abi, image) { pointer, length ->
                val status = abi.validate(pointer, length)
                if (status == 0) error("$path: non-canonical image was validated")
                check(lastError(abi) == "infinity/not-canonical") { "$path: wrong code ${lastError(abi)}" }
            }
            val hash = ByteArray(32)
            withInput(abi, image) { pointer, length ->
                hash.usePinned { pinned ->
                    val status = abi.hash(pointer, length, pinned.addressOf(0).reinterpret())
                    if (status == 0) error("$path: non-canonical image was hashed")
                    check(lastError(abi) == "infinity/not-canonical") { "$path: wrong code ${lastError(abi)}" }
                }
            }
            // INF-POLY-03: the binding surfaces validateCanonical; it must
            // refuse the non-canonical image with the same code.
            withInput(abi, image) { pointer, length ->
                val status = abi.validateCanonical(pointer, length)
                if (status == 0) error("$path: non-canonical image passed validateCanonical")
                check(lastError(abi) == "infinity/not-canonical") { "$path: wrong code ${lastError(abi)}" }
            }
        } else {
            withInput(abi, image) { pointer, length ->
                val status = abi.validate(pointer, length)
                if (status != 0) failure(abi, status)
            }
            withInput(abi, image) { pointer, length ->
                val status = abi.validateCanonical(pointer, length)
                if (status != 0) failure(abi, status)
            }

            val hash = ByteArray(32)
            withInput(abi, image) { pointer, length ->
                hash.usePinned { pinned ->
                    val status = abi.hash(pointer, length, pinned.addressOf(0).reinterpret())
                    if (status != 0) failure(abi, status)
                }
            }
            val actual = hash.joinToString("") {
                it.toInt().and(0xff).toString(16).padStart(2, '0')
            }
            check(actual == expected) { "$path: hash $actual, want $expected" }
        }

        val canonical = output(abi, image) { input, length, out, size ->
            abi.reencode(input, length, out, size)
        }
        if (path.contains("non_canonical")) {
            check(!canonical.contentEquals(image)) { "$path: expected changed bytes" }
            withInput(abi, canonical) { pointer, length ->
                val status = abi.validate(pointer, length)
                if (status != 0) failure(abi, status)
            }
        } else {
            check(canonical.contentEquals(image)) { "$path: canonical bytes changed" }
        }
        checked++
    }
    // INF-POLY-03: pin the exact count, derived from the manifest --
    // a slack `>=` let a dropped vector pass silently.
    val valid = Regex("\"kind\": \"valid\"").findAll(manifest).count()
    check(checked == valid) { "manifest vectors not exercised: $checked of $valid" }

    // INF-POLY-02: every invalid vector must be refused with exactly the
    // manifest's expected_code. INF-FFI-02: the two limits-dependent ones
    // (limit, too_deep) go through validateWithLimits with the narrowed
    // budget from the entry's options.limits (max_nodes:1, max_depth:8);
    // the rest go through validateCanonical. invalid_stream vectors are
    // CLI-only: no stream decode exists in the FFI. The limits struct is
    // 112 bytes in native memory; only the two fields the manifest narrows
    // are written (max_nodes at offset 0, max_depth at offset 104).
    var invalidChecked = 0
    for (match in invalidCase.findAll(manifest)) {
        val invalidName = match.groupValues[1]
        val invalidPath = match.groupValues[2]
        val invalidOptions = match.groupValues[3]
        val expectedCode = match.groupValues[4]
        val invalidImage = readFile("$root/$invalidPath")
        withInput(abi, invalidImage) { pointer, length ->
            val limitsMatch = limitsOption.find(invalidOptions)
            val status = if (limitsMatch != null) {
                val parts = limitsMatch.groupValues[1].split(":", limit = 2)
                // The limits struct is 112 bytes in native memory, allocated
                // with the FFI's own allocator (withInput is not in a
                // memScoped, so allocArray is unavailable).
                val limitsAllocation = allocGen(abi, 112u)
                val limits = limitsAllocation.first ?: error("$invalidName: cannot allocate limits")
                try {
                    check(abi.limitsDefault(limits.reinterpret<ByteVar>()) == 0) { "$invalidName: limitsDefault failed" }
                    val offset = when (parts[0]) {
                        "max_nodes" -> 0
                        "max_depth" -> 104
                        else -> error("$invalidName: unknown limits field ${parts[0]}")
                    }
                    val bytes: CPointer<ByteVar> = limits.reinterpret<ByteVar>()!!
                    val slot: CPointer<UIntVar> = (bytes + offset)!!.reinterpret()!!
                    slot.pointed.value = parts[1].toUInt()
                    abi.validateWithLimits(pointer, length, limits.reinterpret())
                } finally {
                    freeGen(abi, limitsAllocation, 112u)
                }
            } else {
                abi.validateCanonical(pointer, length)
            }
            if (status == 0) error("$invalidName: invalid image was accepted")
            check(lastError(abi) == expectedCode) { "$invalidName: wrong code ${lastError(abi)}" }
        }
        invalidChecked++
    }
    val invalidTotal = Regex("\"kind\": \"invalid\"").findAll(manifest).count()
    check(invalidChecked == invalidTotal) { "manifest invalid vectors were not exercised: $invalidChecked of $invalidTotal" }

    val source = "port = 8080\nname = \"kotlin-native\"\n".encodeToByteArray()
    val first = fromActive(abi, source, "kn.active")
    val second = fromActive(abi, source, "kn.active")
    check(first.contentEquals(second)) { "Active source not deterministic" }
    withInput(abi, first) { pointer, length ->
        val status = abi.validate(pointer, length)
        if (status != 0) failure(abi, status)
    }

    val full = readFile("$root/tests/vectors/valid/full.ainf")
    val json = output(abi, full) { input, length, out, size ->
        abi.redactedJson(input, length, out, size)
    }.decodeToString()
    check(!json.contains("CANARY_SECRET_")) { "secret canary survived" }
    check(json.trimStart().startsWith("{")) { "redacted JSON looks wrong" }

    val junk = byteArrayOf(0xff.toByte(), 0xff.toByte())
    withInput(abi, junk) { pointer, length ->
        check(abi.validate(pointer, length) != 0) { "malformed input accepted" }
        check(lastError(abi).startsWith("infinity/")) { "unstable code" }
    }

    println("Kotlin/Native conformance PASS ($checked vectors, ABI 1)")
}
