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
    val validate: CPointer<CFunction<(CPointer<UByteVar>?, ULong) -> Int>> =
        symbol("active_infinity_validate")
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

@OptIn(ExperimentalForeignApi::class)
private fun withInput(abi: Abi, bytes: ByteArray, action: (CPointer<UByteVar>?, ULong) -> Unit) {
    if (bytes.isEmpty()) {
        action(null, 0u)
        return
    }
    val pointer = abi.alloc(bytes.size.toULong())
        ?: throw ActiveInfinityException("infinity/limit", -1)
    try {
        bytes.usePinned { pinned ->
            memcpy(pointer, pinned.addressOf(0), bytes.size.toULong())
        }
        action(pointer, bytes.size.toULong())
    } finally {
        abi.free(pointer, bytes.size.toULong())
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
            val buffer = abi.alloc(required.toULong())
                ?: throw ActiveInfinityException("infinity/limit", -1)
            try {
                size.value = required.toULong()
                status = call(input, length, buffer, size.ptr)
                if (status != 0) failure(abi, status)
                val written = size.value.toInt()
                result = ByteArray(written)
                result = buffer.reinterpret<ByteVar>().readBytes(written)
            } finally {
                abi.free(buffer, required.toULong())
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
            val buffer = abi.alloc(required.toULong())
                ?: throw ActiveInfinityException("infinity/limit", -1)
            try {
                size.value = required.toULong()
                status = abi.fromActive(input, length, name.cstr.ptr, buffer, size.ptr)
                if (status != 0) failure(abi, status)
                val written = size.value.toInt()
                result = ByteArray(written)
                result = buffer.reinterpret<ByteVar>().readBytes(written)
            } finally {
                abi.free(buffer, required.toULong())
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

    var checked = 0
    for (match in case.findAll(manifest)) {
        val path = match.groupValues[1]
        val expected = match.groupValues[2]
        if (!path.contains("/valid/")) continue
        val image = readFile("$root/$path")
        withInput(abi, image) { pointer, length ->
            val status = abi.validate(pointer, length)
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

        val canonical = output(abi, image) { input, length, out, size ->
            abi.reencode(input, length, out, size)
        }
        if (path.contains("non_canonical")) {
            check(!canonical.contentEquals(image)) { "$path: expected changed bytes" }
        } else {
            check(canonical.contentEquals(image)) { "$path: canonical bytes changed" }
        }
        checked++
    }
    check(checked >= 4) { "manifest vectors not exercised" }

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
