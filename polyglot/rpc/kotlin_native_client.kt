@file:OptIn(ExperimentalForeignApi::class)

// Thin Active RPC client over native ARP1 on TCP (Kotlin/Native, POSIX sockets).

import kotlinx.cinterop.*
import platform.posix.*


private val budget = ulongArrayOf(10000u, 67108864u, 5000u, 100000u, 256u, 100000u, 10000000u)

private fun appendU32(buffer: MutableList<Byte>, value: UInt) {
    for (index in 0 until 4) buffer.add(((value shr (8 * index)) and 0xffu).toByte())
}

private fun appendU64(buffer: MutableList<Byte>, value: ULong) {
    for (index in 0 until 8) buffer.add(((value shr (index * 8)) and 0xffu).toByte())
}

private fun appendString(buffer: MutableList<Byte>, text: String) {
    val bytes = text.encodeToByteArray()
    appendU32(buffer, bytes.size.toUInt())
    bytes.forEach { buffer.add(it) }
}

private fun request(id: ULong, method: String, payload: ByteArray, cap: ByteArray?): ByteArray {
    val buffer = mutableListOf<Byte>()
    "ARP1".encodeToByteArray().forEach { buffer.add(it) }
    buffer.add(1); buffer.add(1); buffer.add(0); buffer.add(0)
    appendU64(buffer, id)
    appendString(buffer, method)
    appendU32(buffer, 0u)
    appendU32(buffer, payload.size.toUInt())
    payload.forEach { buffer.add(it) }
    if (cap == null) {
        appendU32(buffer, 0u)
        return buffer.toByteArray()
    }
    appendU32(buffer, 1u)
    cap.forEach { buffer.add(it) }
    appendU32(buffer, 1u)
    appendString(buffer, "echo")
    for (value in budget) appendU64(buffer, value)
    buffer.add(0); buffer.add(0); buffer.add(0)
    return buffer.toByteArray()
}

private fun requireEnv(name: String): String {
    val pointer = getenv(name) ?: error("$name is required")
    return pointer.toKString()
}

private fun readFile(path: String): ByteArray {
    val file = fopen(path, "rb") ?: error("cannot open $path")
    try {
        fseek(file, 0, SEEK_END)
        val size = ftell(file).toInt()
        rewind(file)
        val buffer = ByteArray(size)
        if (size > 0) {
            buffer.usePinned { pinned ->
                check(fread(pinned.addressOf(0), 1u, size.toULong(), file).toInt() == size)
            }
        }
        return buffer
    } finally {
        fclose(file)
    }
}

private data class Response(val kind: Int, val method: String, val body: ByteArray)

private fun call(address: String, envelope: ByteArray): Response = memScoped {
    val split = address.lastIndexOf(':')
    val host = address.substring(0, split)
    val port = address.substring(split + 1).toInt()
    val fd = socket(AF_INET, SOCK_STREAM, 0)
    check(fd >= 0) { "socket failed" }
    val target = alloc<sockaddr_in>()
    target.sin_family = AF_INET.convert()
    target.sin_port = htons(port.toUShort())
    val parts = host.split(".")
    target.sin_addr.s_addr = parts[0].toUInt() or (parts[1].toUInt() shl 8) or
        (parts[2].toUInt() shl 16) or (parts[3].toUInt() shl 24)
    check(connect(fd, target.ptr.reinterpret(), sizeOf<sockaddr_in>().toUInt()) == 0) { "connect failed" }

    fun sendAll(bytes: ByteArray) {
        bytes.usePinned { pinned ->
            var offset = 0
            while (offset < bytes.size) {
                val sent = send(fd, pinned.addressOf(offset), (bytes.size - offset).toULong(), 0)
                check(sent > 0) { "send failed" }
                offset += sent.toInt()
            }
        }
    }
    fun recvAll(pointer: CPointer<ByteVar>, length: Int) {
        var offset = 0
        while (offset < length) {
            val received = recv(fd, pointer + offset, (length - offset).toULong(), 0)
            check(received > 0) { "recv failed" }
            offset += received.toInt()
        }
    }

    val header = ByteArray(4)
    val length = envelope.size.toUInt()
    header[0] = (length and 0xffu).toByte(); header[1] = ((length shr 8) and 0xffu).toByte()
    header[2] = ((length shr 16) and 0xffu).toByte(); header[3] = ((length shr 24) and 0xffu).toByte()
    sendAll(header)
    sendAll(envelope)

    val frameHeader = allocArray<ByteVar>(4)
    recvAll(frameHeader, 4)
    val bodyLength = (frameHeader[0].toUByte().toInt()) or
        (frameHeader[1].toUByte().toInt() shl 8) or
        (frameHeader[2].toUByte().toInt() shl 16) or
        (frameHeader[3].toUByte().toInt() shl 24)
    val bodyPointer = allocArray<ByteVar>(bodyLength)
    recvAll(bodyPointer, bodyLength)
    close(fd)

    val body = ByteArray(bodyLength) { bodyPointer[it].toUByte().toByte() }
    check(body.decodeToString(0, 4) == "ARP1" && body[4] == 1.toByte()) { "bad magic" }
    val methodLength = (body[16].toUByte().toInt()) or (body[17].toUByte().toInt() shl 8) or
        (body[18].toUByte().toInt() shl 16) or (body[19].toUByte().toInt() shl 24)
    Response(body[5].toInt(), body.decodeToString(20, 20 + methodLength), body)
}

private fun echoes(body: ByteArray, payload: ByteArray): Boolean {
    if (body.size < payload.size + 8) return false
    val caps = (body[body.size - 4].toUByte().toInt()) or (body[body.size - 3].toUByte().toInt() shl 8) or
        (body[body.size - 2].toUByte().toInt() shl 16) or (body[body.size - 1].toUByte().toInt() shl 24)
    if (caps != 0) return false
    return body.copyOfRange(body.size - 4 - payload.size, body.size - 4).contentEquals(payload)
}

fun main() {
    val address = requireEnv("ACTIVE_RPC_ADDR")
    val capHex = requireEnv("ACTIVE_RPC_CAP")
    val payloadPath = requireEnv("ACTIVE_RPC_PAYLOAD")
    check(capHex.length == 32) { "ACTIVE_RPC_CAP must be 32 hex characters" }
    val cap = ByteArray(16) { capHex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    val payload = readFile(payloadPath)

    val echo = call(address, request(42u, "echo", payload, cap))
    check(echo.kind == 2 && echoes(echo.body, payload)) { "echo failed" }

    val refused = call(address, request(43u, "refuse", payload, cap))
    check(refused.kind == 3 && refused.method == "rpc/method-not-granted") { "refusal mismatch" }

    val anonymous = call(address, request(44u, "echo", payload, null))
    check(anonymous.kind == 3 && anonymous.method == "rpc/unknown-capability") { "missing capability" }

    println("Kotlin/Native thin RPC PASS (echo, refusal, missing capability)")
}