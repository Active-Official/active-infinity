// Thin Active RPC client over native ARP1 on TCP (Swift, POSIX sockets).
//
//   swiftc -O polyglot/rpc/rpc_client.swift -o /tmp/rpc-client-swift

#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif
import Foundation

let budget: [UInt64] = [10000, 64 << 20, 5000, 100000, 256, 100000, 10000000]

func require(_ name: String) -> String {
    guard let value = getenv(name), let text = String(validatingUTF8: value), !text.isEmpty else {
        FileHandle.standardError.write(Data("\(name) is required\n".utf8))
        exit(2)
    }
    return text
}

func appendU32(_ buffer: inout [UInt8], _ value: UInt32) {
    for index in 0..<4 { buffer.append(UInt8((value >> (8 * UInt32(index))) & 0xff)) }
}

func appendU64(_ buffer: inout [UInt8], _ value: UInt64) {
    for index in 0..<8 { buffer.append(UInt8((value >> (8 * UInt64(index))) & 0xff)) }
}

func appendString(_ buffer: inout [UInt8], _ text: String) {
    let bytes = Array(text.utf8)
    appendU32(&buffer, UInt32(bytes.count))
    buffer.append(contentsOf: bytes)
}

func request(id: UInt64, method: String, payload: [UInt8], cap: [UInt8]?) -> [UInt8] {
    var buffer: [UInt8] = Array("ARP1".utf8)
    buffer.append(contentsOf: [1, 1, 0, 0])
    appendU64(&buffer, id)
    appendString(&buffer, method)
    appendU32(&buffer, 0)
    appendU32(&buffer, UInt32(payload.count))
    buffer.append(contentsOf: payload)
    guard let cap else {
        appendU32(&buffer, 0)
        return buffer
    }
    appendU32(&buffer, 1)
    buffer.append(contentsOf: cap)
    appendU32(&buffer, 1)
    appendString(&buffer, "echo")
    for value in budget { appendU64(&buffer, value) }
    buffer.append(contentsOf: [0, 0, 0])
    return buffer
}

func call(_ address: String, _ envelope: [UInt8]) throws -> (Int, String, [UInt8]) {
    let split = address.lastIndex(of: ":")!
    let host = String(address[..<split])
    let port = UInt16(address[address.index(after: split)...])!
    let descriptor = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
    guard descriptor >= 0 else { throw NSError(domain: "rpc", code: 1) }
    var target = sockaddr_in()
    target.sin_family = sa_family_t(AF_INET)
    target.sin_port = port.bigEndian
    _ = inet_pton(AF_INET, host, &target.sin_addr)
    let connected = withUnsafePointer(to: &target) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard connected == 0 else { close(descriptor); throw NSError(domain: "rpc", code: 2) }

    var frame = [UInt8]()
    appendU32(&frame, UInt32(envelope.count))
    frame.append(contentsOf: envelope)
    var written = 0
    while written < frame.count {
        let sent = frame.withUnsafeBytes { send(descriptor, $0.baseAddress!.advanced(by: written), frame.count - written, 0) }
        guard sent > 0 else { close(descriptor); throw NSError(domain: "rpc", code: 3) }
        written += sent
    }

    var header = [UInt8](repeating: 0, count: 4)
    try readExact(descriptor, &header)
    let length = header.withUnsafeBytes { $0.load(as: UInt32.self) }
    var body = [UInt8](repeating: 0, count: Int(length))
    try readExact(descriptor, &body)
    close(descriptor)
    guard body.count >= 20, String(decoding: body[0..<4], as: UTF8.self) == "ARP1", body[4] == 1 else {
        throw NSError(domain: "rpc", code: 4)
    }
    let methodLength = body[16..<20].withUnsafeBytes { $0.load(as: UInt32.self) }
    let method = String(decoding: body[20..<(20 + Int(methodLength))], as: UTF8.self)
    return (Int(body[5]), method, body)
}

func readU32(_ data: [UInt8], _ offset: Int) -> UInt32 {
    var value: UInt32 = 0
    for index in 0..<4 { value |= UInt32(data[offset + index]) << (8 * UInt32(index)) }
    return value
}

func readU64(_ data: [UInt8], _ offset: Int) -> UInt64 {
    var value: UInt64 = 0
    for index in 0..<8 { value |= UInt64(data[offset + index]) << (8 * UInt64(index)) }
    return value
}

func echoes(_ body: [UInt8], _ payload: [UInt8]) -> Bool {
    guard body.count >= payload.count + 8 else { return false }
    guard readU32(body, body.count - 4) == 0 else { return false }
    return Array(body[(body.count - 4 - payload.count)..<(body.count - 4)]) == payload
}

func readExact(_ descriptor: Int32, _ buffer: inout [UInt8]) throws {
    var offset = 0
    let total = buffer.count
    while offset < total {
        let received = buffer.withUnsafeMutableBytes {
            recv(descriptor, $0.baseAddress!.advanced(by: offset), total - offset, 0)
        }
        guard received > 0 else { throw NSError(domain: "rpc", code: 5) }
        offset += received
    }
}

let address = require("ACTIVE_RPC_ADDR")
let capHex = require("ACTIVE_RPC_CAP")
let payloadPath = require("ACTIVE_RPC_PAYLOAD")
guard capHex.count == 32 else {
    FileHandle.standardError.write(Data("ACTIVE_RPC_CAP must be 32 hex characters\n".utf8))
    exit(2)
}
var cap = [UInt8]()
var index = capHex.startIndex
while index < capHex.endIndex {
    let next = capHex.index(index, offsetBy: 2)
    cap.append(UInt8(String(capHex[index..<next]), radix: 16)!)
    index = next
}
let payload = [UInt8](try Data(contentsOf: URL(fileURLWithPath: payloadPath)))

do {
    var response = try call(address, request(id: 42, method: "echo", payload: payload, cap: cap))
    guard response.0 == 2, readU64(response.2, 8) == 42, echoes(response.2, payload) else {
        throw NSError(domain: "rpc", code: 10)
    }
    response = try call(address, request(id: 43, method: "refuse", payload: payload, cap: cap))
    guard response.0 == 3, response.1 == "rpc/method-not-granted" else {
        throw NSError(domain: "rpc", code: 11)
    }
    response = try call(address, request(id: 44, method: "echo", payload: payload, cap: nil))
    guard response.0 == 3, response.1 == "rpc/unknown-capability" else {
        throw NSError(domain: "rpc", code: 12)
    }
    print("Swift thin RPC PASS (echo, refusal, missing capability)")
} catch {
    FileHandle.standardError.write(Data("FAIL \(error)\n".utf8))
    exit(1)
}
