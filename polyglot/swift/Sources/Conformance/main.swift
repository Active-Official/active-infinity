/// Active Infinity for Swift (C interop over the ABI).
///
/// One canonicalizer: the binding calls the Rust reference; conformance is the
/// shared manifest. The executable target is the conformance runner.

import CActiveInfinity
import Foundation

enum ActiveInfinityError: Error, CustomStringConvertible {
    case failure(code: String, status: Int32)

    var description: String {
        switch self {
        case let .failure(code, status):
            return "\(code) (status \(status))"
        }
    }
}

struct Image {
    static let abi: UInt32 = 1
    let bytes: [UInt8]

    init(bytes: [UInt8]) throws {
        if active_infinity_abi_version() != Image.abi {
            throw ActiveInfinityError.failure(code: "infinity/abi-mismatch", status: -1)
        }
        self.bytes = bytes
    }

    static func fromFile(_ path: String) throws -> Image {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return try Image(bytes: [UInt8](data))
    }

    static func lastError() -> String {
        guard let pointer = active_infinity_last_error() else {
            return "infinity/unknown"
        }
        return String(cString: pointer)
    }

    static func check(_ status: Int32) throws {
        if status != 0 {
            throw ActiveInfinityError.failure(code: lastError(), status: status)
        }
    }

    func withInput<T>(_ body: (UnsafePointer<UInt8>?, Int) throws -> T) rethrows -> T {
        if bytes.isEmpty {
            return try body(nil, 0)
        }
        return try bytes.withUnsafeBufferPointer { buffer in
            try body(buffer.baseAddress, buffer.count)
        }
    }

    func validate() throws {
        try withInput { pointer, length in
            try Image.check(active_infinity_validate(pointer, length))
        }
    }

    func contentHash() throws -> [UInt8] {
        var hash = [UInt8](repeating: 0, count: 32)
        try withInput { pointer, length in
            try hash.withUnsafeMutableBufferPointer { output in
                try Image.check(
                    active_infinity_content_hash(pointer, length, output.baseAddress)
                )
            }
        }
        return hash
    }

    func contentHashHex() throws -> String {
        try contentHash().map { String(format: "%02x", $0) }.joined()
    }

    func output(
        _ call: (UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<UInt8>?, UnsafeMutablePointer<Int>) -> Int32
    ) throws -> [UInt8] {
        try withInput { pointer, length in
            var required = 0
            let probe = call(pointer, length, nil, &required)
            if probe != -2 {
                try Image.check(probe)
                return []
            }
            if required == 0 {
                return []
            }
            var buffer = [UInt8](repeating: 0, count: required)
            var capacity = required
            try buffer.withUnsafeMutableBufferPointer { output in
                try Image.check(call(pointer, length, output.baseAddress, &capacity))
            }
            return Array(buffer.prefix(capacity))
        }
    }

    func reencode() throws -> [UInt8] {
        try output { input, length, out, size in
            active_infinity_reencode(input, length, out, size)
        }
    }

    func redactedJSON() throws -> String {
        let bytes = try output { input, length, out, size in
            active_infinity_redacted_json(input, length, out, size)
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    static func fromActive(_ source: String, name: String = "module.active") throws -> [UInt8] {
        let payload = Array(source.utf8)
        let nameBytes = Array("\(name)\u{0}".utf8)
        return try Image(bytes: payload).output { input, length, out, size in
            nameBytes.withUnsafeBufferPointer { namePointer in
                active_infinity_from_active(
                    input,
                    length,
                    UnsafeRawPointer(namePointer.baseAddress)?
                        .assumingMemoryBound(to: CChar.self),
                    out,
                    size
                )
            }
        }
    }
}

func main() throws {
    let root = FileManager.default.currentDirectoryPath
    let manifestData = try Data(contentsOf: URL(fileURLWithPath: "\(root)/conformance/manifest.json"))
    guard
        let manifest = try JSONSerialization.jsonObject(with: manifestData) as? [String: Any],
        let cases = manifest["cases"] as? [[String: Any]]
    else {
        throw ActiveInfinityError.failure(code: "infinity/manifest", status: -1)
    }

    var checked = 0
    for entry in cases {
        guard entry["kind"] as? String == "valid",
              let path = entry["path"] as? String,
              let expected = entry["content_hash"] as? String,
              let name = entry["name"] as? String
        else { continue }
        let image = try Image.fromFile("\(root)/\(path)")
        try image.validate()
        if try image.contentHashHex() != expected {
            throw ActiveInfinityError.failure(code: "infinity/\(name)-hash", status: -1)
        }
        let canonical = try image.reencode()
        if name == "non_canonical" {
            if canonical == image.bytes {
                throw ActiveInfinityError.failure(code: "infinity/non-canonical", status: -1)
            }
        } else if canonical != image.bytes {
            throw ActiveInfinityError.failure(code: "infinity/\(name)-bytes", status: -1)
        }
        checked += 1
    }

    let source = "port = 8080\nname = \"swift\"\n"
    let first = try Image.fromActive(source, name: "swift.active")
    let second = try Image.fromActive(source, name: "swift.active")
    if first != second {
        throw ActiveInfinityError.failure(code: "infinity/nondeterministic", status: -1)
    }
    try Image(bytes: first).validate()

    let full = try Image.fromFile("\(root)/tests/vectors/valid/full.ainf")
    let json = try full.redactedJSON()
    if json.contains("CANARY_SECRET_") {
        throw ActiveInfinityError.failure(code: "infinity/redaction", status: -1)
    }
    _ = try JSONSerialization.jsonObject(with: Data(json.utf8))

    do {
        try Image(bytes: [0xff, 0xff]).validate()
        throw ActiveInfinityError.failure(code: "infinity/accepted", status: -1)
    } catch let error as ActiveInfinityError {
        if case let .failure(code, _) = error, !code.hasPrefix("infinity/") {
            throw error
        }
    }

    print("Swift conformance PASS (\(checked) vectors, ABI \(Image.abi))")
}

do {
    try main()
} catch {
    FileHandle.standardError.write(Data("FAIL \(error)\n".utf8))
    exit(1)
}
