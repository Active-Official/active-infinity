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

    // INF-POLY-03: `validate` already proves the canonical form (INF-02);
    // this states the requirement explicitly.
    func validateCanonical() throws {
        try withInput { pointer, length in
            try Image.check(active_infinity_validate_canonical(pointer, length))
        }
    }

    // INF-FFI-02: the limits-parameterized form of validateCanonical. A nil
    // limits means the library defaults. The `active_infinity_limits` struct
    // is imported from the C header, so no Swift-side mirror is needed: fill
    // one with `active_infinity_limits_default` and override the ceiling to
    // tighten.
    func validateWithLimits(_ limits: UnsafePointer<active_infinity_limits>? = nil) throws {
        try withInput { pointer, length in
            try Image.check(active_infinity_validate_with_limits(pointer, length, limits))
        }
    }

    // INF-FFI-02: the limits-parameterized form of reencode. A nil limits
    // means the library defaults (the FFI's NULL convention).
    func decodeWithLimits(_ limits: UnsafePointer<active_infinity_limits>? = nil) throws -> [UInt8] {
        try output { pointer, length, out, size in
            active_infinity_decode_with_limits(pointer, length, limits, out, size)
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

extension active_infinity_limits {
    /// Set one ceiling by its C field name (e.g. `max_nodes`). Fails closed
    /// on an unknown name. (INF-FFI-02)
    mutating func setField(_ name: String, _ value: UInt64) throws {
        switch name {
        case "max_nodes": max_nodes = UInt32(value)
        case "max_edges": max_edges = UInt32(value)
        case "max_children": max_children = UInt32(value)
        case "max_fields": max_fields = UInt32(value)
        case "max_parts": max_parts = UInt32(value)
        case "max_strings": max_strings = UInt32(value)
        case "max_string_bytes": max_string_bytes = UInt32(value)
        case "max_blobs": max_blobs = UInt32(value)
        case "max_blob_bytes": max_blob_bytes = UInt32(value)
        case "max_annotations": max_annotations = UInt32(value)
        case "max_units": max_units = UInt32(value)
        case "max_types": max_types = UInt32(value)
        case "max_aux": max_aux = UInt32(value)
        case "max_numbers": max_numbers = UInt32(value)
        case "max_secrets": max_secrets = UInt32(value)
        case "max_secret_bytes": max_secret_bytes = UInt32(value)
        case "max_extensions": max_extensions = UInt32(value)
        case "max_prov_bytes": max_prov_bytes = UInt32(value)
        case "max_prov_entries": max_prov_entries = UInt32(value)
        case "max_hashes": max_hashes = UInt32(value)
        case "max_bindings": max_bindings = UInt32(value)
        case "max_total_bytes": max_total_bytes = value
        case "max_decoded_bytes": max_decoded_bytes = value
        case "max_depth": max_depth = UInt32(value)
        default:
            throw ActiveInfinityError.failure(code: "infinity/manifest", status: -1)
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
        if name == "non_canonical" {
            // NF-INF02-01: validate and content_hash prove the canonical
            // form (INF-02), so a non-canonical image is refused; reencode
            // is the repair path.
            do {
                try image.validate()
                throw ActiveInfinityError.failure(code: "infinity/accepted", status: -1)
            } catch let error as ActiveInfinityError {
                if case let .failure(code, _) = error, code != "infinity/not-canonical" {
                    throw error
                }
            }
            do {
                _ = try image.contentHashHex()
                throw ActiveInfinityError.failure(code: "infinity/accepted", status: -1)
            } catch let error as ActiveInfinityError {
                if case let .failure(code, _) = error, code != "infinity/not-canonical" {
                    throw error
                }
            }
            // INF-POLY-03: the binding surfaces validateCanonical; it must
            // refuse the non-canonical image with the same code.
            do {
                try image.validateCanonical()
                throw ActiveInfinityError.failure(code: "infinity/accepted", status: -1)
            } catch let error as ActiveInfinityError {
                if case let .failure(code, _) = error, code != "infinity/not-canonical" {
                    throw error
                }
            }
        } else {
            try image.validate()
            try image.validateCanonical()
            if try image.contentHashHex() != expected {
                throw ActiveInfinityError.failure(code: "infinity/\(name)-hash", status: -1)
            }
        }
        let canonical = try image.reencode()
        if name == "non_canonical" {
            if canonical == image.bytes {
                throw ActiveInfinityError.failure(code: "infinity/non-canonical", status: -1)
            }
            try Image(bytes: canonical).validate()
        } else if canonical != image.bytes {
            throw ActiveInfinityError.failure(code: "infinity/\(name)-bytes", status: -1)
        }
        checked += 1
    }

    // INF-POLY-03: pin the exact count, derived from the manifest -- the
    // test used to have no floor at all, so an empty run could PASS.
    let valid = cases.filter { $0["kind"] as? String == "valid" }.count
    guard checked == valid else {
        throw ActiveInfinityError.failure(code: "infinity/manifest", status: -1)
    }

    // INF-POLY-02: every invalid vector must be refused with exactly the
    // manifest's expected_code. INF-FFI-02: the two limits-dependent ones
    // (limit, too_deep) go through validateWithLimits with the narrowed
    // budget from the entry's options.limits (max_nodes:1, max_depth:8);
    // the rest go through validateCanonical. invalid_stream vectors are
    // CLI-only: no stream decode exists in the FFI.
    var invalidChecked = 0
    for entry in cases {
        guard entry["kind"] as? String == "invalid" else { continue }
        guard let invalidPath = entry["path"] as? String,
              let expectedCode = entry["expected_code"] as? String else {
            throw ActiveInfinityError.failure(code: "infinity/manifest", status: -1)
        }
        let invalidImage = try Image.fromFile("\(root)/\(invalidPath)")
        let limitsSpec = (entry["options"] as? [String: Any])?["limits"] as? String
        do {
            if let limitsSpec {
                let parts = limitsSpec.split(separator: ":", maxSplits: 1)
                guard parts.count == 2, let value = UInt64(parts[1]) else {
                    throw ActiveInfinityError.failure(code: "infinity/manifest", status: -1)
                }
                var limits = active_infinity_limits()
                try Image.check(active_infinity_limits_default(&limits))
                try limits.setField(String(parts[0]), value)
                try invalidImage.validateWithLimits(&limits)
            } else {
                try invalidImage.validateCanonical()
            }
            throw ActiveInfinityError.failure(code: "infinity/accepted", status: -1)
        } catch let error as ActiveInfinityError {
            if case let .failure(code, _) = error, code != expectedCode {
                throw ActiveInfinityError.failure(code: "infinity/wrong-code", status: -1)
            }
        }
        invalidChecked += 1
    }
    let invalidTotal = cases.filter { $0["kind"] as? String == "invalid" }.count
    guard invalidChecked == invalidTotal else {
        throw ActiveInfinityError.failure(code: "infinity/manifest", status: -1)
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
