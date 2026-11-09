// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ActiveInfinity",
    targets: [
        .systemLibrary(
            name: "CActiveInfinity",
            path: "Sources/CActiveInfinity"
        ),
        .executableTarget(
            name: "Conformance",
            dependencies: ["CActiveInfinity"],
            path: "Sources/Conformance",
            linkerSettings: [
                .unsafeFlags([
                    "-L", "../../ffi/active-infinity-ffi/target/release",
                ]),
                // XPL-INF-06: the linked library is per-OS. On Linux and
                // macOS the FFI crate's static library is
                // `libactive_infinity_ffi.a`; on Windows the same crate
                // builds `active_infinity_ffi.lib` (static) and
                // `active_infinity_ffi.dll` + `active_infinity_ffi.dll.lib`
                // (shared). The executable links the shared import library
                // on Windows: linking the static library would also drag
                // in Rust std's Windows system libraries (ntdll, ws2_32,
                // bcrypt, ...), which are not on this link line, and the
                // link fails with undefined symbols. The `.dll` must be
                // next to the executable (or on PATH) at run time.
                .linkedLibrary("active_infinity_ffi", .when(platforms: [.linux, .macOS])),
                .linkedLibrary("active_infinity_ffi.dll", .when(platforms: [.windows])),
            ]
        ),
    ]
)
