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
                    "-lactive_infinity_ffi",
                ])
            ]
        ),
    ]
)
