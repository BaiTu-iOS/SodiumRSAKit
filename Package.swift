// swift-tools-version: 5.9
// swiftformat:options --swiftversion 5.9
// Created by yuxilong on 2026/11/24.
import PackageDescription

let package = Package(
    name: "SodiumRSAKit",
    platforms: [.iOS(.v15)],
    products: [.library(name: "SodiumRSAKit", targets: ["SodiumRSAKit"])],
    targets: [
        .binaryTarget(name: "libsodium", path: "SodiumRSAKit/Sodium/libsodium.xcframework"),
        .target(
            name: "SodiumRSAKit",
            dependencies: ["libsodium"],
            path: "SodiumRSAKit",
            exclude: ["RSATool/LICENSE", "Sodium/NAChloride/LICENSE", "Sodium/SodiumObjc/LICENSE",
                      "Sodium/libsodium.LICENSE", "Sodium/libsodium.xcframework",
                      "Sodium/include/sodium/module.modulemap"],
            sources: ["RSATool", "Sodium/SodiumCrypto.m", "Sodium/NAChloride", "Sodium/SodiumObjc"],
            publicHeadersPath: ".",
            cSettings: [
                .headerSearchPath("Sodium"),
                .headerSearchPath("Sodium/NAChloride"),
                .headerSearchPath("Sodium/SodiumObjc"),
                .headerSearchPath("Sodium/include"),
                .headerSearchPath("Sodium/include/sodium"),
            ],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .testTarget(name: "SodiumRSAKitPackageTests", dependencies: ["SodiumRSAKit"], path: "Tests/PackageTests"),
    ]
)
