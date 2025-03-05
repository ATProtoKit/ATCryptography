// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "ATCryptography",
    platforms: [
        .iOS(.v14),
        .macOS(.v13),
        .tvOS(.v14),
        .visionOS(.v1),
        .watchOS(.v9)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "ATCryptography",
            targets: ["ATCryptography"]),
    ],
    dependencies: [
        .package(url: "https://github.com/ATProtoKit/Base58Swift.git", from: "2.1.15"),
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "4.0.0"),
        .package(url: "https://github.com/21-DOT-DEV/swift-secp256k1.git", from: "0.18.0")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "ATCryptography",
            dependencies: [
                .product(name: "Base58Swift", package: "Base58Swift"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "secp256k1", package: "swift-secp256k1")
            ]),
        .testTarget(
            name: "ATCryptographyTests",
            dependencies: ["ATCryptography"]
        ),
    ]
)
