<p align="center">
  <img src="https://github.com/ATProtoKit/ATCryptography/blob/main/Sources/ATCryptography/ATCryptography.docc/Resources/atcryptography_logo.png" height="128" alt="A logo for ATCryptography, which contains three stacks of rounded rectangles in an isometric top view. At the top stack, the at symbol is in a thick weight, with a pointed arrow at the tip. The background of the stack contains many 0s and 1s in a fade. The three stacks are lighter shades of blue.">
</p>

<h1 align="center">ATCryptography</h1>

<p align="center">Cryptographic utilities for the AT Protocol, written in Swift.</p>

<div align="center">

[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FATProtoKit%2FATCryptography%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/ATProtoKit/ATCryptography)
[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FATProtoKit%2FATCryptography%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/ATProtoKit/ATCryptography)
[![GitHub Repo stars](https://img.shields.io/github/stars/atprotokit/atcryptography?style=flat&logo=github)](https://github.com/ATProtoKit/ATCryptography)

</div>
<div align="center">

[![Static Badge](https://img.shields.io/badge/Follow-%40cjrriley.com-0073fa?style=flat&logo=bluesky&labelColor=%23151e27&link=https%3A%2F%2Fbsky.app%2Fprofile%2Fcjrriley.com)](https://bsky.app/profile/cjrriley.com)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/masterj93?color=%23cb5f96&link=https%3A%2F%2Fgithub.com%2Fsponsors%2FMasterJ93)](https://github.com/sponsors/MasterJ93)

</div>

This package implements cryptographic operations required by the AT Protocol, using Apple's [swift-crypto](https://github.com/apple/swift-crypto) and compatible libraries.
ATCryptography supports the following cryptographic systems:
- "p256," otherwise known as "secp256r1" or "NIST P-256."
- "k256," otherwise known as "secp256k1" or "NIST K-256."

The library provides helpers for key management, signing, verification, hashing, and encoding. These utilities are aligned with AT Protocol’s cryptographic requirements, including low-S signatures, byte representation compression, and string encodings.

For details on cryptography in the AT Protocol, refer to the [Cryptography section](https://atproto.com/specs/cryptography) of the specification.

## Installation
You can use the Swift Package Manager to download and import the library into your project:
```swift
dependencies: [
    .package(url: "https://github.com/ATProtoKit/ATCryptography.git", from: "0.1.0")
]
```

Then under `targets`:
```swift
targets: [
    .target(
        // name: "[name of target]",
        dependencies: [
            .product(name: "ATCryptography", package: "atcryptography")
        ]
    )
]
```

## Requirements
ATCryptography is designed to be a server application. For a Linux server, Swift 6.0 or later is required. The minimum requirements include:
- **Amazon Linux** 2
- **Debian** 12
- **Fedora** 39
- **Red Hat UBI** 9
- **Ubuntu** 20.04

You can also use it on macOS. Please target **macOS** 13 or later.

You can also use this project for any programs you make using Swift and running on **Docker**.

> [!WARNING]
> As of right now, Windows support is theoretically possible, but not has not been tested to work. Contributions and feedback on makjng it fully compatible for Windows and Windows Server are welcomed.

## Submitting Contributions and Feedback
While this project will change significantly, feedback, issues, and contributions are highly welcomed and encouraged. If you'd like to contribute to this project, please be sure to read both the [API Guidelines](https://github.com/ATProtoKit/ATCryptography/blob/main/API_GUIDELINES.md) as well as the [Contributor Guidelines](https://github.com/MasterJ93/ATProtoKit/blob/main/CONTRIBUTING.md) before submitting a pull request. Any issues (such as bug reports or feedback) can be submitted in the [Issues](https://github.com/ATProtoKit/ATCryptography/issues) tab. Finally, if there are any security vulnerabilities, please read [SECURITY.md](https://github.com/ATProtoKit/ATCryptography/blob/main/SECURITY.md) for how to report it.

If you have any questions, you can ask me on Bluesky ([@cjrriley.com](https://bsky.app/profile/cjrriley.com)). And while you're at it, give me a follow! I'm also active on the [Bluesky API Touchers](https://discord.gg/3srmDsHSZJ) Discord server.

## License
This Swift package is using the Apache 2.0 License. Please view [LICENSE.md](https://github.com/ATProtoKit/ATCryptography/blob/main/LICENSE.md) for more details.
