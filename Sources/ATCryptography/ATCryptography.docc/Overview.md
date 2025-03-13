# ``ATCryptography``

Create and manage cryptographic keys and signatures for the AT Protocol.

@Metadata {
    @PageColor(blue)
}

## Overview

ATCryptography is a Swift package that contains ways to manage cryptography within the AT Protocol and Bluesky. The helpers will give you an easy way to create public and private keys, signatures, securely random numbers, and more.

The AT Protocol uses two elliptical curves:
- "p256," otherwise known as "secp256r1" or "NIST P-256."
- "k256," otherwise known as "secp256k1" or "NIST K-256."

The technical details of atproto's cryptography can be viewed in the [Cryptography section](https://atproto.com/specs/cryptography) of the AT Protocol website.

This library works best with ATProtoKit and the rest of the famiy of Swift packages related to the project. However, you are also free to use other atproto Swift packages that might not be related to ATProtoKit.

The package fully open sourced and is licenced under the Apache 2.0 licence. You can take a look at it and make contribitions to it on [GitHub](https://github.com/ATProtoKit/ATCryptography). The Swift code has been converted from the official TypeScript code in the AT Protocol's [crypto package](https://github.com/bluesky-social/atproto/tree/main/packages/crypto), but written in a type-safe way without sacrificing speed.

## Topics

### Public and Private Key Management

- ``K256Keypair``
- ``P256Keypair``
- ``Keypair``
- ``ExportableKeypair``

### Public Key Encoding

- ``K256Encoding``
- ``P256Encoding``

### Operations

- ``K256Operations``
- ``P256Operations``
- ``DIDKey``

### Signature Handling

- ``SignatureVerifier``
- ``Signer``

### Hashing

- ``SHA256Hasher``

### Secure Random Number Generation

- ``SecureRandom``

### Plugins

- ``plugins``
- ``K256Plugin``
- ``P256Plugin``
- ``DIDKeyPlugin``

### Base Encoding and Decoding

- ``Base16``
- ``Base32``
- ``Base58``
- ``Base58Alphabet``
- ``Base64URL``

### Utilities

- ``ATCryptographyTools``
- ``Multibase``
- ``ParsedMultikey``
- ``VerifyOptions``
- ``DIDable``
- ``DataConvertible``

### Global Variables

- ``base58MultibasePrefix``
- ``didKeyPrefix``
- ``p256DIDPrefix``
- ``k256DIDPrefix``
- ``p256JWTAlgorithm``
- ``k256JWTAlgorithm``

### Errors

- ``ATCryptographyToolsError``
- ``Base58Error``
- ``DIDKeyError``
- ``EllipticalCurveEncodingError``
- ``EllipticalCurveKeypairError``
- ``EllipticalCurveOperationsError``
- ``MultibaseError``
- ``SecureRandomError``
- ``SignatureVerificationError``
