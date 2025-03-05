//
//  Cryptography.swift
//  ATButler
//
//  Created by Christopher Jr Riley on 2025-03-03.
//

import Foundation
import CryptoKit
import Crypto
import secp256k1

/// A class providing basic cryptographic helper objects used in the AT Protocol.
///
/// The AT Protocol uses both "secp256r1" (aka: "p256") and "secp256k1" (aka: "k256")
/// elliptic curves. For Bluesky, the k256 elliptic curves is used as the default.
///
/// - SeeAlso: The [Cyptography][cyptography] section of the AT Protocol specifications.
///
/// [cyptography]: https://atproto.com/specs/cryptography
class ATCryptography {

    /// The prefix used to indicate Base58 multibase encoding.
    static let base58MultibasePrefix: Character = "z"

    /// The `did:key` prefix.
    static let didKeyPrefix: String = "did:key:"

    /// The binary prefix used for p256-based decentralized identifiers (DIDs).
    static let p256DIDPrefix: [UInt8] = [0x80, 0x24]

    /// The binary prefix used for k256-based decentralized identifiers (DIDs).
    static let k256DIDPrefix: [UInt8] = [0xe7, 0x01]

    /// The ECDSA algorithm used for p256.
    ///
    /// This is mainly used for signing and verifying JSON Web Tokens (JWT).
    static let p256JWTAlgorithm: String = "ES256"

    /// The ECDSA algorithm used for k256.
    ///
    /// This is mainly used for signing and verifying JSON Web Tokens (JWT).
    static let secp256k1JWTAlgorithm: String = "ES256K"
}
