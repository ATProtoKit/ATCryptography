//
//  Cryptography.swift
//  ATButler
//
//  Created by Christopher Jr Riley on 2025-03-03.
//

import Foundation
import Crypto
import secp256k1

/// The prefix used to indicate Base58 multibase encoding.
public let base58MultibasePrefix: Character = "z"

/// The `did:key` prefix.
public let didKeyPrefix: String = "did:key:"

/// The binary prefix used for p256-based decentralized identifiers (DIDs).
public let p256DIDPrefix: [UInt8] = [0x80, 0x24]

/// The binary prefix used for k256-based decentralized identifiers (DIDs).
public let k256DIDPrefix: [UInt8] = [0xe7, 0x01]

/// The ECDSA algorithm used for p256.
///
/// This is mainly used for signing and verifying JSON Web Tokens (JWT).
public let p256JWTAlgorithm: String = "ES256"

/// The ECDSA algorithm used for k256.
///
/// This is mainly used for signing and verifying JSON Web Tokens (JWT).
public let k256JWTAlgorithm: String = "ES256K"
