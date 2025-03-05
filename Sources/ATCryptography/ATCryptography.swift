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

///
class ATCryptography {
    static let base58MultibasePrefix: Character = "z"
    static let didKeyPrefix: String = "did:key:"

    static let secp256k1DIDPrefix: [UInt8] = [0xe7, 0x01]
    static let p256DIDPrefix: [UInt8] = [0x80, 0x24]

    static let p256JWTAlgorithm: String = "ES256"
    static let secp256k1JWTAlgorithm: String = "ES256K"
}
