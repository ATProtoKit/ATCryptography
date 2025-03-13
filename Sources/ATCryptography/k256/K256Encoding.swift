//
//  K256Encoding.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-07.
//

import Foundation
import secp256k1

/// A collection of utility methods for handling k256 public key encoding.
public struct K256Encoding {

    /// Compresses an uncompressed k256 public key.
    ///
    /// - Parameter publicKey: The uncompressed public key as a byte array. Must have exactly
    /// 65 bytes.
    /// - Returns: The compressed public key as a 33-byte array.
    ///
    /// - Throws: `EllipticalCurveEncodingError.invalidKeyLength` if the key length is incorrect.
    public static func compress(publicKey: [UInt8]) throws -> [UInt8] {
        guard publicKey.count == 65,
              let firstByte = publicKey.first,
              firstByte == 4,
              let yLastByte = publicKey.last else {
            throw EllipticalCurveEncodingError.invalidKeyLength(expected: 65, actual: publicKey.count)
        }

        // Determine prefix based on the parity of y
        let prefix: UInt8 = (yLastByte & 1 == 1) ? 3 : 2

        // Preallocate a buffer to hold the result, avoiding unnecessary allocations
        var result = ContiguousArray<UInt8>(repeating: 0, count: 33)
        result[0] = prefix

        // Copy x-coordinate efficiently
        result[1...] = publicKey[1..<33]

        return Array(result) // Convert back if needed for compatibility


    }

    /// Decompresses a compressed k256 public key.
    ///
    /// - Parameter publicKey: The compressed public key as a byte array. Must have exactly
    /// 33 bytes.
    /// - Returns: The uncompressed public key.
    ///
    /// - Throws: `EllipticalCurveEncodingError.invalidKeyLength` if the key length is incorrect.
    ///           `EllipticalCurveEncodingError.keyDecodingFailed` if the key decoding failed.
    public static func decompress(publicKey: [UInt8]) throws -> [UInt8] {
        guard publicKey.count == 33,
              let firstByte = publicKey.first,
              (firstByte == 2 || firstByte == 3) else {
            throw EllipticalCurveEncodingError.invalidKeyLength(expected: 33, actual: publicKey.count)
        }

        // Create secp256k1 context.
        guard let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)) else {
            throw EllipticalCurveEncodingError.keyDecodingFailed
        }
        defer {
            secp256k1_context_destroy(context)
        }

        // Define secp256k1_pubkey struct.
        var cPubkey = secp256k1_pubkey()

        // Attempt to parse the compressed public key.
        guard secp256k1_ec_pubkey_parse(context, &cPubkey, publicKey, publicKey.count) == 1 else {
            throw EllipticalCurveEncodingError.keyDecodingFailed
        }

        // Preallocate uncompressed key buffer with a fixed size (avoids dynamic allocation).
        var uncompressedPubkey: [UInt8] = Array(repeating: 0, count: 65)
        var uncompressedKeyLen = 65

        // Serialize the parsed public key to an uncompressed format.
        guard secp256k1_ec_pubkey_serialize(
            context,
            &uncompressedPubkey,
            &uncompressedKeyLen,
            &cPubkey,
            UInt32(SECP256K1_EC_UNCOMPRESSED)
        ) == 1 else {
            throw EllipticalCurveEncodingError.keyDecodingFailed
        }

        // Return as an Array for API compatibility.
        return Array(uncompressedPubkey.prefix(uncompressedKeyLen))
    }
}
