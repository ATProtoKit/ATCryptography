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

    /// Compresses an uncompressed p256 public key.
    ///
    /// The uncompressed key
    ///
    /// - Parameter publicKey: The uncompressed public key as a byte array. Must have exactly
    /// 65 bytes.
    /// - Returns: The compressed public key as a 33-byte array.
    ///
    /// - Throws: `EllipticalCurveEncodingError.invalidKeyLength` if the key length is incorrect.
    public static func compressPublicKey(_ publicKey: [UInt8]) throws -> [UInt8] {
        guard let publicKeyData = try? secp256k1.Signing.PublicKey(dataRepresentation: publicKey, format: .compressed) else {
            throw EllipticalCurveEncodingError.invalidKeyLength(expected: 65, actual: publicKey.count)
        }

        return Array(publicKeyData.dataRepresentation)
    }

    /// Decompresses a compressed p256 public key.
    ///
    /// - Parameter publicKey: The compressed public key as a byte array (33 bytes: `0x02/0x03 || X`).
    /// - Returns: The uncompressed public key as a byte array (65 bytes: `0x04 || X || Y`).
    ///
    /// - Throws: `EllipticalCurveEncodingError.invalidKeyLength` if the key length is incorrect.
    ///           `EllipticalCurveEncodingError.keyDecodingFailed` if the key decoding failed.
    public static func decompressPublicKey(_ publicKey: [UInt8]) throws -> [UInt8] {
        guard publicKey.count == 33 else {
            throw EllipticalCurveEncodingError.invalidKeyLength(expected: 33, actual: publicKey.count)
        }

        let data = Data(publicKey)
        guard let publicKey = try? secp256k1.Signing.PublicKey(dataRepresentation: data, format: .uncompressed) else {
            throw EllipticalCurveEncodingError.keyDecodingFailed
        }

        return Array(publicKey.dataRepresentation)
    }
}
