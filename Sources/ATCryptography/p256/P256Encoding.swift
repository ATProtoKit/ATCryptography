//
//  P256Encoding.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-06.
//

import Foundation
import CryptoKit

/// A collection of utility functions for handling p256 public key encoding.
public struct P256Encoding {

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
        guard let publicKeyData = try? P256.Signing.PublicKey(rawRepresentation: publicKey) else {
            throw EllipticalCurveEncodingError.invalidKeyLength(expected: 65, actual: publicKey.count)
        }

        return Array(publicKeyData.compactRepresentation ?? Data())
    }

    /// Decompresses a compressed p256 public key.
    ///
    /// - Parameter publicKey: The compressed public key as a byte array. Must have exactly
    /// 33 bytes.
    /// - Returns: The uncompressed public key as a 65-byte array.
    ///
    /// - Throws: `EllipticalCurveEncodingError.invalidKeyLength` if the key length is incorrect.
    ///           `EllipticalCurveEncodingError.keyDecodingFailed` if the key decoding failed.
    public static func decompressPublicKey(_ publicKey: [UInt8]) throws -> [UInt8] {
        guard publicKey.count == 33 else {
            throw EllipticalCurveEncodingError.invalidKeyLength(expected: 33, actual: publicKey.count)
        }

        let data = Data(publicKey)
        guard let publicKey = try? P256.Signing.PublicKey(compactRepresentation: data) else {
            throw EllipticalCurveEncodingError.keyDecodingFailed
        }

        return Array(publicKey.rawRepresentation)
    }
}
