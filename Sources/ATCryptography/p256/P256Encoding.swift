//
//  P256Encoding.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-06.
//

import Foundation
import Crypto

/// A collection of utility functions for handling p256 public key encoding.
public struct P256Encoding {

    /// Compresses an uncompressed p256 public key.
    ///
    /// The public key must have exactly 65 bytes and the first prefix should be `0x04`. However,
    /// the prefix will automatically be added if it's 64 bytes instead.
    ///
    /// - Note: The prefix will be added automatically if If the public key has 64 bytes, then the prefix will be added automatically.
    ///
    /// - Parameter publicKey: The uncompressed public key as a byte array. Must have exactly
    /// 65 bytes and contain.
    /// - Returns: The compressed public key as a 33-byte array.
    ///
    /// - Throws: `EllipticalCurveEncodingError.invalidKeyLength` if the key length is incorrect.
    public static func compress(publicKey: [UInt8]) throws -> [UInt8] {
        let rawKey: [UInt8]

        switch publicKey.count {
            case 65 where publicKey.first == 0x04:
                // Remove the uncompressed prefix (0x04).
                rawKey = Array(publicKey.dropFirst())

            case 64:
                // Already in raw format.
                rawKey = publicKey

            default:
                throw EllipticalCurveEncodingError.invalidKeyLength(expected: 65, actual: publicKey.count)
        }

        // Convert to a compressed public key.
        let key = try P256.Signing.PublicKey(rawRepresentation: Data(rawKey))
        if #available(iOS 16, tvOS 16, *) {
            return Array(key.compressedRepresentation)
        } else {
            return Array(try key.compressedRepresentationCompat())
        }
    }

    /// Decompresses a compressed p256 public key.
    ///
    /// The public key must have exactly 33 bytes and the first prefix should be either `0x02` or
    /// `0x03`, depending on whether the second half of the key is even or odd.. However,
    /// the prefix will automatically be added if it's 32 bytes instead.
    ///
    /// - Parameters:
    ///   - publicKey: The compressed public key as a byte array. Must have exactly 33 bytes.
    ///   - shouldAddPrefix: Determines whether the prefix should be added or not.
    ///   Defaults to `false`.
    /// - Returns: The uncompressed public key.
    ///
    /// - Throws: `EllipticalCurveEncodingError.invalidKeyLength` if the key length is incorrect.
    ///           `EllipticalCurveEncodingError.keyDecodingFailed` if the key decoding failed.
    public static func decompress(publicKey: [UInt8], shouldAddPrefix: Bool = false) throws -> [UInt8] {
        let compressedPublicKey: Data

        switch publicKey.count {
            case 33 where publicKey.first == 0x02 || publicKey.first == 0x03:
                // Remove prefix before using CryptoKit.
                compressedPublicKey = Data(publicKey)

            case 32:
                // Already in raw format.
                compressedPublicKey = Data(publicKey)

            default:
                throw EllipticalCurveEncodingError.invalidKeyLength(expected: 33, actual: publicKey.count)
        }

        // Convert to an uncompressed public key.
        var uncompressedRawPublicKey: [Data.Element]
        if #available(iOS 16.0, tvOS 16, *) {
            let key = try P256.Signing.PublicKey(compressedRepresentation: compressedPublicKey)
            uncompressedRawPublicKey = Array(key.rawRepresentation)
        } else {
            // Fallback on earlier versions
            let key = try CompressedP256.decompress(compressedPublicKey)
            uncompressedRawPublicKey = Array(key.rawRepresentation)
        }
//        var uncompressedRawPublicKey = Array(key.rawRepresentation)

        // Prepend the uncompressed prefix (0x04)
        if shouldAddPrefix {
            // Prepend the uncompressed key prefix (0x04) if not already present.
            if uncompressedRawPublicKey.first != 0x04 {
                uncompressedRawPublicKey.insert(0x04, at: 0)
            }
        } else {
            // Ensure the key is returned without the prefix.
            if uncompressedRawPublicKey.first == 0x04 && (uncompressedRawPublicKey.count - 1) != 63 {
                uncompressedRawPublicKey.removeFirst()
            }
        }

        return uncompressedRawPublicKey
    }
}
