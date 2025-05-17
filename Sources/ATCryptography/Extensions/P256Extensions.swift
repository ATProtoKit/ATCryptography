//
//  P256Extensions.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-05-13.
//

import Foundation
import Crypto
import BigInt

extension P256.Signing.PublicKey {

    /// Returns the compressed SEC1 representation of a p256 public key,
    /// compatible with platforms where `.compressedRepresentation` is unavailable.
    ///
    /// The compressed form includes only the X coordinate and a prefix byte
    /// (0x02 for even Y, 0x03 for odd Y), following the SEC1 standard.
    ///
    /// - Warning: This should only be used for iOS 15 or earlier and tvOS 15 or earlier.
    ///
    /// - Returns: A 33-byte compressed public key.
    /// - Throws: An error if the raw representation is invalid or not uncompressed.
    internal func compressedRepresentationCompat() throws -> Data {
        let rawKey = self.rawRepresentation

        // Ensure it’s exactly 64 bytes: 32 bytes for X, 32 for Y.
        guard rawKey.count == 64 else {
            throw P256Error.invalidCompressedKey
        }

        let xCoordinate = rawKey.prefix(32)
        let yCoordinate = rawKey.suffix(32)

        guard let lastByteOfY = yCoordinate.last else {
            throw P256Error.invalidCompressedKey
        }

        let prefixByte: UInt8 = (lastByteOfY % 2 == 0) ? 0x02 : 0x03
        return Data([prefixByte]) + xCoordinate
    }

    /// Decompresses a compressed p256 public key into a full uncompressed SEC1 key,
    /// and initializes a `P256.Signing.PublicKey` from it.
    ///
    /// This function is designed to support older Apple platforms (iOS/tvOS 13–15)
    /// where `.init(compressedRepresentation:)` is unavailable.
    ///
    /// - Warning: This should only be used for iOS 15 or earlier and tvOS 15 or earlier.
    ///
    /// - Parameter compressedKey: The SEC1 compressed public key data.
    /// - Returns: A valid `P256.Signing.PublicKey`.
    /// - Throws: `P256Error.invalidCompressedKey` or `P256Error.pointNotOnCurve`
    ///   if the data is malformed or does not represent a point on the p256 curve.
    internal static func decompressP256PublicKey(compressed compressedKey: Data) throws -> P256.Signing.PublicKey {
        guard compressedKey.count == 33 else {
            throw P256Error.invalidCompressedKey
        }

        let prefixByte = compressedKey[0]
        guard prefixByte == 0x02 || prefixByte == 0x03 else {
            throw P256Error.invalidCompressedKey
        }

        let xBytes = compressedKey.dropFirst()
        let xCoordinate = BigUInt(xBytes)

        guard
            let prime = BigUInt("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", radix: 16),
            let b = BigUInt("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", radix: 16)
        else {
            throw P256Error.invalidCompressedKey
        }

        let a = prime - 3
        let ySquared = (xCoordinate.power(3, modulus: prime) + a * xCoordinate + b) % prime

        guard let yCoordinate = try modularSquareRoot(ySquared, prime: prime) else {
            throw P256Error.pointNotOnCurve
        }

        let isYOdd = yCoordinate % 2 == 1
        let shouldBeOdd = (prefixByte == 0x03)
        let finalYCoordinate = (isYOdd == shouldBeOdd) ? yCoordinate : (prime - yCoordinate)

        let xData = xCoordinate.serialize().pad(to: 32)
        let yData = finalYCoordinate.serialize().pad(to: 32)

        let uncompressedKey = xData + yData
        return try P256.Signing.PublicKey(rawRepresentation: uncompressedKey)
    }

    /// Computes the modular square root of a given number (`squareRoot`) modulo a prime (`prime`).
    ///
    /// This function is specifically optimized for the p256 curve, whose `prime` satisfies the condition
    /// `prime ≡ 3 mod 4`. This allows the use of a simplified square root computation:
    ///
    ///     sqrt(squareRoot) ≡ squareRoot^((prime + 1) / 4) mod prime
    ///
    /// This equation is valid only when `squareRoot` is a quadratic residue modulo `prime`. If `squareRoot`
    /// is not a square modulo `prime`, the function returns `nil`.
    ///
    /// - Warning: This should only be used for iOS 15 or earlier and tvOS 15 or earlier.
    ///
    /// - Parameters:
    ///   - squareRoot: The value whose modular square root is to be computed.
    ///   - prime: A prime modulus. For p256, this should be the curve's prime field.
    /// - Returns: The modular square root of `squareRoot` modulo `prime`, if it exists.
    ///
    /// - Throws: `P256Error.pointNotOnCurve` if the prime does not satisfy `prime ≡ 3 mod 4`, which means
    /// the simplified square root algorithm cannot be used.
    private static func modularSquareRoot(_ squareRoot: BigUInt, prime: BigUInt) throws -> BigUInt? {
        // Special case for p256 where prime ≡ 3 mod 4:
        // sqrt(squareRoot) ≡ squareRoot^((prime + 1) / 4) mod prime
        if prime % 4 == 3 {
            let exponent = (prime + 1) / 4
            let result = squareRoot.power(exponent, modulus: prime)
            if (result.power(2, modulus: prime) == squareRoot % prime) {
                return result
            } else {
                return nil
            }
        }

        // Otherwise, a full Tonelli-Shanks is needed.
        throw P256Error.pointNotOnCurve
    }
}

extension Data {

    /// Pads the current `Data` instance with leading zeroes to match the specified length.
    ///
    /// This is commonly used to ensure big-endian encoded integers or coordinates are a fixed size, such as
    /// 32 bytes for p256 public key components.
    ///
    /// - Warning: This should only be used for iOS 15 or earlier and tvOS 15 or earlier.
    ///
    /// - Parameter length: The target length in bytes.
    /// - Returns: A new `Data` instance of exactly `length` bytes, with leading zeroes added if necessary.
    ///           If the current length is already `>= length`, the original data is returned unchanged.
    internal func pad(to length: Int) -> Data {
        if count >= length { return self }
        return Data(repeating: 0, count: length - count) + self
    }
}

/// Utility for compressing and decompressing p256 public keys on platforms where native CryptoKit support
/// for compressed keys is unavailable.
///
/// This wrapper supports SEC1 compressed key encoding (33 bytes) and decoding by reconstructing the full
/// point on the curve using the Weierstrass equation.
///
/// Use this only on iOS and tvOS 13–15. Prefer native CryptoKit APIs on newer platforms.
internal struct CompressedP256 {

    /// Compresses a p256 public key using SEC1 encoding.
    ///
    /// - Warning: This should only be used for iOS 15 or earlier and tvOS 15 or earlier.
    ///
    /// - Parameter key: A valid uncompressed p256 public key.
    /// - Returns: A 33-byte compressed SEC1 representation.
    ///
    /// - Throws: If compression fails (e.g., invalid raw data).
    internal static func compress(_ key: P256.Signing.PublicKey) throws -> Data {
        return try key.compressedRepresentationCompat()
    }

    /// Decompresses a SEC1 compressed public key into a usable p256 public key.
    ///
    /// - Parameter data: A 33-byte compressed key.
    /// - Returns: A full `P256.Signing.PublicKey`.
    ///
    /// - Throws: `P256Error` if the key is malformed or cannot be decompressed.
    internal static func decompress(_ data: Data) throws -> P256.Signing.PublicKey {
        return try P256.Signing.PublicKey.decompressP256PublicKey(compressed: data)
    }
}

/// Errors that may occur while working with compressed p256 keys.
///
/// - Warning: This should only be used for iOS 15 or earlier and tvOS 15 or earlier.
internal enum P256Error: Error {

    /// The input data is not a valid compressed p256 key.
    case invalidCompressedKey

    /// The calculated Y coordinate is not a valid point on the curve.
    case pointNotOnCurve
}

