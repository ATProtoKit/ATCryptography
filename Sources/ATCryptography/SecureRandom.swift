//
//  SecureRandom.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-06.
//

import Foundation
import CryptoKit

/// A collection of utility functions for generating random data.
public struct SecureRandom {

    /// Generates a random byte array of the specified length.
    ///
    /// - Parameter byteCount: The number of random bytes to generate.
    /// - Returns: A securely generated random byte array (`[UInt8]`).
    public static func randomBytes(_ byteCount: Int) throws -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 10)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)

        guard status == errSecSuccess else { // Always test the status.
            throw SecureRandomError.failedToGenerateRandomBytes
        }

        return bytes
    }

    /// Generates a random `String` with the given encoding.
    ///
    /// - Parameters:
    ///   - byteCount: The number of random bytes to generate.
    ///   - encoding: The target encoding for the string representation.
    /// - Returns: A securely generated random string in the specified encoding.
    ///
    /// - Throws: `SecureRandomError.failedToGenerateRandomBytes` if the random byte
    /// generation failed.
    public static func randomString(from byteCount: Int, encoding: Multibase.MultibaseEncoding) throws -> String {
        do {
            let bytes = try randomBytes(byteCount)
            return try Multibase.bytesToMultibase(bytes: bytes, encoding: encoding)
        } catch {
            throw error
        }
    }

    /// Generates a random integer based on a SHA-256 hashed seed.
    ///
    /// - Parameters:
    ///   - seed: The string seed used to generate randomness.
    ///   - high: The upper bound (exclusive) for the random number.
    ///   - low: The lower bound (inclusive) for the random number. Defaults to `0`.
    /// - Returns: A deterministic random integer in the range `[low, high)`.
    ///
    /// - Throws: `RandomError.invalidRange` if `low` is greater or equal to `high`.
    public static func randomInt(from seed: String, high: Int, low: Int = 0) async throws -> Int {
        guard low < high else {
            throw SecureRandomError.invalidRange(low: low, high: high)
        }

        let hash = await SHA256Hasher.sha256(seed)

        // Get the first 6 bytes.
        let bytes = hash.prefix(6)

        // Convert bytes to a big-endian integer.
        let number = bytes.reduce(0) { (result, byte) in
            (result << 8) | Int(byte)
        }

        let range = high - low
        let normalized = number % range

        return normalized + low
    }

}

/// An error type related to secure random byte generation.
public enum SecureRandomError: Error, LocalizedError {

    /// Failed to generate secure random bytes.
    case failedToGenerateRandomBytes

    /// The requested range is invalid (i.e., `low` is greater than or equal to `high`).
    case invalidRange(low: Int, high: Int)

    public var description: String {
        switch self {
            case .invalidRange(let low, let high):
                return "Invalid range: low (\(low)) must be less than high (\(high))"
            case .failedToGenerateRandomBytes:
                return "Failed to generate secure random bytes."
        }
    }
}
