//
//  ATCryptographyTools.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-05.
//

import Foundation

/// Utility methods for handling DIDs, multikeys, and byte arrays in the AT Protocol.
public struct ATCryptographyTools {

    /// Extracts the multikey portion from a DID string.
    ///
    /// - Parameter did: The DID string, which must start with the `did:key:` prefix.
    /// - Returns: The extracted multikey string.
    ///
    /// - Throws: An error if the DID does not have the correct prefix.
    public static func extractMultikey(from did: String) throws -> String {
        guard did.hasPrefix(didKeyPrefix) else {
            throw ATCryptographyToolsError.invalidDIDPrefix(did: did)
        }

        return String(did.dropFirst(didKeyPrefix.count))
    }

    /// Extracts the byte array from a Base58-encoded multikey string.
    ///
    /// - Parameter multikey: The multikey string, which must start with the Base58 multibase prefix (`z`).
    /// - Returns: The extracted bytes as a `[UInt8]` array.
    ///
    /// - Throws: - `ATCryptographyError.invalidMultikeyPrefix` if the multikey does not have the correct prefix.\
    /// \
    ///           - `ATCryptographyError.invalidBase58Encoding` if decoding fails.
    public static func extractPrefixedBytes(from multikey: String) throws -> [UInt8] {
        guard multikey.hasPrefix(String(base58MultibasePrefix)) else {
            throw ATCryptographyToolsError.invalidMultikeyPrefix(multikey: multikey)
        }

        let base58Encoded = String(multikey.dropFirst()) // Remove the "z" prefix

        // Decode Base58 string into Data, then convert Data to [UInt8]
        let decodedData = try Base58.decode(base58Encoded)
        return [UInt8](decodedData)
    }

    /// Checks if a byte array has a specific prefix.
    ///
    /// - Parameters:
    ///   - bytes: The full byte array to check.
    ///   - prefix: The expected prefix as a byte array.
    /// - Returns: `true` if the `bytes` array starts with the given `prefix`, otherwise `false`.
    public static func hasPrefix(bytes: [UInt8], prefix: [UInt8]) -> Bool {
        guard bytes.count >= prefix.count else { return false }
        return Array(bytes.prefix(prefix.count)) == prefix
    }
}
