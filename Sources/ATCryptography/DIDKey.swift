//
//  DIDKey.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-07.
//

import Foundation

/// A collection of utility methods for handling `did:key` operations.
public struct DIDKey {

    /// Parses a multikey string and returns the associated JWT algorithm and key bytes.
    ///
    /// - Parameter multikey: The multikey string to parse.
    /// - Returns: A `ParsedMultikey` containing the JWT algorithm and decompressed key bytes.
    ///
    /// - Throws: `DIDError.unsupportedKeyType` if the key type is not recognized.
    public static func parseMultikey(_ multikey: String) throws -> ParsedMultikey {
        let prefixedBytes = try ATCryptographyTools.extractPrefixedBytes(from: multikey)

        guard let pluginType = plugins.first(where: { ATCryptographyTools.hasPrefix(bytes: prefixedBytes, prefix: $0.prefix) }) else {
            throw DIDKeyError.unsupportedKeyType
        }

        let keyBytes = try pluginType.decompress(publicKey: Array(prefixedBytes.dropFirst(pluginType.prefix.count)))

        // There appears to be a bug that's causing the public key to have less than the expected amount, but it's nearly impossible to replicate
        // as it happens very rarely.
        #if DEBUG
        print("Public Key count: \(keyBytes.count)")
        print("First byte for the public key: \([UInt8](keyBytes)[0])")
        #endif
        return ParsedMultikey(jwtAlgorithm: pluginType.jwtAlgorithm, keyBytes: keyBytes)
    }

    /// Formats a multikey string using a JWT algorithm and key bytes.
    ///
    /// - Parameters:
    ///   - jwtAlgorithm: The JWT algorithm associated with the key.
    ///   - keyBytes: The raw key bytes.
    /// - Returns: A formatted multikey string.
    ///
    /// - Throws: `DIDError.unsupportedKeyType` if the key type is not recognized.
    public static func formatMultikey(jwtAlgorithm: String, keyBytes: [UInt8]) throws -> String {
        guard let plugin = plugins.first(where: { $0.jwtAlgorithm == jwtAlgorithm }) else {
            throw DIDKeyError.unsupportedKeyType
        }

        let prefixedBytes = plugin.prefix + (try plugin.compress(publicKey: keyBytes))

        return String(base58MultibasePrefix) + Base58.encode(Data(prefixedBytes))
    }

    /// Parses a `did:key` string and returns the associated JWT algorithm and key bytes.
    ///
    /// - Parameter did: The `did:key` string to parse.
    /// - Returns: A `ParsedMultikey` containing the JWT algorithm and decompressed key bytes.
    ///
    /// - Throws: `DIDError.invalidDIDPrefix` if the DID is malformed.
    public static func parseDIDKey(_ did: String) throws -> ParsedMultikey {
        let multikey = try ATCryptographyTools.extractMultikey(from: did)
        return try parseMultikey(multikey)
    }

    /// Formats a `did:key` string using a JWT algorithm and key bytes.
    ///
    /// - Parameters:
    ///   - jwtAlgorithm: The JWT algorithm associated with the key.
    ///   - keyBytes: The raw key bytes.
    /// - Returns: A formatted `did:key` string.
    ///
    /// - Throws: `DIDError.unsupportedKeyType` if the key type is not recognized.
    public static func formatDIDKey(jwtAlgorithm: String, keyBytes: [UInt8]) throws -> String {
        return didKeyPrefix + (try formatMultikey(jwtAlgorithm: jwtAlgorithm, keyBytes: keyBytes))
    }
}

/// Represents a parsed `did:key`, containing its JWT algorithm and key bytes.
public struct ParsedMultikey {

    /// The JSON Web Token (JWT) algorithm associated with the key.
    public let jwtAlgorithm: String

    /// The decompressed public key bytes.
    public let keyBytes: [UInt8]
}
