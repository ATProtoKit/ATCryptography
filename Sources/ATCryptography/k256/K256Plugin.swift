//
//  K256Plugin.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-07.
//

import Foundation

/// A plugin for handling k256 `did:key` operations.
public struct K256Plugin: DIDKeyPlugin {

    /// The prefix associated with this `did:key` implementation.
    public static let prefix: [UInt8] = ATCryptography.k256DIDPrefix

    /// The JSON Web Token (JWT) algorithm associated with this key type.
    public static let jwtAlgorithm: String = ATCryptography.k256JWTAlgorithm

    /// Verifies a decentralized identifier (DID)-based signature.
    ///
    /// - Parameters:
    ///   - did: The DID of the signer.
    ///   - message: The original message that was signed.
    ///   - signature: The signature to verify.
    ///   - options: Optional verification settings.
    /// - Returns: `true` if the signature is valid, otherwise `false`.
    ///
    /// - Throws: An error if the DID is not a valid k256 `did:key`.
    public static func verifySignature(did: String, message: [UInt8], signature: [UInt8], options: VerifyOptions? = nil) async throws -> Bool {
        return try await K256Operations.verifyDIDSignature(did: did, data: message, signature: signature, options: options)
    }

    /// Compresses an uncompressed k256 public key.
    ///
    /// - Parameter publicKey: The uncompressed public key as a byte array. Must be exactly
    /// 65 bytes.
    /// - Returns: The compressed public key as a 33-byte array.
    ///
    /// - Throws: `EllipticalCurveEncodingError.invalidKeyLength` if the key length is incorrect.
    public static func compressPublicKey(_ publicKey: [UInt8]) throws -> [UInt8] {
        return try K256Encoding.compressPublicKey(publicKey)
    }

    /// Decompresses a compressed k256 public key.
    ///
    /// - Parameter publicKey: The compressed public key as a byte array. Must be exactly
    /// 33 bytes.
    /// - Returns: The uncompressed public key as a 65-byte array.
    ///
    /// - Throws: `EllipticalCurveEncodingError.invalidKeyLength` if the key length is incorrect.\
    /// \
    ///           `EllipticalCurveEncodingError.keyDecodingFailed` if the key decoding failed.
    public static func decompressPublicKey(_ publicKey: [UInt8]) throws -> [UInt8] {
        return try K256Encoding.decompressPublicKey(publicKey)
    }
}
