//
//  Types.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-05.
//

import Foundation

/// A protocol that defines a signing mechanism.
///
/// Implementing types must specify the JSON Web Token (JWT) signing algorithm and provide a
/// method for signing a given message.
public protocol Signer {

    /// The JSON Web Token (JWT) signing algorithm used.
    var jwtAlgorithm: String { get }

    /// Signs a given message and returns the resulting signature.
    ///
    /// - Parameter message: The message to sign.
    /// - Returns: The signature as an array of bytes.
    ///
    /// - Throws: An error if the signing process fails.
    func sign(message: [UInt8]) async throws -> [UInt8]
}

/// A protocol for entities that can provide a decentralized identifier (DID).
public protocol DIDable {

    /// Returns the decentralized identifier (DID) of the implementing entity.
    func did() throws -> String
}

/// A protocol for cryptographic key pairs that can sign messages and return their DID.
///
/// This extends `Signer` and `DIDable`, meaning any conforming type must implement
/// both signing capabilities and DID retrieval.
public protocol Keypair: Signer, DIDable {}

/// A protocol for cryptographic key pairs that support exporting their key material.
public protocol ExportableKeypair: Keypair {

    /// Exports the keypair in a serialized format.
    ///
    /// - Returns: The exported keypair as an array of bytes.
    ///
    /// - Throws: An error if the export process fails.
    func export() async throws -> [UInt8]
}

/// A protocol representing a plugin for handling `did:key` operations.
///
/// This includes key compression, decompression, and signature verification.
public protocol DIDKeyPlugin: Sendable {

    /// The prefix associated with this `did:key` implementation.
    static var prefix: [UInt8] { get }

    /// The JSON Web Token (JWT) algorithm associated with this key type.
    static var jwtAlgorithm: String { get }

    /// Verifies a decentralized identifier (DID)-based signature.
    ///
    /// - Parameters:
    ///   - did: The DID of the signer.
    ///   - message: The original message that was signed.
    ///   - signature: The signature to verify.
    ///   - options: Optional verification settings.
    /// - Returns: `true` if the signature is valid, otherwise `false`.
    ///
    /// - Throws: An error if the DID is not a valid P-256 `did:key`.
    static func verifySignature(did: String, message: [UInt8], signature: [UInt8], options: VerifyOptions?) async throws -> Bool

    /// Compresses an uncompressed p256 public key.
    ///
    /// - Parameter publicKey: The uncompressed public key as a byte array. Must be exactly
    /// 65 bytes.
    /// - Returns: The compressed public key as a 33-byte array.
    ///
    /// - Throws: `P256EncodingError.invalidKeyLength` if the key length is incorrect.
    static func compressPublicKey(_ publicKey: [UInt8]) throws -> [UInt8]

    /// Decompresses a compressed p256 public key.
    ///
    /// - Parameter publicKey: The compressed public key as a byte array. Must be exactly
    /// 33 bytes.
    /// - Returns: The uncompressed public key as a 65-byte array.
    ///
    /// - Throws: `P256EncodingError.invalidKeyLength` if the key length is incorrect.\
    /// \
    ///           `P256EncodingError.keyDecodingFailed` if the key decoding failed.
    static func decompressPublicKey(_ publicKey: [UInt8]) throws -> [UInt8]
}

/// Options for signature verification.
///
/// This includes optional settings for allowing malleable signatures.
public struct VerifyOptions {

    /// Whether to allow malleable signatures.
    ///
    /// If `true`, the verification process will not strictly reject signatures
    /// that have a malleable representation.
    public let areMalleableSignaturesAllowed: Bool?

    /// Initializes verification options.
    ///
    /// - Parameter areMalleableSignaturesAllowed: Whether to allow malleable signatures (defaults to `false`).
    public init(areMalleableSignaturesAllowed: Bool? = false) {
        self.areMalleableSignaturesAllowed = areMalleableSignaturesAllowed
    }
}
