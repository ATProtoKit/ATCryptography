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
    func did() -> String
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

/// A structure representing a plugin for handling `did:key` operations.
///
/// This includes key compression, decompression, and signature verification.
public struct DIDKeyPlugin {

    /// The prefix associated with this `did:key` implementation.
    public let prefix: [UInt8]

    /// The JSON Web Token (JWT) algorithm associated with this key type.
    public let jwtAlgorithm: String

    /// Verifies a signature given a decentralized identifier (DID), message, and signed data.
    ///
    /// - Parameters:
    ///   - did: The decentralized identifier (DID) associated with the public key.
    ///   - message: The original message that was signed.
    ///   - signature: The provided signature to verify.
    ///   - options: Optional verification settings.
    /// - Returns: `true` if the signature is valid, otherwise `false`.
    ///
    /// - Throws: An error if verification fails.
    public let verifySignature: (_ did: String, _ message: [UInt8], _ signature: [UInt8], _ options: VerifyOptions?) async throws -> Bool

    /// Compresses an uncompressed public key.
    ///
    /// - Parameter uncompressed: The uncompressed public key.
    /// - Returns: The compressed public key.
    public let compressPublicKey: (_ uncompressed: [UInt8]) -> [UInt8]

    /// Decompresses a compressed public key.
    ///
    /// - Parameter compressed: The compressed public key.
    /// - Returns: The decompressed public key.
    public let decompressPublicKey: (_ compressed: [UInt8]) -> [UInt8]
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
    /// - Parameter allowMalleableSig: Whether to allow malleable signatures (defaults to `false`).
    public init(areMalleableSignaturesAllowed: Bool? = false) {
        self.areMalleableSignaturesAllowed = areMalleableSignaturesAllowed
    }
}
