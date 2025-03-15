//
//  K256Keypair.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-07.
//

import Foundation
@preconcurrency import secp256k1

/// A cryptographic keypair for k256.
public struct K256Keypair: ExportableKeypair, Sendable {

    /// The JSON Web Token (JWT) signing algorithm used.
    public let jwtAlgorithm: String = k256JWTAlgorithm

    /// The private key used for signing.
    private let privateKey: secp256k1.Signing.PrivateKey

    /// Indicates whether the private key can be exported.
    private let isExportable: Bool

    /// The public key corresponding to the private key.
    private let publicKey: secp256k1.Signing.PublicKey

    /// Initializes a `K256Keypair` with a given private key.
    ///
    /// - Parameters:
    ///   - privateKey: The private key in raw bytes.
    ///   - isExportable: Indicates whether the private key can be exported.
    ///
    /// - Throws: An error if the private key is invalid.
    private init(privateKey: [UInt8], isExportable: Bool) throws {
        self.privateKey = try secp256k1.Signing.PrivateKey(dataRepresentation: privateKey, format: .uncompressed)
        self.publicKey = self.privateKey.publicKey
        self.isExportable = isExportable
    }

    /// Generates a new random `K256Keypair`.
    ///
    /// This is a factory method to create a private and public key pair. All instance methods
    /// for this instance will only apply to the keypair.
    ///
    /// - Parameter isExportable: Indicates whether the private key can be exported.
    /// Defaults to `false`.
    /// - Returns: A new `K256Keypair` instance.
    public static func create(isExportable: Bool = false) throws -> K256Keypair {
        let privateKey = try secp256k1.Signing.PrivateKey(format: .uncompressed)
        return try K256Keypair(privateKey: Array(privateKey.dataRepresentation), isExportable: isExportable)
    }

    /// Imports a `K256Keypair` from an existing private key.
    ///
    /// - Parameters:
    ///   - privateKey: The private key as a hex string or raw byte array.
    ///   - isExportable: Indicates whether the private key can be exported.
    /// Defaults to `false`.
    /// - Returns: A `K256Keypair` instance.
    ///
    /// - Throws: An error if the private key is invalid.
    public static func `import`<Key: DataConvertible>(privateKey: Key, isExportable: Bool = false) throws -> K256Keypair {
        let privateKeyBytes = privateKey.toData().map { $0 }
        return try K256Keypair(privateKey: privateKeyBytes, isExportable: isExportable)
    }

    /// Returns the public key as raw bytes.
    ///
    /// - Returns: The public key as a byte array.
    public func publicKeyBytes() -> [UInt8] {
        let rawPublicKey = publicKey.dataRepresentation // Should be 64 bytes.
        return Array(rawPublicKey)
    }

    /// Returns the public key as a `String` in the specified encoding.
    ///
    /// - Parameter encoding: The encoding format. Defaults to `.base64urlpad`.
    /// - Returns: The encoded public key string.
    ///
    /// - Throws: `MultibaseError.unsupportedMultibase` if the encoding is not supported.
    public func publicKeyAsString(using encoding: Multibase.MultibaseEncoding = .base64urlpad) throws -> String {
        return try Multibase.bytesToMultibase(bytes: publicKeyBytes(), encoding: encoding)
    }

    /// Returns the decentralized identifier (DID) for this keypair.
    ///
    /// - Returns: The formatted DID string.
    public func did() throws -> String {
        do {
            return try DIDKey.formatDIDKey(jwtAlgorithm: jwtAlgorithm, keyBytes: publicKeyBytes())
        } catch {
            throw error
        }
    }

    /// Signs a message using the private key.
    ///
    /// - Parameter message: The message to sign.
    /// - Returns: The signature as a byte array.
    ///
    /// - Throws: An error if signing fails.
    public func sign(message: [UInt8]) async throws -> [UInt8] {
        let hash = await SHA256Hasher.sha256(message)
        let signature = try privateKey.signature(for: Data(hash))
        return Array(signature.dataRepresentation)
    }

    /// Exports the private key in raw byte format.
    ///
    /// - Returns: The private key as a byte array.
    ///
    /// - Throws: `EllipticalCurveKeypairError.privateKeyNotExportable` if the keypair is
    /// not exportable.
    public func export() async throws -> [UInt8] {
        guard isExportable else {
            throw EllipticalCurveKeypairError.privateKeyNotExportable
        }

        return Array(privateKey.dataRepresentation)
    }
}
