//
//  P256Operations.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-06.
//

import Foundation
import Crypto

/// A collection of cryptographic operations related to p256.
public struct P256Operations {

    /// Verifies a DID-based signature.
    ///
    /// - Parameters:
    ///   - did: The DID of the signer.
    ///   - data: The original message that was signed.
    ///   - signature: The signature to verify.
    ///   - options: Optional verification settings. Optional. Defaults to `nil`.
    /// - Returns: `true` if the signature is valid, otherwise `false`.
    ///
    /// - Throws: An error if the DID is not a valid p256 `did:key`.
    public static func verifyDIDSignature(did: String, data: [UInt8], signature: [UInt8], options: VerifyOptions? = nil) async throws -> Bool {
        let prefixedBytes = try ATCryptographyTools.extractPrefixedBytes(from: ATCryptographyTools.extractMultikey(from: did))

        guard ATCryptographyTools.hasPrefix(bytes: prefixedBytes, prefix: p256DIDPrefix) else {
            throw EllipticalCurveOperationsError.invalidEllipticalCurveDID(did: did)
        }

        let keyBytes = Array(prefixedBytes.dropFirst(p256DIDPrefix.count))
        return try await verifySignature(publicKey: keyBytes, data: data, signature: signature, options: options)
    }

    /// Verifies a p256 signature.
    ///
    /// - Parameters:
    ///   - publicKey: The public key in raw bytes.
    ///   - data: The original message that was signed.
    ///   - signature: The signature to verify.
    ///   - options: Options for signature verification. Optional. Defaults to `nil`.
    /// - Returns: `true` if the signature is valid, or `false` if not.
    ///
    /// - Throws: An error if signature verification fails.
    public static func verifySignature(publicKey: [UInt8], data: [UInt8], signature: [UInt8], options: VerifyOptions? = nil) async throws -> Bool {
        let allowMalleable = options?.areMalleableSignaturesAllowed ?? false
        let hashedData = await SHA256Hasher.sha256(data)

        let uncompressedPublicKey: P256.Signing.PublicKey

        if #available(iOS 16, tvOS 16, *) {
            guard let key = try? P256.Signing.PublicKey(compressedRepresentation: publicKey) else {
                throw EllipticalCurveOperationsError.invalidPublicKey
            }

            uncompressedPublicKey = key
        } else {
            guard let key = try? CompressedP256.decompress(Data(publicKey)) else {
                throw EllipticalCurveOperationsError.invalidPublicKey
            }

            uncompressedPublicKey = key
        }

        let signatureData = Data(signature)

        // If malleable signatures are not allowed, enforce compact format.
        if !allowMalleable, !isCompactFormat(signature) {
            throw EllipticalCurveOperationsError.invalidSignatureFormat
        }

        guard let parsedSignature = try? P256.Signing.ECDSASignature(rawRepresentation: signatureData) else {
            return false
        }

        guard let correctedSignature = parsedSignature.normalizedForP256() else {
            return false
        }

        return uncompressedPublicKey.isValidSignature(correctedSignature, for: Data(hashedData))
    }

    /// Checks if a signature is in compact format.
    ///
    /// - Parameter signature: The signature to check.
    /// - Returns: `true` if the signature is in compact format, otherwise `false`.
    public static func isCompactFormat(_ signature: [UInt8]) -> Bool {
        // ECDSA p256 signatures should be exactly 64 bytes in compact form.
        do {
            // Attempt to initialize a P-256 signature from compact representation.
            let ecdsaSignature = try P256.Signing.ECDSASignature(rawRepresentation: signature)

            // Convert back to raw representation and compare with input
            return ecdsaSignature.rawRepresentation == signature.toData()
        } catch {
            return false
        }
    }

    // MARK: - With SessionToken

    /// Verifies a DID-based signature from a session token.
    ///
    /// A ``SessionToken`` instance must be created before calling this method. The reason for this instead
    /// of the method itself having to call the method is to help in ensuring the session token was
    /// actually used.
    ///
    /// - Parameters:
    ///   - did: The DID of the signer.
    ///   - data: The original message that was signed.
    ///   - sessionToken: The session token containing the signature to verify.
    ///   - options: Optional verification settings. Optional. Defaults to `nil`.
    /// - Returns: `true` if the signature is valid, otherwise `false`.
    ///
    /// - Throws: An error if the DID is not a valid p256 `did:key`.
    public static func verifyDIDSignature(did: String, data: [UInt8], sessionToken: SessionToken, options: VerifyOptions? = nil) async throws -> Bool {
        let jwt = sessionToken

        guard let signature = jwt.signature else {
            throw SignatureVerificationError.invalidEncoding(reason: "No valid signature found in the provided session token.")
        }

        return try await P256Operations.verifyDIDSignature(did: did, data: data, signature: [UInt8](signature), options: options)
    }

    /// Verifies a p256 signature from a session token.
    ///
    /// A ``SessionToken`` instance must be created before calling this method. The reason for this instead
    /// of the method itself having to call the method is to help in ensuring the session token was
    /// actually used.
    ///
    /// - Parameters:
    ///   - publicKey: The public key in raw bytes.
    ///   - data: The original message that was signed.
    ///   - sessionToken: The session token containing the signature to verify.
    ///   - options: Options for signature verification. Optional. Defaults to `nil`.
    /// - Returns: `true` if the signature is valid, or `false` if not.
    ///
    /// - Throws: An error if signature verification fails.
    public static func verifySignature(publicKey: [UInt8], data: [UInt8], sessionToken: SessionToken, options: VerifyOptions? = nil) async throws -> Bool {
        let jwt = sessionToken

        guard let signature = jwt.signature else {
            throw SignatureVerificationError.invalidEncoding(reason: "No valid signature found in the provided session token.")
        }

        return try await P256Operations.verifySignature(publicKey: publicKey, data: data, signature: [UInt8](signature), options: options)
    }
}
