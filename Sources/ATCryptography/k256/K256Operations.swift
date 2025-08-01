//
//  K256Operations.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-07.
//

import Foundation
import secp256k1

/// A collection of cryptographic operations related to k256.
public struct K256Operations {

    /// Verifies a DID-based signature.
    ///
    /// - Parameters:
    ///   - did: The DID of the signer.
    ///   - data: The original message that was signed.
    ///   - signature: The signature to verify.
    ///   - options: Optional verification settings. Optional. Defaults to `nil`.
    /// - Returns: `true` if the signature is valid, otherwise `false`.
    ///
    /// - Throws: An error if the DID is not a valid k256 `did:key`.
    public static func verifyDIDSignature(did: String, data: [UInt8], signature: [UInt8], options: VerifyOptions? = nil) async throws -> Bool {
        let prefixedBytes = try ATCryptographyTools.extractPrefixedBytes(from: ATCryptographyTools.extractMultikey(from: did))

        guard ATCryptographyTools.hasPrefix(bytes: prefixedBytes, prefix: k256DIDPrefix) else {
            throw EllipticalCurveOperationsError.invalidEllipticalCurveDID(did: did)
        }

        let keyBytes = Array(prefixedBytes.dropFirst(k256DIDPrefix.count))
        return try await verifySignature(publicKey: keyBytes, data: data, signature: signature, options: options)
    }

    /// Verifies a k256 signature.
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

        guard let publicKey = try? secp256k1.Signing.PublicKey(dataRepresentation: publicKey, format: .compressed) else {
            throw EllipticalCurveOperationsError.invalidPublicKey
        }

        let signatureData = Data(signature)

        // If malleable signatures are not allowed, enforce compact format.
        if !allowMalleable, !isCompactFormat(signature) {
            throw EllipticalCurveOperationsError.invalidSignatureFormat
        }

        guard let parsedSignature = try? secp256k1.Signing.ECDSASignature(dataRepresentation: signatureData) else {
            return false
        }

        guard let correctedSignature = parsedSignature.normalizedForK256() else {
            return false
        }

        return publicKey.isValidSignature(correctedSignature, for: Data(hashedData))
    }

    /// Checks if a signature is in compact format.
    ///
    /// - Parameter signature: The signature to check.
    /// - Returns: `true` if the signature is in compact format, otherwise `false`.
    public static func isCompactFormat(_ signature: [UInt8]) -> Bool {
        // ECDSA k256 signatures should be exactly 64 bytes in compact form.
        do {
            // Attempt to initialize a P-256 signature from compact representation.
            let ecdsaSignature = try secp256k1.Signing.ECDSASignature(dataRepresentation: signature)

            // Convert back to raw representation and compare with input
            return ecdsaSignature.dataRepresentation == signature.toData()
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
    /// - Throws: An error if the DID is not a valid k256 `did:key`.
    public static func verifyDIDSignature(did: String, data: [UInt8], sessionToken: SessionToken, options: VerifyOptions? = nil) async throws -> Bool {
        let jwt = sessionToken

        guard let signature = jwt.signature else {
            throw SignatureVerificationError.invalidEncoding(reason: "No valid signature found in the provided session token.")
        }

        return try await verifyDIDSignature(did: did, data: data, signature: [UInt8](signature), options: options)
    }

    /// Verifies a k256 signature from a session token.
    ///
    /// A ``SessionToken`` instance must be created before calling this method. The reason for this instead
    /// of the method itself having to call the method is to help in ensuring the session token was
    /// actually used.
    ///
    /// - Parameters:
    ///   - publicKey: The public key in raw bytes.
    ///   - data: The original message that was signed.
    ///   - sessionToken: The signature to verify.
    ///   - options: Options for signature verification. Optional. Defaults to `nil`.
    /// - Returns: `true` if the signature is valid, or `false` if not.
    ///
    /// - Throws: An error if signature verification fails.
    public static func verifySignature(publicKey: [UInt8], data: [UInt8], sessionToken: SessionToken, options: VerifyOptions? = nil) async throws -> Bool {
        let jwt = sessionToken

        guard let signature = jwt.signature else {
            throw SignatureVerificationError.invalidEncoding(reason: "No valid signature found in the provided session token.")
        }

        return try await K256Operations.verifySignature(publicKey: publicKey, data: data, signature: [UInt8](signature), options: options)
    }
}
