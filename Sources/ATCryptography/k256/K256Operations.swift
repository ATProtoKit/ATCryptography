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
    /// - Throws: An error if the DID is not a valid P-256 `did:key`.
    public static func verifyDIDSignature(did: String, data: [UInt8], signature: [UInt8], options: VerifyOptions? = nil) async throws -> Bool {
        let prefixedBytes = try ATCryptographyTools.extractPrefixedBytes(from: ATCryptographyTools.extractMultikey(from: did))

        guard ATCryptographyTools.hasPrefix(bytes: prefixedBytes, prefix: ATCryptography.k256DIDPrefix) else {
            throw EllipticalCurveOperationsError.invalidEllipticalCurveDID(did: did)
        }

        let keyBytes = Array(prefixedBytes.dropFirst(ATCryptography.p256DIDPrefix.count))
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

        guard let publicKey = try? secp256k1.Signing.PublicKey(dataRepresentation: publicKey, format: .compressed) else {
            throw EllipticalCurveOperationsError.invalidPublicKey
        }

        let signatureData = Data(signature)

        // If malleable signatures are not allowed, enforce compact format.
        if !allowMalleable, !isCompactFormat(signature) {
            throw EllipticalCurveOperationsError.invalidSignatureFormat
        }

        guard let parsedSignature = try? secp256k1.Signing.ECDSASignature(derRepresentation: signatureData) else {
            return false
        }

        return publicKey.isValidSignature(parsedSignature, for: Data(hashedData))
    }

    /// Checks if a signature is in compact format.
    ///
    /// - Parameter signature: The signature to check.
    /// - Returns: `true` if the signature is in compact format, otherwise `false`.
    public static func isCompactFormat(_ signature: [UInt8]) -> Bool {
        // ECDSA p256 signatures should be exactly 64 bytes in compact form.
        guard signature.count == 64 else { return false }

        // Attempt to create a CryptoKit ECDSA signature.
        guard let parsedSignature = try? secp256k1.Signing.ECDSASignature(dataRepresentation: signature) else {
            // If it can't be parsed, it's not a valid compact signature.
            return false
        }

        return parsedSignature.dataRepresentation == Data(signature)
    }
}
