//
//  P256Operations.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-06.
//

import Foundation
import CryptoKit
import BigInt

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

        guard ATCryptographyTools.hasPrefix(bytes: prefixedBytes, prefix: ATCryptography.p256DIDPrefix) else {
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

        guard let publicKey = try? P256.Signing.PublicKey(compactRepresentation: publicKey) else {
            throw EllipticalCurveOperationsError.invalidPublicKey
        }

        let signatureData = Data(signature)

        // If malleable signatures are not allowed, enforce compact format.
        if !allowMalleable, !isCompactFormat(signature) {
            throw EllipticalCurveOperationsError.invalidSignatureFormat
        }

        guard let parsedSignature = try? P256.Signing.ECDSASignature(rawRepresentation: signatureData) else {
            return false
        }

        guard let correctedSignature = Self.normalizeSignature(signature: parsedSignature) else {
            return false
        }

        return publicKey.isValidSignature(correctedSignature, for: Data(hashedData))
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

    /// Creates a "low-S" variant of the signature, if required.
    ///
    /// - Parameter signature: The signature itself.
    /// - Returns: The signature in its "low-S" variant, or `nil` if the signature fails to
    /// be created.
    public static func normalizeSignature(signature: P256.Signing.ECDSASignature) -> P256.Signing.ECDSASignature? {
        let rawSignature = signature.derRepresentation

        // Since CryptoKit doesn't have built-in support for exposing the curve order or retrieving the "low-S" variant,
        // we're making our own.
        guard let curveOrder = BigInt("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", radix: 16) else {
            return nil
        }
        let halfOrder = curveOrder / 2

        let r = rawSignature.prefix(32)  // First 32 bytes = r
        var s = rawSignature.suffix(32)  // Last 32 bytes = s

        let sInt = BigInt(data: s)

        // Step 4: If s > half-order, compute new s
        if sInt > halfOrder {
            let newS = curveOrder - sInt
            s = newS.toData32()  // Convert back to 32 bytes
        }

        // Return the corrected signature
        let correctedSignature = try? P256.Signing.ECDSASignature(derRepresentation: Data(rawSignature))
        return correctedSignature
    }
}

extension BigInt {

    /// Initializes the `BigInt` object from a `Data` object.
    ///
    /// - Parameter data: The `Data` object to convert.
    init(data: Data) {
        self.init(data.map { String(format: "%02x", $0) }.joined(), radix: 16)!
    }

    /// Converts a `BigInt` object to a 32-byte `Data` object.
    func toData32() -> Data {
        let data = self.magnitude.serialize()
        return data.count < 32 ? Data(repeating: 0, count: 32 - data.count) + data : data
    }
}
