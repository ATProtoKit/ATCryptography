//
//  SignatureVerifier.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-07.
//


import Foundation

/// A collection of utility methods for verifying signatures.
public struct SignatureVerifier {

    /// Verifies a digital signature using a `did:key`.
    ///
    /// - Parameters:
    ///   - didKey: The `did:key` string associated with the signer.
    ///   - data: The original message that was signed.
    ///   - signature: The signature to verify.
    ///   - options: Options for signature verification. Optional. Defaults to `nil`.
    ///   - jwtAlgorithm: The JWT algorithm used. Optional. Defaults to `nil`.
    /// - Returns: `true` if the signature is valid, or `false` if not.
    ///
    /// - Throws: An error if the key type is unsupported or the JWT algorithm does not match.
    public static func verifySignature(
        didKey: String,
        data: [UInt8],
        signature: [UInt8],
        options: VerifyOptions? = nil,
        jwtAlgorithm: String? = nil
    ) async throws -> Bool {
        let parsedDIDKey = try DIDKey.parseDIDKey(didKey)

        if let expectedAlgorithm = jwtAlgorithm, expectedAlgorithm != parsedDIDKey.jwtAlgorithm {
            throw SignatureVerificationError.mismatchedAlgorithm(expected: expectedAlgorithm, actual: parsedDIDKey.jwtAlgorithm)
        }

        guard let pluginType = plugins.first(where: { $0.jwtAlgorithm == parsedDIDKey.jwtAlgorithm }) else {
            throw SignatureVerificationError.unsupportedAlgorithm(algorithm: parsedDIDKey.jwtAlgorithm)
        }

        return try await pluginType.verifySignature(did: didKey, message: data, signature: signature, options: options)
    }

    /// Verifies a digital signature where the data and signature are given as UTF-8 and Base64URL strings.
    ///
    /// - Parameters:
    ///   - didKey: The `did:key` string associated with the signer.
    ///   - data: The original message in UTF-8 string format.
    ///   - signature: The signature as a Base64URL-encoded string.
    ///   - options: Options for signature verification. Optional. Defaults to `nil`.
    /// - Returns: `true` if the signature is valid, otherwise `false`.
    ///
    /// - Throws: An error if decoding fails or signature verification fails.
    public static func verifySignatureUtf8(didKey: String, data: String, signature: String, options: VerifyOptions? = nil) async throws -> Bool {
        guard let dataBytes = data.data(using: .utf8)?.map({ $0 }) else {
            throw SignatureVerificationError.invalidEncoding(reason: "Invalid UTF-8 string")
        }

        guard let signatureData = Base64URL.decodeURL(signature) else {
            throw SignatureVerificationError.invalidEncoding(reason: "Invalid Base64URL signature")
        }

        let signatureBytes = [UInt8](signatureData) // Convert Data to [UInt8]

        return try await verifySignature(didKey: didKey, data: dataBytes, signature: signatureBytes, options: options)
    }
}
