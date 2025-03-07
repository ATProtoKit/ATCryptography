//
//  Errors.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-07.
//

import Foundation

/// An error type related to for cryptographic utility functions.
public enum ATCryptographyToolsError: Error, CustomStringConvertible {

    /// The decentralized identifier (DID) prefix is incorrect.
    ///
    /// - Parameter did: The decentralized identifier (DID) prefix.
    case invalidDIDPrefix(did: String)

    /// The multikey prefix is invalid.
    ///
    /// - Parameter multikey: The multikey prefix.
    case invalidMultikeyPrefix(multikey: String)

    /// The encoding of Base58 is invalid.
    ///
    /// - Parameter multikey: The multikey prefix.
    case invalidBase58Encoding(multikey: String)

    public var description: String {
        switch self {
            case .invalidDIDPrefix(let did):
                return "Incorrect prefix for did:key: \(did)"
            case .invalidMultikeyPrefix(let multikey):
                return "Incorrect prefix for multikey: \(multikey)"
            case .invalidBase58Encoding(let multikey):
                return "Invalid Base58 encoding in multikey: \(multikey)"
        }
    }
}

/// Errors related to elliptical curve public key encoding and decoding.
public enum EllipticalCurveEncodingError: Error, CustomStringConvertible {

    /// The key length is incorrect.
    ///
    /// - Parameters:
    ///   - expected: The amount of bytes that was expected.
    ///   - actual: The amount of bytes that was actually received.
    case invalidKeyLength(expected: Int, actual: Int)

    /// The public key decoding provess failed.
    case keyDecodingFailed

    public var description: String {
        switch self {
            case .invalidKeyLength(let expected, let actual):
                return "Invalid key length: expected \(expected) bytes, but got \(actual) bytes."
            case .keyDecodingFailed:
                return "Key decoding failed."
        }
    }
}

/// Errors related to `P256Keypair` and `K256Keypair`.
public enum EllipticalCurveKeypairError: Error, CustomStringConvertible {

    /// The private key cannot be exported.
    case privateKeyNotExportable

    public var description: String {
        switch self {
            case .privateKeyNotExportable:
                return "Private key is not exportable."
        }
    }
}

/// Errors related to p256 and k256 operations.
public enum EllipticalCurveOperationsError: Error, CustomStringConvertible {

    /// The given DID is not a valid p265 or k256 `did:key`.
    ///
    /// - Parameter did: The invalid decentralized identifier (DID).
    case invalidEllipticalCurveDID(did: String)

    /// The provided public key is invalid.
    case invalidPublicKey

    /// The provided signature is in an invalid format.
    case invalidSignatureFormat

    public var description: String {
        switch self {
            case .invalidEllipticalCurveDID(let did):
                return "DID '\(did)' is not a valid elliptical curve did:key."
            case .invalidPublicKey:
                return "Invalid public key."
            case .invalidSignatureFormat:
                return "Invalid signature format."
        }
    }
}

/// An error type related to secure random byte generation.
public enum SecureRandomError: Error, LocalizedError {

    /// Failed to generate secure random bytes.
    case failedToGenerateRandomBytes

    /// The requested range is invalid (i.e., `low` is greater than or equal to `high`).
    case invalidRange(low: Int, high: Int)

    public var description: String {
        switch self {
            case .invalidRange(let low, let high):
                return "Invalid range: low (\(low)) must be less than high (\(high))"
            case .failedToGenerateRandomBytes:
                return "Failed to generate secure random bytes."
        }
    }
}

/// Errors related to multibase encoding and decoding.
public enum MultibaseError: Error, CustomStringConvertible {

    /// The multibase encoding is unsupported.
    ///
    /// - Parameter multibase: The multibase encoding value.
    case unsupportedMultibase(multiBase: String)

    public var description: String {
        switch self {
            case .unsupportedMultibase(let value):
                return "Unsupported multibase encoding: \(value)"
        }
    }
}

/// Errors related to signature verification.
public enum SignatureVerificationError: Error, CustomStringConvertible {

    /// The provided key algorithm does not match the expected algorithm.
    ///
    /// - Parameters:
    ///   - expected: The `String` value that was expected.
    ///   - actual: The `String` value that was actually given.
    case mismatchedAlgorithm(expected: String, actual: String)

    /// The key type or algorithm is unsupported.
    case unsupportedAlgorithm(algorithm: String)

    /// The input encoding is invalid.
    ///
    /// - Parameter input: The reason the encoding was invalid.
    case invalidEncoding(reason: String)

    public var description: String {
        switch self {
            case .mismatchedAlgorithm(let expected, let actual):
                return "Expected key algorithm. Expected '\(expected)', but got '\(actual)'."
            case .unsupportedAlgorithm(let algorithm):
                return "Unsupported signature algorithm: \(algorithm)."
            case .invalidEncoding(let reason):
                return "Invalid encoding: \(reason)."
        }
    }
}
