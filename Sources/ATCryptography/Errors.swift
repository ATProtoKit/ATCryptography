//
//  Errors.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-07.
//

import Foundation

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
