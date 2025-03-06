//
//  Base64URL.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-06.
//

import Foundation

/// A utility for encoding and decoding Base64URL (RFC 4648, without padding support).
public struct Base64URL {

    /// Encodes binary data into a Base64URL-encoded string (RFC 4648, without padding).
    ///
    /// - Parameter data: The `Data` to encode.
    /// - Returns: The Base64URL-encoded `String` (without padding).
    public func encodeURL(_ data: Data) -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "=")) // Remove padding
    }

    /// Decodes a Base64URL-encoded string into `Data`. Does **not** support Base64URLPad.
    ///
    /// - Parameter string: The Base64URL string to decode (must not include padding).
    /// - Returns: The decoded `Data`, or `nil` if decoding fails.
    public func decode(_ string: String) -> Data? {
        // Reject input containing `=` padding characters
        guard !string.contains("=") else { return nil }

        // Convert Base64URL to standard Base64
        let base64String = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        return Data(base64Encoded: base64String)
    }
}
