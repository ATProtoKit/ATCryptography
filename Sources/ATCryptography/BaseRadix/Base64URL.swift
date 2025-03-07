//
//  Base64URL.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-06.
//

import Foundation

/// A utility for encoding and decoding Base64URL (RFC 4648).
///
/// Supports both Base64URL (unpadded) and Base64URLPad (padded).
public struct Base64URL {

    /// Encodes binary data into a Base64URL-encoded string (RFC 4648, without padding).
    ///
    /// - Parameter data: The `Data` to encode.
    /// - Returns: The Base64URL-encoded `String` (without padding).
    public static func encodeURL(_ data: Data) -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "=")) // Remove padding.
    }

    /// Decodes a Base64URL-encoded string (without padding) into a `Data` object.
    ///
    /// - Parameter string: The Base64URL string to decode (must not include padding).
    /// - Returns: The decoded `Data`, or `nil` if decoding fails.
    public static func decodeURL(_ string: String) -> Data? {
        // Ensure the input does not contain `=` padding characters.
        guard !string.contains("=") else { return nil }

        // Convert Base64URL to standard Base64
        var base64String = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        // Add necessary padding to make the length a multiple of 4.
        let paddingNeeded = (4 - base64String.count % 4) % 4
        base64String.append(String(repeating: "=", count: paddingNeeded))

        return Data(base64Encoded: base64String)
    }

    /// Encodes binary data into a Base64URLPad-encoded string (RFC 4648, with padding).
    ///
    /// - Parameter data: The `Data` to encode.
    /// - Returns: The Base64URLPad-encoded `String` (with padding).
    public static func encodeURLPad(_ data: Data) -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_") // Keep padding
    }

    /// Decodes a Base64URLPad-encoded string (with padding) into `Data`.
    ///
    /// - Parameter string: The Base64URLPad string to decode (must include padding if originally present).
    /// - Returns: The decoded `Data`, or `nil` if decoding fails.
    public static func decodeURLPad(_ string: String) -> Data? {
        // Convert Base64URLPad to standard Base64.
        let base64String = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        return Data(base64Encoded: base64String)
    }
}
