//
//  Base32.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-06.
//

import Foundation

/// A utility for encoding and decoding Base32 (RFC 4648).
public struct Base32 {

    /// Base32 Alphabet (lowercase variant)
    private static let base32Alphabet = Array("abcdefghijklmnopqrstuvwxyz234567")

    /// Base32 Alphabet (uppercase variant)
    private static let base32AlphabetUpper = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    /// Padding character for Base32
    private static let paddingCharacter: Character = "="

    /// Encodes binary data into a Base32 string (lowercase).
    ///
    /// - Parameter bytes: The `[UInt8]` to encode.
    /// - Returns: The Base32-encoded `String` in lowercase.
    public static func encode(_ bytes: [UInt8]) -> String {
        return encode(bytes, using: Base32.base32Alphabet)
    }

    /// Encodes binary data into a Base32 string (uppercase).
    ///
    /// - Parameter bytes: The `[UInt8]` to encode.
    /// - Returns: The Base32-encoded `String` in uppercase.
    public static func encodeUpper(_ bytes: [UInt8]) -> String {
        return encode(bytes, using: Base32.base32AlphabetUpper)
    }

    /// Decodes a Base32 string into `[UInt8]`.
    ///
    /// - Parameter string: The Base32 string (uppercase or lowercase).
    /// - Returns: The decoded `[UInt8]`, or `nil` if decoding fails.
    ///
    /// - Note: Ignores case and accepts padding (`=`), but only at the end.
    public static func decode(_ string: String) -> [UInt8]? {
        let normalizedString = string.uppercased()
        let alphabet = Base32.base32AlphabetUpper

        var buffer: UInt32 = 0
        var bufferSize = 0
        var output: [UInt8] = []

        for char in normalizedString {
            guard char != Base32.paddingCharacter, let value = alphabet.firstIndex(of: char) else {
                return nil
            }

            buffer = (buffer << 5) | UInt32(value)
            bufferSize += 5

            if bufferSize >= 8 {
                output.append(UInt8((buffer >> (bufferSize - 8)) & 0xFF))
                bufferSize -= 8
            }
        }

        return output.isEmpty ? nil : output
    }

    /// Internal method for encoding using a given alphabet.
    ///
    /// - Parameters:
    ///   - bytes: The `[UInt8]` array to encode.
    ///   - alphabet: The alphabet used for encoding the data.
    ///   - Returns: A `String` object, encoded in Base32 (in upper or lowercase).
    private static func encode(_ bytes: [UInt8], using alphabet: [Character]) -> String {
        var output = ""
        var buffer: UInt32 = 0
        var bufferSize = 0

        for byte in bytes {
            buffer = (buffer << 8) | UInt32(byte)
            bufferSize += 8

            while bufferSize >= 5 {
                let index = Int((buffer >> (bufferSize - 5)) & 0x1F)
                output.append(alphabet[index])
                bufferSize -= 5
            }
        }

        if bufferSize > 0 {
            let index = Int((buffer << (5 - bufferSize)) & 0x1F)
            output.append(alphabet[index])
        }

        // Add padding if necessary
        while output.count % 8 != 0 {
            output.append(Base32.paddingCharacter)
        }

        return output
    }
}
