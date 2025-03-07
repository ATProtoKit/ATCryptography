//
//  Base16.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-05.
//

import Foundation

/// A utility for encoding and decoding Base16 (hexadecimal) data.
public struct Base16 {

    /// Converts an array of bytes to a Base16 string representation.
    ///
    /// - Parameter bytes: The input byte array to encode.
    /// - Returns: The encoded `String` in Base16.
    public static func encode(_ bytes: [UInt8]) -> String {
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Converts an array of bytes to a Base16 string representation (uppercase).
    ///
    /// - Parameter bytes: The input byte array to encode.
    /// - Returns: The encoded `String` in uppercase Base16.
    public static func encodeUpper(_ bytes: [UInt8]) -> String {
        return bytes.map { String(format: "%02X", $0) }.joined()
    }

    /// Converts a Base16 string to binary data.
    ///
    /// - Parameter input: The Base16 string to decode.
    /// - Returns: The raw bytes as an array of `UInt8`, or `nil` if the string is invalid.
    ///
    /// - Note: The input string must contain an even number of characters
    ///   and only consist of valid hexadecimal digits (0-9, A-F, a-f). If
    ///   these conditions are not met, the function returns `nil`.
    public static func decode(_ string: String) -> [UInt8]? {
        let length = string.count
        guard length % 2 == 0 else { return nil }

        var bytes = [UInt8]()
        var index = string.startIndex

        for _ in 0..<(length / 2) {
            let nextIndex = string.index(index, offsetBy: 2)
            guard let byte = UInt8(string[index..<nextIndex], radix: 16) else { return nil }
            bytes.append(byte)
            index = nextIndex
        }

        return bytes
    }
}
