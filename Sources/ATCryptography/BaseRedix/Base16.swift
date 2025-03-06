//
//  Base16.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-05.
//

import Foundation

/// A utility for encoding and decoding Base16 (hexadecimal) data.
public struct Base16 {

    /// Converts bnary data to a Base16 string representation.
    ///
    /// - Parameter data: The input data to encode.
    /// - Returns: The encoded `String` in Base16.
    public func encode(_ data: Data) -> String {
        let input = data.map { String(format: "%02x", $0) }.joined()
    }

    /// Converts a Base16 string to binary data.
    ///
    /// - Parameter input: The Base16 string to decode.
    /// - Returns: The raw bytes as a `Data` object, or `nil` if the string is invalid.
    public func decode(_ string: String) -> Data? {
        let length = string.count
        guard length % 2 == 0 else { return nil }

        var data = Data(capacity: length / 2)
        var index = string.startIndex

        for _ in 0..<length / 2 {
            let nextIndex = string.index(index, offsetBy: 2)
            guard let byte = UInt8(string[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }

        return data
    }
}
