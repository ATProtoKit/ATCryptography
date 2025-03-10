//
//  StringExtensions.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-10.
//

import Foundation

extension String {

    /// Converts a `String` to an `[UInt8]`.
    ///
    /// Returns `nil` if there's an odd number of characters, or if the characters
    /// are outside of the numbers or the letters A-F.
    var hexBytes: [UInt8] {
        var filteredHex = self.uppercased().filter { "0123456789ABCDEF".contains($0) }

        // Ensure the length is even; if odd, drop the last character
        if filteredHex.count % 2 != 0 {
            filteredHex.removeLast()
        }

        var byteArray: [UInt8] = []
        var index = filteredHex.startIndex

        while index < filteredHex.endIndex {
            let nextIndex = filteredHex.index(index, offsetBy: 2)
            let byteString = String(filteredHex[index..<nextIndex])

            if let byte = UInt8(byteString, radix: 16) {
                byteArray.append(byte)
            }

            index = nextIndex
        }

        return byteArray
    }
}
