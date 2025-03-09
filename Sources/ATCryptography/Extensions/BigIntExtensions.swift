//
//  BigIntExtensions.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-08.
//

import Foundation
import BigInt

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
