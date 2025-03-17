//
//  DataExtensions.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-10.
//

import Foundation
import Crypto

internal extension Data {

    /// Computes a checksum by applying SHA-256 twice and taking the first 4 bytes.
    ///
    /// - Returns: The first 4 bytes of the double SHA-256 hash.
    func checksum() -> Data {
        let firstHash = SHA256.hash(data: self)
        let secondHash = SHA256.hash(data: Data(firstHash))
        return Data(secondHash.prefix(4))
    }
}
