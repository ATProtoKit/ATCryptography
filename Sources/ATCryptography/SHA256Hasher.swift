//
//  SHA256Hasher.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-06.
//

import Foundation
import CryptoKit

/// A collection of utility methods for computing SHA-256 hashes.
public struct SHA256Hasher: Sendable {

    /// Computes the SHA-256 hash of a given input asynchronously..
    ///
    /// - Parameter input: The input, which can be either a string or a byte array (`[UInt8]`).
    /// - Returns: The SHA-256 hash as a byte array (`[UInt8]`).
    static func sha256(_ input: some DataConvertible) async -> [UInt8] {
        let data = input.toData() // Convert input outside the Task.

        return await Task(priority: .userInitiated) {
            let hash = SHA256.hash(data: data)
            return Array(hash)
        }.value
    }

    /// Computes the SHA-256 hash of a given input as a hexadecimal string asynchronously.
    ///
    /// - Parameter input: The input, which can be either a string or a byte array (`[UInt8]`).
    /// - Returns: The SHA-256 hash as a hexadecimal string.
    static func sha256Hex(_ input: some DataConvertible) async -> String {
        let data = input.toData()  // Convert input outside the Task.

        return await Task(priority: .userInitiated) {
            let hashBytes = SHA256.hash(data: data)
            return hashBytes.map { String(format: "%02x", $0) }.joined()
        }.value
    }

    /// Computes the SHA-256 hash of a given input synchronously.
    ///
    /// - Parameter input: The input, which can be either a string or a byte array (`[UInt8]`).
    /// - Returns: The SHA-256 hash as a byte array (`[UInt8]`).
    static func sha256(_ input: some DataConvertible) -> [UInt8] {
        let data = input.toData()
        let hash = SHA256.hash(data: data)
        return Array(hash)
    }

    /// Computes the SHA-256 hash of a given input as a hexadecimal string synchronously.
    ///
    /// - Parameter input: The input, which can be either a string or a byte array (`[UInt8]`).
    /// - Returns: The SHA-256 hash as a hexadecimal string.
    static func sha256Hex(_ input: some DataConvertible) -> String {
        let hashBytes = sha256(input)
        return hashBytes.map { String(format: "%02x", $0) }.joined()
    }
}

/// A protocol that provides a unified way to convert different types into `Data`.
///
/// This is used to allow both `String` and `[UInt8]` to be passed into hash functions seamlessly.
protocol DataConvertible {

    /// Converts the conforming type into `Data`.
    ///
    /// - Returns: The converted `Data` object.
    func toData() -> Data
}

extension String: DataConvertible {
    func toData() -> Data {
        return self.data(using: .utf8) ?? Data()
    }
}

extension Array: DataConvertible where Element == UInt8 {
    func toData() -> Data {
        return Data(self)
    }
}
