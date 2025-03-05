//
//  Base58.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-05.
//

import Foundation
import CryptoKit
import BigInt

/// Represents a Base58 encoding alphabet.
///
/// This structure provides a way to define custom Base58 alphabets and includes
/// a default Base58 encoding alphabet for use in the AT Protocol (called "base58btc").
///
/// - Note: This is in no way being used for cryptocurrency, in spite of using the
/// Bitcoin-styled alphabet.
public struct Base58Alphabet: Sendable {

    /// An array representing the encoding character set.
    public var encode: [Character] = Array(repeating: "\0", count: 58)

    /// An array used for decoding Base58 characters back into their index values.
    public var decode: [UInt8] = Array(repeating: 0xFF, count: 128)

    /// Initializes a `Base58Alphabet` with a given character set.
    ///
    /// - Parameter alphabet: A string containing exactly 58 unique ASCII characters.
    private init(_ alphabet: String) {
        for (i, char) in alphabet.enumerated() {
            let asciiValue = char.asciiValue

            encode[i] = char
            // Since the `create` function already checks each character for the ASCII value,
            // no character will inappropriately be made `0x00`.
            decode[Int(asciiValue ?? 0x00)] = UInt8(i)
        }
    }

    /// Creates a custom Base58 alphabet.
    ///
    /// - Note: The alphabet _must_ contain exactly 58 unique ASCII characters.
    ///
    /// - Parameter alphabet: A string representing the custom alphabet.
    /// - Returns: A `Base58Alphabet` instance.
    /// - Throws: `Base58Error.invalidNumberOfCharacters` if the length is not 58.
    ///           `Base58Error.invalidCharacter` if a non-ASCII character is present.
    ///           `Base58Error.duplicateCharacter` if duplicate characters exist.
    public static func create(alphabet: String) throws -> Base58Alphabet {
        guard alphabet.count == 58 else {
            throw Base58Error.invalidNumberOfCharacters
        }

        var seenCharacters = Set<Character>()

        for char in alphabet {
            // Ensure ASCII-only characters
            guard char.isASCII else {
                throw Base58Error.invalidCharacter(character: char)
            }

            // Ensure no duplicate characters
            guard seenCharacters.insert(char).inserted else {
                throw Base58Error.duplicateCharacter(character: char)
            }
        }

        // If all checks pass, initialize the Base58Alphabet instance
        return Base58Alphabet(alphabet)
    }

    /// The default Base58 alphabet.
    public static let `default` = Base58Alphabet("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
}

/// Provides Base58 encoding and decoding functionalities.
public struct Base58 {

    /// Encodes binary data into a Base58-encoded string.
    ///
    /// - Parameters:
    ///   - data: The input data to encode.
    ///   - alphabet: The Base58 alphabet to use (defaults to the standard alphabet).
    /// - Returns: A Base58-encoded string.
    public static func encode(_ data: Data, alphabet: Base58Alphabet = .default) -> String {
        var intData = BigUInt(data)
        let base = BigUInt(58)
        var result = [Character]()

        while intData > 0 {
            let (quotient, remainder) = intData.quotientAndRemainder(dividingBy: base)
            result.append(alphabet.encode[Int(remainder)])
            intData = quotient
        }

        result.append(contentsOf: data.prefix(while: { $0 == 0 }).map { _ in alphabet.encode[0] })
        return String(result.reversed())
    }
}

/// An error type related to Base58.
public enum Base58Error: Error, LocalizedError {

    /// The alphabet must have exactly 58 characters.
    case invalidNumberOfCharacters

    /// There is an invalid character within the alphabet.
    ///
    /// - Parameter character: The character in question.
    case invalidCharacter(character: Character)

    /// There is a duplicate character in the alphabet.
    ///
    /// - Parameter character: The duplicate character.
    case duplicateCharacter(character: Character)

    /// There's an invalid checksum in the encoding.
    case invalidChecksum

    /// A description of each of the errors.
    public var errorDescription: String? {
        switch self {
            case .invalidNumberOfCharacters:
                return "Alphabet must have exactly 58 characters."
            case .invalidCharacter(let character):
                return "Invalid Base58 character: \(character)."
            case .duplicateCharacter(let character):
                return "Duplicate Base58 character: \(character)."
            case .invalidChecksum:
                return "Invalid checksum in Base58Check encoding."
        }
    }
}

// Extension for checksum calculation
private extension Data {

    /// Computes a checksum by applying SHA-256 twice and taking the first 4 bytes.
    ///
    /// - Returns: The first 4 bytes of the double SHA-256 hash.
    func checksum() -> Data {
        let firstHash = SHA256.hash(data: self)
        let secondHash = SHA256.hash(data: Data(firstHash))
        return Data(secondHash.prefix(4))
    }
}
