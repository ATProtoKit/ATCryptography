//
//  Base58.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-05.
//

import Foundation
import Crypto
import BigInt

/// Represents a Base58 encoding alphabet.
///
/// This structure provides a way to define custom Base58 alphabets and includes
/// a default Base58 encoding alphabet for use in the AT Protocol (called "base58btc").
///
/// - Note: This is in no way being used for cryptocurrency, in spite of using the
/// Bitcoin-styled alphabet.
public struct Base58Alphabet: Sendable {

    /// The default Base58 alphabet.
    public static let `default` = Base58Alphabet("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

    /// An array representing the encoding character set.
    public var encode: [UInt8] = Array(repeating: 0, count: 58)

    /// An array used for decoding Base58 characters back into their index values.
    public var decode: [UInt8] = Array(repeating: 0xFF, count: 128)

    /// Initializes a `Base58Alphabet` with a given character set.
    ///
    /// Since the ``create(alphabet:)`` method is the only way to invoke the initializer,
    /// the resulting alphabet is garanteed to have a unique, 58-character ASCII alphabet.
    ///
    /// - Parameter alphabet: A string containing exactly 58 unique ASCII characters.
    private init(_ alphabet: String) {
        let bytes = alphabet.utf8.map { UInt8($0) }

        for (i, byte) in bytes.enumerated() {
            encode[i] = byte
            decode[Int(byte)] = UInt8(i)
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
}

/// Provides Base58 encoding and decoding functionalities.
public struct Base58 {

    /// The base value used for encoding and decoding.
    private static let base = BigUInt(58)

    /// Encodes binary data into a Base58-encoded string.
    ///
    /// - Parameters:
    ///   - data: The input data to encode.
    ///   - alphabet: The Base58 alphabet to use Defaults to `.default`.
    /// - Returns: A Base58-encoded string.
    public static func encode(_ data: Data, alphabet: Base58Alphabet = .default) -> String {
        var intData = BigUInt(data)
        var result = [UInt8]()

        while intData > 0 {
            let (quotient, remainder) = intData.quotientAndRemainder(dividingBy: base)
            result.append(alphabet.encode[Int(remainder)])
            intData = quotient
        }

        result.append(contentsOf: data.prefix(while: { $0 == 0 }).map { _ in alphabet.encode[0] })
        result.reverse()

        return String(decoding: result, as: UTF8.self)
    }

    /// Decodes a Base58-encoded string back into binary data.
    ///
    /// - Parameters:
    ///   - string: The Base58-encoded input string.
    ///   - alphabet: The Base58 alphabet to use. Defaults to `.default`.
    /// - Returns: The decoded `Data`.
    ///
    /// - Throws: `Base58Error.invalidCharacter` if an invalid character is encountered.
    public static func decode(_ string: String, alphabet: Base58Alphabet = .default) throws -> Data {
        var intData = BigUInt(0)

        let leadingZeroes = string.prefix(while: { $0 == Character(UnicodeScalar(alphabet.encode[0])) }).count
        let trimmedString = string.dropFirst(leadingZeroes)

        for char in trimmedString.utf8 {
            guard char < 128, alphabet.decode[Int(char)] != 0xFF else {
                throw Base58Error.invalidCharacter(character: Character(UnicodeScalar(char)))
            }
            intData = intData * base + BigUInt(alphabet.decode[Int(char)])
        }

        var data = intData.serialize()
        data.insert(contentsOf: Array(repeating: 0, count: leadingZeroes), at: 0)
        return data
    }


    /// Encodes data with a version byte and checksum using Base58Check encoding.
    ///
    /// - Parameters:
    ///   - data: The data to encode.
    ///   - version: The version byte to prepend.
    ///   - alphabet: The Base58 alphabet to use. Defaults to `.default`.
    /// - Returns: A Base58Check-encoded string.
    public static func encodeCheck(_ data: Data, version: UInt8, alphabet: Base58Alphabet = .default) -> String {
        var payload = Data([version]) + data
        let checksum = payload.checksum()
        payload.append(contentsOf: checksum)

        return encode(payload, alphabet: alphabet)
    }

    /// Decodes a Base58Check-encoded string into its original data and version byte.
    ///
    /// - Parameters:
    ///   - string: The Base58Check-encoded input string.
    ///   - alphabet: The Base58 alphabet to use (defaults to the standard alphabet).
    /// - Returns: A tuple containing the version byte and the decoded data.
    ///
    /// - Throws: `Base58Error.invalidChecksum` if the checksum validation fails.
    public static func decodeCheck(_ string: String, alphabet: Base58Alphabet = .default) throws -> (version: UInt8, payload: Data) {
        let decoded = try decode(string, alphabet: alphabet)
        guard decoded.count > 4 else { throw Base58Error.invalidChecksum }

        let payload = decoded.dropLast(4)
        let checksum = decoded.suffix(4)

        if payload.checksum() != checksum {
            throw Base58Error.invalidChecksum
        }

        guard let version = payload.first else {
            throw Base58Error.invalidChecksum
        }

        return (version, payload.dropFirst())
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
