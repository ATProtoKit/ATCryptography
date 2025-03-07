//
//  Multibase.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-05.
//

import Foundation

/// A collection of utility methods for handling multibase encoding and decoding.
public struct Multibase: Sendable {

    /// Converts a multibase-encoded string into raw bytes.
    ///
    /// - Parameter multibase: The multibase-encoded string.
    /// - Returns: The decoded bytes as `[UInt8]`.
    ///
    /// - Throws: `MultibaseError.unsupportedMultibase` if the encoding is not recognized.
    public static func multibaseToBytes(multibase: String) throws -> [UInt8] {
        guard let base = multibase.first else {
            throw MultibaseError.unsupportedMultibase(multiBase: multibase)
        }

        let key = String(multibase.dropFirst())

        switch base {
            case "f":
                guard let data = Base16.decode(key) else {
                    throw MultibaseError.unsupportedMultibase(multiBase: key)
                }

                return [UInt8](data)
            case "F":
                guard let data = Base16.decode(key) else {
                    throw MultibaseError.unsupportedMultibase(multiBase: key)
                }

                return [UInt8](data)
            case "b":
                guard let data = Base32.decode(key) else {
                    throw MultibaseError.unsupportedMultibase(multiBase: key)
                }

                return [UInt8](data)
            case "B":
                guard let data = Base32.decode(key) else {
                    throw MultibaseError.unsupportedMultibase(multiBase: key)
                }

                return [UInt8](data)
            case "z":
                do {
                    let data = try Base58.decode(key)
                    return [UInt8](data)
                } catch {
                    throw MultibaseError.unsupportedMultibase(multiBase: key)
                }
            case "m":
                guard let data = Data(base64Encoded: key) else {
                    throw MultibaseError.unsupportedMultibase(multiBase: key)
                }

                return [UInt8](data)
            case "u":
                guard let data = Base64URL.decodeURL(key) else {
                    throw MultibaseError.unsupportedMultibase(multiBase: key)
                }

                return [UInt8](data)
            case "U":
                do {
                    guard let data = Base64URL.decodeURLPad(key) else {
                        throw MultibaseError.unsupportedMultibase(multiBase: key)
                    }

                    return [UInt8](data)
                } catch {
                    throw error
                }
            default:
                throw MultibaseError.unsupportedMultibase(multiBase: multibase)
        }
    }

    public static func bytesToMultibase(bytes: [UInt8], encoding: MultibaseEncoding) throws -> String {
        switch encoding {
            case .base16:
                return "f\(Base16.encode(bytes))"
            case .base16Upper:
                return "F\(Base16.encodeUpper(bytes))"
            case .base32:
                return "b\(Base32.encode(bytes))"
            case .base32upper:
                return "B\(Base32.encodeUpper(bytes))"
            case .base58btc:
                let data = Data(bytes)
                return "z\(Base58.encode(data))"
            case .base64:
                let data = Data(bytes)
                return "m\(data.base64EncodedString())"
            case .base64url:
                let data = Data(bytes)
                return "u\(Base64URL.encodeURL(data))"
            case .base64urlpad:
                let data = Data(bytes)
                return "U\(Base64URL.encodeURLPad(data))"
        }
    }

    /// Supported multibase encodings.
    public enum MultibaseEncoding: String {

        /// Base16 Encoding.
        case base16

        /// Base16Upper encoding.
        case base16Upper

        /// Base32 encoding.
        case base32

        /// Base32Upper encoding.
        case base32upper

        /// Base58btc encoding.
        case base58btc

        /// Base64 encoding.
        case base64

        /// Base64URL encoding.
        case base64url

        /// Base64URLPad encoding.
        case base64urlpad
    }
}
