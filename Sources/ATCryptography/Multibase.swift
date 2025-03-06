//
//  Multibase.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-05.
//

import Foundation

/// A collection of utility functions for handling multibase encoding and decoding.
struct Multibase: Sendable {

    /// Converts a multibase-encoded string into raw bytes.
    ///
    /// - Parameter multibase: The multibase-encoded string.
    /// - Returns: The decoded bytes as `[UInt8]`.
    ///
    /// - Throws: `MultibaseError.unsupportedMultibase` if the encoding is not recognized.
    static func multibaseToBytes(multibase: String) throws -> [UInt8] {
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
                guard let data = Base64URL.decode(key) else {
                    throw MultibaseError.unsupportedMultibase(multiBase: key)
                }

                return [UInt8](data)
            case "U":
                // TODO: Add Base64URLPad
                do {
                    let data = try Radix.decodeBase64(key, urlSafe: true, padded: true)
                    return [UInt8](data)
                } catch {
                    throw error
                }
            default:
                throw MultibaseError.unsupportedMultibase(multiBase: multibase)
        }
    }

    static func bytesToMultibase(bytes: [UInt8], encoding: MultibaseEncoding) throws -> String {
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
                // TODO: Add Base64URL
//                let data = Data(bytes)
                return "u\(Radix.encodeBase64(bytes, urlSafe: true, padded: false))"
            case .base64urlpad:
                // TODO: Add Base64URLPad
//                let data = Data(bytes)
                return "U\(Radix.encodeBase64(bytes, urlSafe: true, padded: true))"
        }
    }

    /// Supported multibase encodings.
    enum MultibaseEncoding: String {

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

public struct Radix: Sendable {

    /// Decodes a Base64 string into bytes.
    public static func decodeBase64(_ string: String, urlSafe: Bool, padded: Bool) throws -> [UInt8] {
        var base64String = string
        if urlSafe {
            base64String = base64String.replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
        }
        if padded {
            while base64String.count % 4 != 0 {
                base64String.append("=")
            }
        }

        guard let data = Data(base64Encoded: base64String) else {
            throw MultibaseError.unsupportedMultibase(multiBase: string)
        }
        return [UInt8](data)
    }

    /// Encodes bytes into a Base64 string.
    public static func encodeBase64(_ bytes: [UInt8], urlSafe: Bool, padded: Bool) -> String {
        var base64 = Data(bytes).base64EncodedString()

        if !padded {
            base64 = base64.replacingOccurrences(of: "=", with: "")
        }

        if urlSafe {
            base64 = base64.replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
        }

        return base64
    }
}


/// Errors related to multibase encoding and decoding.
enum MultibaseError: Error, CustomStringConvertible {

    /// The multibase encoding is unsupported.
    ///
    /// - Parameter multibase: The multibase encoding value.
    case unsupportedMultibase(multiBase: String)

    var description: String {
        switch self {
            case .unsupportedMultibase(let value):
                return "Unsupported multibase encoding: \(value)"
        }
    }
}
