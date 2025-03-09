//
//  ECDSASignatureExtensions.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-08.
//


import Foundation
import CryptoKit
import secp256k1
import BigInt

extension P256.Signing.ECDSASignature {

    /// Creates a "low-S" variant of the ECDSA signature, if required.
    ///
    /// Since `CryptoKit` doesn't create a "low-S" variant by default, this method is needed.
    ///
    /// - Returns: The signature in its "low-S" variant, or `nil` if the operation fails.
    public func normalizedForP256() -> P256.Signing.ECDSASignature? {
        let derSignature = self.derRepresentation

        // Decode the DER-encoded signature into r and s
        guard let (r, s) = Self.extractRS(from: derSignature) else {
            return nil
        }

        // Curve order for p256.
        let curveOrder = BigInt("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", radix: 16)!
        let halfOrder = curveOrder / 2

        let sInt = BigInt(data: s)

        // If s > half-order, compute new s = order - s
        let newS = sInt > halfOrder ? (curveOrder - sInt).toData32() : s

        // Reconstruct a DER-encoded signature
        guard let newDerSignature = Self.createDEREncodedSignature(r: r, s: newS) else {
            return nil
        }

        // Return the corrected signature
        return try? P256.Signing.ECDSASignature(derRepresentation: newDerSignature)
    }

    /// Extracts r and s values from a DER-encoded ECDSA signature.
    private static func extractRS(from derSignature: Data) -> (r: Data, s: Data)? {
        let bytes = [UInt8](derSignature)

        guard bytes.count >= 6, bytes[0] == 0x30 else {
            return nil // Not a valid DER signature
        }

        var offset = 2 // Skip DER sequence header
        let rLength = Int(bytes[offset + 1])
        offset += 2
        let r = Data(bytes[offset..<offset + rLength])
        offset += rLength

        let sLength = Int(bytes[offset + 1])
        offset += 2
        let s = Data(bytes[offset..<offset + sLength])

        return (r, s)
    }

    /// Creates a DER-encoded ECDSA signature from r and s values.
    private static func createDEREncodedSignature(r: Data, s: Data) -> Data? {
        var der = Data()

        der.append(0x30) // DER sequence
        let totalLength = r.count + s.count + 4
        der.append(UInt8(totalLength))

        // Encode r
        der.append(0x02) // Integer type
        der.append(UInt8(r.count))
        der.append(r)

        // Encode s
        der.append(0x02) // Integer type
        der.append(UInt8(s.count))
        der.append(s)

        return der
    }
}

extension secp256k1.Signing.ECDSASignature {

    // secp256k1.Signing.ECDSASignature(dataRepresentation
    /// Creates a "low-S" variant of the ECDSA signature, if required.
    ///
    /// Since `CryptoKit` doesn't create a "low-S" variant by default, this method is needed.
    ///
    /// - Returns: The signature in its "low-S" variant, or `nil` if the operation fails.
    public func normalizedForK256() -> secp256k1.Signing.ECDSASignature? {
        do {
            let derSignature = try self.derRepresentation

            // Decode the DER-encoded signature into r and s
            guard let (r, s) = Self.extractRS(from: derSignature) else {
                return nil
            }

            // Curve order for k256.
            let curveOrder = BigInt("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", radix: 16)!
            let halfOrder = curveOrder / 2

            let sInt = BigInt(data: s)

            // If s > half-order, compute new s = order - s
            let newS = sInt > halfOrder ? (curveOrder - sInt).toData32() : s

            // Reconstruct a DER-encoded signature
            guard let newDerSignature = Self.createDEREncodedSignature(r: r, s: newS) else {
                return nil
            }

            // Return the corrected signature
            return try? secp256k1.Signing.ECDSASignature(derRepresentation: newDerSignature)
        } catch {
            return nil
        }
    }

    /// Extracts r and s values from a DER-encoded ECDSA signature.
    private static func extractRS(from derSignature: Data) -> (r: Data, s: Data)? {
        let bytes = [UInt8](derSignature)

        guard bytes.count >= 6, bytes[0] == 0x30 else {
            return nil // Not a valid DER signature
        }

        var offset = 2 // Skip DER sequence header
        let rLength = Int(bytes[offset + 1])
        offset += 2
        let r = Data(bytes[offset..<offset + rLength])
        offset += rLength

        let sLength = Int(bytes[offset + 1])
        offset += 2
        let s = Data(bytes[offset..<offset + sLength])

        return (r, s)
    }

    /// Creates a DER-encoded ECDSA signature from r and s values.
    private static func createDEREncodedSignature(r: Data, s: Data) -> Data? {
        var der = Data()

        der.append(0x30) // DER sequence
        let totalLength = r.count + s.count + 4
        der.append(UInt8(totalLength))

        // Encode r
        der.append(0x02) // Integer type
        der.append(UInt8(r.count))
        der.append(r)

        // Encode s
        der.append(0x02) // Integer type
        der.append(UInt8(s.count))
        der.append(s)

        return der
    }
}
