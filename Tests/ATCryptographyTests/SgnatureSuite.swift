//
//  SgnatureSuite.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-14.
//

import Foundation
import Testing
@testable import ATCryptography

@Suite("Signatures", .disabled()) struct SignatureTests {

    @MainActor public static var signatureVectors: [TestVector] = []

    @Test("Verifies k256 and p256 signature vectors.", arguments: signatureVectors, 1...signatureVectors.count)
    func verifySignatureVectors(signatureVector: TestVector) async throws {
        let messageBytes = signatureVector.base64Message.data(using: .utf8)?.base64EncodedString()
        let signatureBytes = signatureVector.base64Signature.data(using: .utf8)?.base64EncodedString()
        let keyBytes = try Multibase.multibaseToBytes(multibase: signatureVector.publicMultibaseKey)
        let didKey = try DIDKey.parseDIDKey(signatureVector.publicDIDKey)

        #expect(keyBytes == didKey.keyBytes, "The key bytes from the multibase and the did:key from the signature vector must be equal.")

        switch signatureVector.algorithm {
            case "ES256":
                if let messageBytes = messageBytes {
                    let isSignatureValid = try await P256Operations.verifySignature(
                        publicKey: keyBytes,
                        data: messageBytes.bytes,
                        signature: signatureBytes?.bytes ?? [UInt8]()
                    )

                    #expect(isSignatureValid == signatureVector.isSignatureValid, "The p256 signature validation must match the value in the test vector.")
                }
            case "ES256K":
                if let messageBytes = messageBytes {
                    let isSignatureValid = try await K256Operations.verifySignature(
                        publicKey: keyBytes,
                        data: messageBytes.bytes,
                        signature: signatureBytes?.bytes ?? [UInt8]()
                    )

                    #expect(isSignatureValid == signatureVector.isSignatureValid, "The k256 signature validation must match the value in the test vector.")
                }
            default:
                break
        }
    }

    public struct TestVector {
        public let algorithm: String
        public let publicDIDKey: String
        public let publicMultibaseKey: String
        public let base64Message: String
        public let base64Signature: String
        public let isSignatureValid: Bool
        public let tags: [String]
    }
}
