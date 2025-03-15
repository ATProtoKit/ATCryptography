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

    @Test("Verifies k256 and p256 signature vectors.", arguments: TestVectorEnum.signatureVectors, 1...TestVectorEnum.signatureVectors.count)
    func verifySignatureVectors(signatureVector: TestVector, count: Int) async throws {
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

    enum TestVectorEnum {
        public static var signatureVectors: [TestVector] {
            return [
                TestVector(
                    algorithm: "ES256",
                    publicDIDKey: "did:key:zDnaembgSGUhZULN2Caob4HLJPaxBh92N7rtH21TErzqf8HQo",
                    publicMultibaseKey: "zxdM8dSstjrpZaRUwBmDvjGXweKuEMVN95A9oJBFjkWMh",
                    base64Message: "oWVoZWxsb2V3b3JsZA",
                    base64Signature: "2vZNsG3UKvvO/CDlrdvyZRISOFylinBh0Jupc6KcWoJWExHptCfduPleDbG3rko3YZnn9Lw0IjpixVmexJDegg",
                    isSignatureValid: true,
                    tags: []
                ),
                TestVector(
                    algorithm: "ES256K",
                    publicDIDKey: "did:key:zQ3shqwJEJyMBsBXCWyCBpUBMqxcon9oHB7mCvx4sSpMdLJwc",
                    publicMultibaseKey: "z25z9DTpsiYYJKGsWmSPJK2NFN8PcJtZig12K59UgW7q5t",
                    base64Message: "oWVoZWxsb2V3b3JsZA",
                    base64Signature: "5WpdIuEUUfVUYaozsi8G0B3cWO09cgZbIIwg1t2YKdUn/FEznOndsz/qgiYb89zwxYCbB71f7yQK5Lr7NasfoA",
                    isSignatureValid: true,
                    tags: []
                ),
                TestVector(
                    algorithm: "ES256",
                    publicDIDKey: "did:key:zDnaembgSGUhZULN2Caob4HLJPaxBh92N7rtH21TErzqf8HQo",
                    publicMultibaseKey: "zxdM8dSstjrpZaRUwBmDvjGXweKuEMVN95A9oJBFjkWMh",
                    base64Message: "oWVoZWxsb2V3b3JsZA",
                    base64Signature: "2vZNsG3UKvvO/CDlrdvyZRISOFylinBh0Jupc6KcWoKp7O4VS9giSAah8k5IUbXIW00SuOrjfEqQ9HEkN9JGzw",
                    isSignatureValid: false,
                    tags: ["high-s"]
                ),
                TestVector(
                    algorithm: "ES256K",
                    publicDIDKey: "did:key:zQ3shqwJEJyMBsBXCWyCBpUBMqxcon9oHB7mCvx4sSpMdLJwc",
                    publicMultibaseKey: "z25z9DTpsiYYJKGsWmSPJK2NFN8PcJtZig12K59UgW7q5t",
                    base64Message: "oWVoZWxsb2V3b3JsZA",
                    base64Signature: "5WpdIuEUUfVUYaozsi8G0B3cWO09cgZbIIwg1t2YKdXYA67MYxYiTMAVfdnkDCMN9S5B3vHosRe07aORmoshoQ",
                    isSignatureValid: false,
                    tags: ["high-s"]
                ),
                TestVector(
                    algorithm: "ES256",
                    publicDIDKey: "did:key:zDnaeT6hL2RnTdUhAPLij1QBkhYZnmuKyM7puQLW1tkF4Zkt8",
                    publicMultibaseKey: "ze8N2PPxnu19hmBQ58t5P3E9Yj6CqakJmTVCaKvf9Byq2",
                    base64Message: "oWVoZWxsb2V3b3JsZA",
                    base64Signature: "MEQCIFxYelWJ9lNcAVt+jK0y/T+DC/X4ohFZ+m8f9SEItkY1AiACX7eXz5sgtaRrz/SdPR8kprnbHMQVde0T2R8yOTBweA",
                    isSignatureValid: false,
                    tags: ["der-encoded"]
                ),
                TestVector(
                    algorithm: "ES256K",
                    publicDIDKey: "did:key:zQ3shnriYMXc8wvkbJqfNWh5GXn2bVAeqTC92YuNbek4npqGF",
                    publicMultibaseKey: "z22uZXWP8fdHXi4jyx8cCDiBf9qQTsAe6VcycoMQPfcMQX",
                    base64Message: "oWVoZWxsb2V3b3JsZA",
                    base64Signature: "MEUCIQCWumUqJqOCqInXF7AzhIRg2MhwRz2rWZcOEsOjPmNItgIgXJH7RnqfYY6M0eg33wU0sFYDlprwdOcpRn78Sz5ePgk",
                    isSignatureValid: false,
                    tags: ["der-encoded"]
                )
            ]
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
