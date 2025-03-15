//
//  SignatureTestExtension.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-14.
//

import Foundation

extension SignatureTests {

    public func createSignatureFixtures() -> [TestVector] {
        // Valid p256 key and signature, with 'low-S' signature.
        let signatureVector1 = TestVector(
            algorithm: "ES256",
            publicDIDKey: "did:key:zDnaembgSGUhZULN2Caob4HLJPaxBh92N7rtH21TErzqf8HQo",
            publicMultibaseKey: "zxdM8dSstjrpZaRUwBmDvjGXweKuEMVN95A9oJBFjkWMh",
            base64Message: "oWVoZWxsb2V3b3JsZA",
            base64Signature: "2vZNsG3UKvvO/CDlrdvyZRISOFylinBh0Jupc6KcWoJWExHptCfduPleDbG3rko3YZnn9Lw0IjpixVmexJDegg",
            isSignatureValid: true,
            tags: []
        )

        // Valid k256 key and signature, with 'low-S' signature.
        let signatureVector2 = TestVector(
            algorithm: "ES256K",
            publicDIDKey: "did:key:zQ3shqwJEJyMBsBXCWyCBpUBMqxcon9oHB7mCvx4sSpMdLJwc",
            publicMultibaseKey: "z25z9DTpsiYYJKGsWmSPJK2NFN8PcJtZig12K59UgW7q5t",
            base64Message: "oWVoZWxsb2V3b3JsZA",
            base64Signature: "5WpdIuEUUfVUYaozsi8G0B3cWO09cgZbIIwg1t2YKdUn/FEznOndsz/qgiYb89zwxYCbB71f7yQK5Lr7NasfoA",
            isSignatureValid: true,
            tags: []
        )

        // p256 key and signature, with non-'low-S' signature, which is invalid in atproto.
        let signatureVector3 = TestVector(
            algorithm: "ES256",
            publicDIDKey: "did:key:zDnaembgSGUhZULN2Caob4HLJPaxBh92N7rtH21TErzqf8HQo",
            publicMultibaseKey: "zxdM8dSstjrpZaRUwBmDvjGXweKuEMVN95A9oJBFjkWMh",
            base64Message: "oWVoZWxsb2V3b3JsZA",
            base64Signature: "2vZNsG3UKvvO/CDlrdvyZRISOFylinBh0Jupc6KcWoKp7O4VS9giSAah8k5IUbXIW00SuOrjfEqQ9HEkN9JGzw",
            isSignatureValid: false,
            tags: ["high-s"]
        )

        // k256 key and signature, with non-'low-S' signature, which is invalid in atproto.
        let signatureVector4 = TestVector(
            algorithm: "ES256K",
            publicDIDKey: "did:key:zQ3shqwJEJyMBsBXCWyCBpUBMqxcon9oHB7mCvx4sSpMdLJwc",
            publicMultibaseKey: "z25z9DTpsiYYJKGsWmSPJK2NFN8PcJtZig12K59UgW7q5t",
            base64Message: "oWVoZWxsb2V3b3JsZA",
            base64Signature: "5WpdIuEUUfVUYaozsi8G0B3cWO09cgZbIIwg1t2YKdXYA67MYxYiTMAVfdnkDCMN9S5B3vHosRe07aORmoshoQ",
            isSignatureValid: false,
            tags: ["high-s"]
        )

        // p256 key and signature, with DER-encoded signature, which is invalid in atproto.
        let signatureVector5 = TestVector(
            algorithm: "ES256",
            publicDIDKey: "did:key:zDnaeT6hL2RnTdUhAPLij1QBkhYZnmuKyM7puQLW1tkF4Zkt8",
            publicMultibaseKey: "ze8N2PPxnu19hmBQ58t5P3E9Yj6CqakJmTVCaKvf9Byq2",
            base64Message: "oWVoZWxsb2V3b3JsZA",
            base64Signature: "MEQCIFxYelWJ9lNcAVt+jK0y/T+DC/X4ohFZ+m8f9SEItkY1AiACX7eXz5sgtaRrz/SdPR8kprnbHMQVde0T2R8yOTBweA",
            isSignatureValid: false,
            tags: ["der-encoded"]
        )

        // k256 key and signature, with DER-encoded signature, which is invalid in atproto.
        let signatureVector6 = TestVector(
            algorithm: "ES256K",
            publicDIDKey: "did:key:zQ3shnriYMXc8wvkbJqfNWh5GXn2bVAeqTC92YuNbek4npqGF",
            publicMultibaseKey: "z22uZXWP8fdHXi4jyx8cCDiBf9qQTsAe6VcycoMQPfcMQX",
            base64Message: "oWVoZWxsb2V3b3JsZA",
            base64Signature: "MEUCIQCWumUqJqOCqInXF7AzhIRg2MhwRz2rWZcOEsOjPmNItgIgXJH7RnqfYY6M0eg33wU0sFYDlprwdOcpRn78Sz5ePgk",
            isSignatureValid: false,
            tags: ["der-encoded"]
        )

        var signatureVectors: [TestVector] = [signatureVector1, signatureVector2, signatureVector3, signatureVector4, signatureVector5, signatureVector6]
        return signatureVectors
    }
}
