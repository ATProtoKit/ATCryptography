//
//  DIDKeySuite.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-10.
//

import Foundation
import Testing
@testable import ATCryptography

@Suite("did:keys") struct didKeyTests {

    @Suite("k256 did:key") struct k256DIDKeyTests {

        @Test("Validate whether a private key correctly derives a did:key (in k256).",
              arguments: zip(
                EllipticalCurveTestVectors.k256Seeds,
                EllipticalCurveTestVectors.k256IDs))
        func validateKeyDerivesDID(seed: String, didKey: String) throws {
            let keypair = try K256Keypair.import(privateKey: seed.hexBytes)
            let keypairDIDKey = try keypair.did()

            #expect(keypairDIDKey == didKey,
                    "The k256 did:key generated from the seed should match the hard-coded did:key.")
        }

        @Test("Converts between bytes to did:key (in k256).",
              arguments: zip(
                EllipticalCurveTestVectors.k256Seeds,
                EllipticalCurveTestVectors.k256IDs))
        func convertBytesToDIDKey(seed: String, didKey: String) throws {
            let keypair = try K256Keypair.import(privateKey: seed.hexBytes)
            let formattedDIDKey = try DIDKey.formatDIDKey(
                jwtAlgorithm: k256JWTAlgorithm,
                keyBytes: keypair.publicKeyBytes()
            )

            try #require(formattedDIDKey == didKey,
                         "The k256 did:key generated from the seed should match the hard-coded did:key.")

            let parsedDIDKey = try DIDKey.parseDIDKey(didKey)
            #expect(parsedDIDKey.jwtAlgorithm == k256JWTAlgorithm,
                    "The JWT algorithm should match the hard-coded value.")
            #expect(parsedDIDKey.keyBytes == keypair.publicKeyBytes(),
                    "The array of bytes in the parsed did:key should match the array of bytes in the keypair.")
        }
    }

    @Suite("p256 did:key") struct p256DIDKeyTests {

        @Test("Derives the correct did:key from the JWK algorithm (in p256).",
              arguments: zip(
                EllipticalCurveTestVectors.p256PrivateKeys,
                EllipticalCurveTestVectors.p256TestVectorsIDs))
        func validateKeyDerivesDID(privateKey: String, didKey: String) throws {
            let bytes: [UInt8] = [UInt8](try Base58.decode(privateKey))
            let keypair = try P256Keypair.import(privateKey: bytes)
            let keypairDIDKey = try keypair.did()

            #expect(keypairDIDKey == didKey,
                    "The k256 did:key generated from the seed should match the hard-coded did:key.")
        }

        @Test("Converts between bytes to did:key (in p256).",
              arguments: zip(
                EllipticalCurveTestVectors.p256PrivateKeys,
                EllipticalCurveTestVectors.p256TestVectorsIDs))
        func convertBytesToDIDKey(privateKey: String, didKey: String) throws {
            let bytes: [UInt8] = [UInt8](try Base58.decode(privateKey))
            let keypair = try P256Keypair.import(privateKey: bytes)
            let formattedDIDKey = try DIDKey.formatDIDKey(
                jwtAlgorithm: p256JWTAlgorithm,
                keyBytes: keypair.publicKeyBytes()
            )

            try #require(formattedDIDKey == didKey,
                         "The k256 did:key generated from the seed should match the hard-coded did:key.")

            let parsedDIDKey = try DIDKey.parseDIDKey(didKey)
            #expect(parsedDIDKey.jwtAlgorithm == p256JWTAlgorithm,
                    "The JWT algorithm should match the hard-coded value.")
            #expect(parsedDIDKey.keyBytes == keypair.publicKeyBytes(),
                    "The array of bytes in the parsed did:key should match the array of bytes in the keypair.")
        }
    }

    enum EllipticalCurveTestVectors {

        // did:key k256 test vectors from W3C.
        // https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/secp256k1.json
        static var k256Seeds: [String] {
            return [
                "9085d2bef69286a6cbb51623c8fa258629945cd55ca705cc4e66700396894e0c",
                "f0f4df55a2b3ff13051ea814a8f24ad00f2e469af73c363ac7e9fb999a9072ed",
                "6b0b91287ae3348f8c2f2552d766f30e3604867e34adc37ccbb74a8e6b893e02",
                "c0a6a7c560d37d7ba81ecee9543721ff48fea3e0fb827d42c1868226540fac15",
                "175a232d440be1e0788f25488a73d9416c04b6f924bea6354bf05dd2f1a75133"
            ]
        }

        // did:key k256 test vectors from W3C.
        // https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/secp256k1.json
        static var k256IDs: [String] {
            return [
                "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
                "did:key:zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2",
                "did:key:zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N",
                "did:key:zQ3shadCps5JLAHcZiuX5YUtWHHL8ysBJqFLWvjZDKAWUBGzy",
                "did:key:zQ3shptjE6JwdkeKN4fcpnYQY3m9Cet3NiHdAfpvSUZBFoKBj"
            ]
        }

        // did:key p256 test vectors from W3C.
        // https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/nist-curves.json
        static var p256PrivateKeys: [String] {
            return [
                "9p4VRzdmhsnq869vQjVCTrRry7u4TtfRxhvBFJTGU2Cp"
            ]
        }

        // did:key p256 test vectors from W3C.
        // https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/nist-curves.json
        static var p256TestVectorsIDs: [String] {
            return [
                "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb"
            ]
        }
    }
}
