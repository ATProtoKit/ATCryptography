//
//  KeyCompressionSuite.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-11.
//

import Foundation
import Testing
@testable import ATCryptography

@Suite("Public Key Compression") struct PublicKeyCompressionTests {

    @Suite("k256 Compression") struct k256Tests {

        @Test("Compresses a k256 keypair to its appropriate length, then to its original length.")
        func compressAndDecompressKeypair() throws {
            var keyBytes: [UInt8] = []
            var compressedKeys: [UInt8] = []

            let keypair = try K256Keypair.create()
            let parsedDIDKey = try DIDKey.parseDIDKey(keypair.did())
            keyBytes = parsedDIDKey.keyBytes

            compressedKeys = try K256Encoding.compressPublicKey(keyBytes)

            try #require(compressedKeys.count == 33,
                         "The compressed public key should have 33 bytes.")

            let decompressedKeys = try K256Encoding.decompressPublicKey(compressedKeys)

            #expect(decompressedKeys.count == 65,
                    "The decompressed public key should have 65 bytes.")
        }

        @Test("Creates, compresses, and decompresses 100 k256 keypairs to make sure the compression works consistently.")
        func compressionLoop() throws {
            var publicKeys: [[UInt8]] = []
            var compressedKeys: [[UInt8]] = []
            var decompressedKeys: [[UInt8]] = []

            for _ in 1...100 {
                let keypair = try K256Keypair.create()
                let parsedDIDKey = try DIDKey.parseDIDKey(keypair.did())
                publicKeys.append(parsedDIDKey.keyBytes)
            }

            compressedKeys = try publicKeys.map { try K256Encoding.compressPublicKey($0) }
            decompressedKeys = try compressedKeys.map { try K256Encoding.decompressPublicKey($0) }

            #expect(publicKeys == decompressedKeys, "The decompressed public keys much match the original ones.")
        }
    }

    @Suite("p256 Compression") struct p256Tests {

        @Test("Compresses a p256 keypair to its appropriate length, then to its original length.")
        func compressAndDecompressKeypair() throws {
            var keyBytes: [UInt8] = []
            var compressedKeys: [UInt8] = []

            let keypair = try P256Keypair.create()
            let parsedDIDKey = try DIDKey.parseDIDKey(keypair.did())
            keyBytes = parsedDIDKey.keyBytes

            compressedKeys = try P256Encoding.compressPublicKey(keyBytes)

            try #require(compressedKeys.count == 33,
                         "The compressed public key should have 33 bytes.")

            let decompressedKeys = try P256Encoding.decompressPublicKey(compressedKeys)

            #expect(decompressedKeys.count == 65,
                    "The decompressed public key should have 65 bytes.")
        }
    }
}

