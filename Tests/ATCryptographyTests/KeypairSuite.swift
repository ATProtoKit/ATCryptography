//
//  KeypairSuite.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-13.
//

import Foundation
import Testing
@testable import ATCryptography

@Suite("Keypairs") struct KeypairTests {

    @Suite("k256 Keypairs") struct K256KeypairTests {

        @Test("Has the same k256 did:key on import.")
        func sameDIDKeyOnImport() async throws {
            let importedKeypair: K256Keypair

            let keypair = try K256Keypair.create(isExportable: true)
            let exportedKeypair = try await keypair.export()
            importedKeypair = try K256Keypair.importPrivateKey(privateKey: exportedKeypair)

            #expect(try keypair.did() == importedKeypair.did(), "The imported k256 did:key should match the original.")
        }

        @Test("Produces a valid k256 signature.")
        func produceValidSignature() async throws {
            let data: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
            let keypair = try K256Keypair.create()
            let signature = try await keypair.sign(message: data)

            let isValidSignature = try await K256Operations.verifyDIDSignature(
                did: keypair.did(),
                data: data,
                signature: signature
            )

            #expect(isValidSignature == true, "The k256 signature should be valid.")
        }
    }

    @Suite("p256 Keypairs") struct P256KeypairTests {

        @Test("Has the same p256 did:key on import.")
        func sameDIDKeyOnImport() async throws {
            let importedKeypair: P256Keypair

            let keypair = try P256Keypair.create(isExportable: true)
            let exportedKeypair = try await keypair.export()
            importedKeypair = try P256Keypair.importPrivateKey(privateKey: exportedKeypair)

            #expect(try keypair.did() == importedKeypair.did(), "The imported p256 did:key should match the original.")
        }

        @Test("Produces a valid p256 signature.")
        func produceValidSignature() async throws {
            let data: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
            let keypair = try P256Keypair.create()
            let signature = try await keypair.sign(message: data)

            let isValidSignature = try await P256Operations.verifyDIDSignature(
                did: keypair.did(),
                data: data,
                signature: signature
            )

            #expect(isValidSignature == true, "The p256 signature should be valid.")
        }
    }
}
