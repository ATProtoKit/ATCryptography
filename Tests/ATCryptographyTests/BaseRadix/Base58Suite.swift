//
//  Base58Suite.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-09.
//

import Foundation
import Testing
@testable import ATCryptography

@Suite
struct `Base58 Encoding and Decoding` {

    @Test
    func `Encodes a Data object to a Base58-encoded string`() {
        let input: [UInt8] = [0x02, 0x6f, 0x55, 0x60, 0x84, 0xa5, 0x75, 0x5e, 0x9c, 0x8b, 0x8f, 0x0b]
        let expectedOutput = "3fa85f6457174562"
        #expect(Base58.encode(Data(input)) == expectedOutput)
    }

    @Test
    func `Decodes a Base58-encoded string to a Data object`() throws {
        let input = "3fa85f6457174562"
        let expectedOutput: [UInt8] = [0x02, 0x6F, 0x55, 0x60, 0x84, 0xA5, 0x75, 0x5E, 0x9C, 0x8B, 0x8F, 0x0B]

        let base58 = try Base58.decode(input)

        #expect(base58 == Data(expectedOutput))
    }

    @Test
    func `Fails from an invalid character`() throws {
        let input = "3fa85f645717456&"

        #expect(throws: Base58Error.self) {
            try Base58.decode(input)
        }
    }

    @Test
    func `Decodes an empty string`() throws {
        let input = ""
        let base58 = try Base58.decode(input)
        #expect(base58 == Data())
    }
}
