//
//  Base32Suite.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-08.
//

import Testing
@testable import ATCryptography

struct Base32Suite {

    @Test("Encodes a single byte to lowercase Base32.")
    func encode() {
        let input: [UInt8] = [0x12, 0x34, 0x56, 0x78]
        let expectedOutput = "ci2fm6a="
        #expect(Base32.encode(input) == expectedOutput)
    }

    @Test("Encodes a single byte to uppercase Base32.")
    func encodeUpper() {
        let input: [UInt8] = [0x12, 0x34, 0x56, 0x78]
        let expectedOutput = "CI2FM6A="
        #expect(Base32.encodeUpper(input) == expectedOutput)
    }

    @Test("Decodes a valid lowercase Base32 string.")
    func decodeLowercase() {
        let input = "ci2fm6=="
        let expectedOutput: [UInt8] = [0x12, 0x34, 0x56]
        #expect(Base32.decode(input) == expectedOutput)
    }

    @Test("Decodes a valid uppercase Base32 string.")
    func decodeUppercase() {
        let input = "CI2FM6=="
        let expectedOutput: [UInt8] = [0x12, 0x34, 0x56]
        #expect(Base32.decode(input) == expectedOutput)
    }

    @Test("Decodes an invalid Base32 string (contains illegal characters).")
    func decodeInvalidCharacters() {
        let input = "CI@FM6=="
        #expect(Base32.decode(input) == nil)
    }

    @Test("Decodes an empty string.")
    func decodeEmptyString() {
        let input = ""
        #expect(Base32.decode(input) == nil)
    }
}
