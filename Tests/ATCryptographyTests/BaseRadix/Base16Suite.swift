//
//  Base16Suite.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-08.
//

import Testing
@testable import ATCryptography

struct Base16Suite {

    @Test("Encodes a single byte to lowercase Base16.")
    func encode() {
        let input: [UInt8] = [0x12, 0xAB, 0xCD, 0xEF]
        let expectedOutput = "12abcdef"
        #expect(Base16.encode(input) == expectedOutput)
    }

    @Test("Encodes a single byte to uppercase Base16.")
    func encodeUpper() {
        let input: [UInt8] = [0x12, 0xAB, 0xCD, 0xEF]
        let expectedOutput = "12ABCDEF"
        #expect(Base16.encodeUpper(input) == expectedOutput)
    }

    /// Test decoding a valid lowercase hex string.
    @Test("Decodes a valid lowercase Base16 string.")
    func decodeLowercase() {
        let input = "12abcdef"
        let expectedOutput: [UInt8] = [0x12, 0xAB, 0xCD, 0xEF]
        #expect(Base16.decode(input) == expectedOutput)
    }

    @Test("Decodes a valid uppercase Base16 string.")
    func decodeUppercase() {
        let input = "12ABCDEF"
        let expectedOutput: [UInt8] = [0x12, 0xAB, 0xCD, 0xEF]
        #expect(Base16.decode(input) == expectedOutput)
    }

    @Test("Decodes an invalid odd length Base16 string.")
    func decodeInvalidOddLength() {
        let input = "123"
        #expect(Base16.decode(input) == nil)
    }

    @Test("Decodes an invalid Base16 string (non-hex characters).")
    func decodeInvalidCharacters() {
        let input = "12GZ"
        #expect(Base16.decode(input) == nil)
    }

    /// Test decoding an empty string.
    @Test("Decodes an empty string.")
    func decodeEmptyString() {
        let input = ""
        let expectedOutput: [UInt8] = []
        #expect(Base16.decode(input) == expectedOutput)
    }
}
