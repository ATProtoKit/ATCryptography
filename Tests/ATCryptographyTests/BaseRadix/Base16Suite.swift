//
//  Base16Suite.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-08.
//

import Testing
@testable import ATCryptography

@Suite
struct `Base 16 Encoding and Decoding` {

    @Test
    func `Encodes a single byte to lowercase Base16`() {
        let input: [UInt8] = [0x12, 0xAB, 0xCD, 0xEF]
        let expectedOutput = "12abcdef"
        #expect(Base16.encode(input) == expectedOutput)
    }

    @Test
    func `Encodes a single byte to uppercase Base16`() {
        let input: [UInt8] = [0x12, 0xAB, 0xCD, 0xEF]
        let expectedOutput = "12ABCDEF"
        #expect(Base16.encodeUpper(input) == expectedOutput)
    }

    @Test
    func `Decodes a valid lowercase Base16 string`() {
        let input = "12abcdef"
        let expectedOutput: [UInt8] = [0x12, 0xAB, 0xCD, 0xEF]
        #expect(Base16.decode(input) == expectedOutput)
    }

    @Test
    func `Decodes a valid uppercase Base16 string`() {
        let input = "12ABCDEF"
        let expectedOutput: [UInt8] = [0x12, 0xAB, 0xCD, 0xEF]
        #expect(Base16.decode(input) == expectedOutput)
    }

    @Test
    func `Decodes an invalid odd length Base16 string`() {
        let input = "123"
        #expect(Base16.decode(input) == nil)
    }

    @Test
    func `Decodes an invalid Base16 string (non-hex characters)`() {
        let input = "12GZ"
        #expect(Base16.decode(input) == nil)
    }

    @Test
    func `Decodes an empty string`() {
        let input = ""
        let expectedOutput: [UInt8] = []
        #expect(Base16.decode(input) == expectedOutput)
    }
}
