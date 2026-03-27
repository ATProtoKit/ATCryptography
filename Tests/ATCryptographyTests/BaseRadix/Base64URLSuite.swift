//
//  Base64URLSuite.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-10.
//

import Foundation
import Testing
@testable import ATCryptography

@Suite
struct `Base64URL Encoding and Decoding` {

    @Test
    func `Encodes bytes to a Base64URL string`() {
        let input: [UInt8] = [0x8f, 0x2b, 0x7b, 0x4b, 0x9e, 0xa3, 0x38, 0x99, 0x63, 0x49, 0x05, 0x91, 0x10]
        let expectedOutput = "jyt7S56jOJljSQWREA"

        let data = Data(input)

        #expect(Base64URL.encodeURL(data) == expectedOutput)
    }

    @Test
    func `Encodes bytes to a Base64URLPad string`() {
        let input: [UInt8] = [0x8f, 0x2b, 0x7b, 0x4b, 0x9e, 0xa3, 0x38, 0x99, 0x63, 0x49, 0x05, 0x91, 0x10, 0x0f, 0xfe]
        let expectedOutput = "jyt7S56jOJljSQWREA_-"

        let data = Data(input)

        #expect(Base64URL.encodeURLPad(data) == expectedOutput)
    }

    @Test
    func `Decodes a Base64URL string to an array of bytes`() {
        let input = "jyt7S56jOJljSQWREA"
        let expectedOutput: [UInt8] = [0x8f, 0x2b, 0x7b, 0x4b, 0x9e, 0xa3, 0x38, 0x99, 0x63, 0x49, 0x05, 0x91, 0x10]

        let base64URL = Base64URL.decodeURL(input)

        #expect(base64URL == Data(expectedOutput))
    }

    @Test
    func `Decodes a BaseURLPad string to an array of bytes`() {
        let input = "jyt7S56jOJljSQWREA_-"
        let expectOutput: [UInt8] = [0x8f, 0x2b, 0x7b, 0x4b, 0x9e, 0xa3, 0x38, 0x99, 0x63, 0x49, 0x05, 0x91, 0x10, 0x0f, 0xfe]

        let base64URLPad = Base64URL.decodeURLPad(input)

        #expect(base64URLPad == Data(expectOutput))
    }

    @Test
    func `Decodes an invalid Base64URL (contains illegal character)`() {
        let input = "jyt7S56jOJljSQ#REA_-"

        let base64URL = Base64URL.decodeURL(input)

        #expect(base64URL == nil)
    }

    @Test
    func `Decodes an invalid Base64URLPad (contains illegal character)`() {
        let input = "jyt7S56jOJljSQ#REA_-"
        
        let base64URLPad = Base64URL.decodeURLPad(input)
        
        #expect(base64URLPad == nil)
    }

    @Test
    func `Decodes an empty string (Base64URL)`() {
        let input = ""

        let base64URL = Base64URL.decodeURL(input)

        #expect(base64URL == Data())
    }

    @Test
    func `Decodes an empty string (Base64URLPad)`() {
        let input = ""

        let base64URLPad = Base64URL.decodeURLPad(input)

        #expect(base64URLPad == Data())
    }
}
