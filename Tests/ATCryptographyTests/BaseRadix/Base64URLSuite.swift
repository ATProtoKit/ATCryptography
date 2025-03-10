//
//  Base64URLSuite.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-10.
//

import Foundation
import Testing
@testable import ATCryptography

struct Base64URLSuite {

    @Test("Encodes bytes to a Base64URL string.")
    func encodeURL() {
        let input: [UInt8] = [0x8f, 0x2b, 0x7b, 0x4b, 0x9e, 0xa3, 0x38, 0x99, 0x63, 0x49, 0x05, 0x91, 0x10]
        let expectedOutput = "jyt7S56jOJljSQWREA"

        let data = Data(input)

        #expect(Base64URL.encodeURL(data) == expectedOutput)
    }

    @Test("Encodes bytes to a Base64URLPad string.")
    func encodeURLPad() {
        let input: [UInt8] = [0x8f, 0x2b, 0x7b, 0x4b, 0x9e, 0xa3, 0x38, 0x99, 0x63, 0x49, 0x05, 0x91, 0x10, 0x0f, 0xfe]
        let expectedOutput = "jyt7S56jOJljSQWREA_-"

        let data = Data(input)

        #expect(Base64URL.encodeURLPad(data) == expectedOutput)
    }

    @Test("Decodes a Base64URL string to an array of bytes.")
    func decodeURL() {
        let input = "jyt7S56jOJljSQWREA"
        let expectedOutput: [UInt8] = [0x8f, 0x2b, 0x7b, 0x4b, 0x9e, 0xa3, 0x38, 0x99, 0x63, 0x49, 0x05, 0x91, 0x10]

        let base64URL = Base64URL.decodeURL(input)

        #expect(base64URL == Data(expectedOutput))
    }

    @Test("Decodes a BaseURLPad string to an array of bytes.")
    func decodeURLPad() {
        let input = "jyt7S56jOJljSQWREA_-"
        let expectOutput: [UInt8] = [0x8f, 0x2b, 0x7b, 0x4b, 0x9e, 0xa3, 0x38, 0x99, 0x63, 0x49, 0x05, 0x91, 0x10, 0x0f, 0xfe]

        let base64URLPad = Base64URL.decodeURLPad(input)

        #expect(base64URLPad == Data(expectOutput))
    }

    @Test("Decodes an invalid Base64URL (contains illegal character).")
    func decodeInvalidCharacter() {
        let input = "jyt7S56jOJljSQ#REA_-"

        let base64URL = Base64URL.decodeURL(input)

        #expect(base64URL == nil)
    }

    @Test("Decodes an invalid Base64URLPad (contains illegal character).")
    func decodeInvalidCharacterPad() {
        let input = "jyt7S56jOJljSQ#REA_-"
        
        let base64URLPad = Base64URL.decodeURLPad(input)
        
        #expect(base64URLPad == nil)
    }

    @Test("Decodes an empty string (Base64URL)")
    func decodeEmptyBase64URLString() async throws {
        let input = ""

        let base64URL = Base64URL.decodeURL(input)

        #expect(base64URL == Data())
    }

    @Test("Decodes an empty string (Base64URLPad)")
    func decodeEmptyBase64URLPadString() async throws {
        let input = ""

        let base64URLPad = Base64URL.decodeURLPad(input)

        #expect(base64URLPad == Data())
    }
}
