//
//  RandomSuite.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-13.
//

import Foundation
import Testing
@testable import ATCryptography

@Suite("Random") struct RandomTests {
    @Suite("Random Integer Tests") struct Test {

        @Test("Distributs effectively, even with low bucket counts.")
        func randomDistribution() async throws {
            var counts: [Int] = [0, 0]
            let salt = UUID().uuidString

            for i in 0..<10_000 {
                let int = try await SecureRandom.randomInt(from: "\(i)\(salt)", high: 2)
                counts[int] += 1
            }

            let zero = counts[0]
            let one = counts[1]

            #expect((zero + one) == 10_000, "All generated numbers sum up to 10,000.")
            #expect((Double(max(zero, one) / min(zero, one))) <= 1.1,
                    "The distribution is approximately even, allowing a tolerance level of 10%.")
        }

    }
}

