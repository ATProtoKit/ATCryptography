//
//  Plugins.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-07.
//

import Foundation

/// A collection of supported `did:key` plugins.
public let plugins: [any DIDKeyPlugin.Type] = [
    P256Plugin.self
    // TODO: Uncomment this when the struct has been implemented.
//    K256Plugin.self
]
