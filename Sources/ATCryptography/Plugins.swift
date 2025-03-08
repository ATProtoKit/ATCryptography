//
//  Plugins.swift
//  ATCryptography
//
//  Created by Christopher Jr Riley on 2025-03-07.
//

import Foundation

/// A collection of supported `did:key` plugins.
public let plugins: [any DIDKeyPlugin.Type] = [
    P256Plugin.self,
    K256Plugin.self
]
