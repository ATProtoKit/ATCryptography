# Generating and Managing Keypairs

Learn how to use ATCryptography to create and manage keypairs, as well as signing and verifying signatures.

## Overview

The AT Protocol relies on cryptography for various parts of the protocol, from OAuth, to DAG-CBOR encoding. This article will show you how to use ATCryptography effectively and what to look out for.

### Key Generation

To create a keypair, you first use one of the two `struct`s available: ``K256Keypair`` (for k256) and ``P256Keypair`` (for p256). In Bluesky, while both can be used, it's recommended that you use the one for k256, as Bluesky uses this cryptography system by default. However, you are free to use whichever one you want, especially if you're building your own service on atproto.

**Generating a k256 keypair**
```swift
Task {
    do {
        let keypair = try K256Keypair.create()

        print(publicKey)
    } catch {
        throw error
    }
}
```

**Generaing a p256 keypair**
```swift
Task {
    do {
        let keypair = try K256Keypair.create()

        print(publicKey)
    } catch {
        throw error
    }
}
```

From here, you can check what the public key looks like using ``K256Keypair/publicKeyBytes()`` (k256)/``P256Keypair/publicKeyBytes()`` (p256):

```swift
let publicKey = try keypair.publicKeyBytes()
```

### Importing And Exporting a Keypair

If you already received a keypair from an external source, or if you wish to send the keypair to an external source, you can easily import and export the keypairs. Please keep in mind of two things:
1. Make sure you know what cryptography system the keypair is in. Putting a mismatched keypair into the incorrect method can result in an error.
2. Before you export, make sure the ``K256Keypair/create(isExportable:)`` (k256)/``P256Keypair/create(isExportable:)`` (p256) method has `isExportable` to `true`, as it's set to `false` by default. You are unable to change this after the fact.

To import a keypair, use the ``K256Keypair/import(privateKey:isExportable:)`` (k256)/``P256Keypair/import(privateKey:isExportable:)`` (p256) method.


```swift
Task {
    do {
        let importedKeypair: [UInt8] = [/* A keypair in an array of bytes...*/]

        // k256
        let keypair = try K256Keypair.import(privateKey: importedKeypair)
        
        // p256
        let keypair = try P256Keypair.import(privateKey: importedKeypair)
    } catch {
        throw error
    }
}
```

- Note: ``K256Keypair/import(privateKey:isExportable:)`` (k256)/``P256Keypair/import(privateKey:isExportable:)`` (p256) also includes the `isExportable` argument. Be sure to set it to `true` if you intend to export the keypair later on.

To export the keypair, use the ``K256Keypair/export()`` (k256)/ ``P256Keypair/export()`` (p256) method:

```swift
let exportedKeypair = try keypair.export()
```

The method will return an `[UInt8]` object.

### Signing a Message

When you want to sign something with the keypair, you use the ``K256Keypair/sign(message:)`` (k256)/``P256Keypair/sign(message:)`` (p256) method. In the `message` argument, insert the message as an `[UInt8]` object. This will return a signature in the form of an `[UInt8]` object.

```swift
Task {
    do {
        let message: [UInt8] = [0x41, 0x54, 0x50, 0x72, 0x6F, 0x74, 0x6F, 0x4B, 0x69, 0x74]

        // k256
        let keypair = try K256Keypair.create()
        let signature = keypair.sign(message: message)
        print(signature)

        // p256
        let keypair = try P256Keypair.create()
        let signature = keypair.sign(message: message)
        print(signature)
    } catch {
        throw error
    }
}
```

It's highly recommended to verify the signature after creating it. Before doing so, be sure to grab the `did:key` for the keypair by using ``K256Keypair/did()`` (k256)/``P256Keypair/did()`` (p256). After that, use ``SignatureVerifier/verifySignature(didKey:data:signature:options:jwtAlgorithm:)``. Insert the `did:key` into the `didKey` argument, the message in the `data` argument, and the signature in the `signature` argument.

```swift
Task {
    do {
        let message: [UInt8] = [0x41, 0x54, 0x50, 0x72, 0x6F, 0x74, 0x6F, 0x4B, 0x69, 0x74]

        // k256
        let keypair = try K256Keypair.create()
        let didKey = keypair.did()
        let signature = keypair.sign(message: message)

        // p256
        let keypair = try P256Keypair.create()
        let didKey = keypair.did()
        let signature = keypair.sign(message: message)
        
        // Verify the signature.
        let isSignatureValid = try await SignatureVerifier.verifySignature(
            didKey: didKey,
            data: message,
            signature: signature
        )

        if isSignatureValid == true {
            print("Signature has been verified!")
        } else {
            print("This signature appears to be suspicious.")
        }
    } catch {
        throw error
    }
}
```

The method will only return a `Bool`. If it returns `false`, then the following may be the issue:
- Check that the public key and signature are using the same cryptographic system.
- The message may not have been hashed correctly (if you didn't do it yourself). It's a good idea to hash it yourself instead of relying on an outside source
unless you can be sure it will return with a properly-hashed message.
- The signature could have been from a bad actor. If this is the case, reject it immediately and let the user know about it. 
