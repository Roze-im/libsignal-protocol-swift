//
//  SignatureTests.swift
//  libsignal-protocol-swiftTests
//
//  Created by Benjamin Garrigues on 06/07/2022.
//  Copyright © 2022 User. All rights reserved.
//

import Foundation
import XCTest
import SignalProtocol


class SignatureTests: XCTestCase {
    func testSignPayload() {
        guard let ownStore = setupStore(makeKeys: true) else {
            XCTFail("Could not create store")
            return
        }
        guard let identity = ownStore.identityKeyStore.identityKeyPair() else {
            XCTFail("no identity keypair found")
            return
        }

        let payload: Data = "test".data(using: .utf8)!
        let signature = Signature.sign(payload: payload, withPrivateKey: identity.privateKey)
        XCTAssertTrue(Signature.verify(signature: signature, for: payload, withPublicKey: identity.publicKey))
        XCTAssertFalse(Signature.verify(signature: signature, for: payload, withPublicKey: identity.privateKey))
    }
}
