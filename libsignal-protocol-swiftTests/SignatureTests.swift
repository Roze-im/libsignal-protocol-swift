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
        var signature: Data = Data()
        switch Signature.sign(payload: payload, withPrivateKey: identity.privateKey) {
        case .success(let sign):
            signature = sign
        case .failure(let error):
            XCTFail("sign failure: \(error)")
        }

        // empty signature : should return false
        var res =  Signature.verify(signature: Data(), for: payload, withPublicKey: identity.publicKey)
        switch res {
        case .success(let success):
            XCTAssertFalse(success)
        case .failure(.verifyError(let error)):
            XCTAssertEqual(error, SignalError.invalidArgument)
        default:
            XCTFail("unexpected outcome for verify : \(res)")
        }

        // use the wrong key to verify
        let resPrivate = Signature.verify(signature: signature, for: payload, withPublicKey: identity.privateKey)
        switch resPrivate {
        case .failure(.keyDecodeError(let error)):
            XCTAssertEqual(error, SignalError.invalidKey)
        break
        default:
            XCTFail("unexpected verify with wrong key outcome : \(resPrivate)")
        }

        // verify a different payload
        switch Signature.verify(signature: signature, for: "test2".data(using: .utf8)!, withPublicKey: identity.publicKey){
        case .success(let success):
            XCTAssertFalse(success)
        case .failure(let failure):
            XCTFail("verify  failure : \(failure)")
        }

        // good verify
        switch Signature.verify(signature: signature, for: payload, withPublicKey: identity.publicKey){
        case .success(let success):
            XCTAssertTrue(success)
        case .failure(let failure):
            XCTFail("verify  failure : \(failure)")
        }

        // verify with a different public key
        let otherKeyPair = try! Signal.generateIdentityKeyPair()
        switch Signature.verify(signature: signature, for: payload, withPublicKey: otherKeyPair.publicKey){
        case .success(let success):
            XCTAssertFalse(success)
        case .failure(let failure):
            XCTFail("verify  failure : \(failure)")
        }

    }
}
