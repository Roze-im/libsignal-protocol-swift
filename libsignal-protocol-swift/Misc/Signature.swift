//
//  Signature.swift
//  libsignal-protocol-swift
//
//  Created by Benjamin Garrigues on 06/07/2022.
//  Copyright © 2022 User. All rights reserved.
//

import Foundation
import SignalModule

public struct Signature {
    public enum SignatureError: Error {
        case signError(SignalError)
        case verifyError(SignalError)
        case nilSignatureBuffer
        case keyDecodeError(SignalError)
    }

    // privatekey: Taken from KeyPair
    public static func sign(payload: Data, withPrivateKey privateKey: Data) -> Result<Data, SignatureError> {

        // Convert private key to [UInt8]
        let privateBuffer = privateKey.signalBuffer
        defer { signal_buffer_free(privateBuffer) }
        let privLength = signal_buffer_len(privateBuffer)
        let privData = signal_buffer_data(privateBuffer)!
        var privKey: OpaquePointer? = nil
        let keyDecodeResult = withUnsafeMutablePointer(to: &privKey) {
            curve_decode_private_point($0, privData, privLength, Signal.context)
        }
        guard keyDecodeResult == 0 else {
            return .failure(.keyDecodeError(SignalError(value: keyDecodeResult)))
        }
        defer { ec_private_key_destroy(privKey) }

        var signatureBuf: OpaquePointer? = nil
        let signResult = withUnsafeMutablePointer(to: &signatureBuf) { signatureBufPtr in
            return payload.withUnsafeBytes {
                return curve_calculate_signature(
                    Signal.context,
                    signatureBufPtr,
                    privKey,
                    $0,
                    payload.count)
            }
        }

        guard signResult == 0 else {
            return .failure(.signError(SignalError(value: signResult)))
        }
        guard let signatureBuf = signatureBuf else {
            return .failure(.nilSignatureBuffer)
        }
        defer { signal_buffer_free(signatureBuf) }

        return .success(Data(signalBuffer: signatureBuf))
    }

    // publicKey : taken from KeyPair
    public static func verify(signature: Data, for payload: Data, withPublicKey publicKey: Data) -> Result<Bool, SignatureError> {

        // Convert public key
        let publicBuffer = publicKey.signalBuffer
        defer { signal_buffer_free(publicBuffer) }
        let pubLength = signal_buffer_len(publicBuffer)
        let pubData = signal_buffer_data(publicBuffer)!
        var pubKey: OpaquePointer? = nil
        let keyDecodeResult = withUnsafeMutablePointer(to: &pubKey) {
            curve_decode_point($0, pubData, pubLength, Signal.context)
        }

        guard keyDecodeResult == 0 else {
            return .failure(.keyDecodeError(SignalError(value: keyDecodeResult)))
        }
        defer { ec_public_key_destroy(pubKey) }

        let verifyRes = signature.withUnsafeBytes { signaturePtr in
            payload.withUnsafeBytes { payloadPtr in
                return curve_verify_signature(pubKey,
                                              payloadPtr,
                                              payload.count,
                                              signaturePtr,
                                              signature.count)
            }
        }

        if verifyRes < 0 {
            return .failure(.verifyError(SignalError(value: verifyRes)))
        }
        return .success(verifyRes == 0)
    }
}
