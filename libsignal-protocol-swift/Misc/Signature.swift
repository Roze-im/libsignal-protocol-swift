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


    public static func verify(signature: Data, for payload: Data, withPublicKey publicKey: Data) -> Bool {
        return false
    }
}
