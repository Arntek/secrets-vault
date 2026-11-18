// Secure Enclave bridge for internal/touchid, exposed to Go through a C
// interface (bridge.h) and linked as a static library by cgo.
//
// The Swift side only does what needs CryptoKit and the Secure Enclave:
// create a Touch ID-gated P-256 key, read its public key, and run ECDH with
// it after the user touches the sensor. Wrapping, HKDF and AES-GCM happen in
// Go, where they are unit-tested.
//
// The key is stored as a CryptoKit dataRepresentation blob in a normal file
// (no Keychain, no entitlements, no paid Apple account). The blob is only
// usable by this Mac's Secure Enclave.
//
// Never log or print key material here: no print(), no NSLog().

import CryptoKit
import Foundation
import LocalAuthentication
import Security

private let SVTID_OK: Int32 = 0
private let SVTID_NO_ENCLAVE: Int32 = 1
private let SVTID_NO_BIOMETRY: Int32 = 2
private let SVTID_CANCELLED: Int32 = 3
private let SVTID_AUTH_FAILED: Int32 = 4
private let SVTID_BAD_KEY: Int32 = 5
private let SVTID_BUFFER: Int32 = 6
private let SVTID_FAILED: Int32 = 7

private let pubLen = 65
private let sharedLen = 32

private func accessControl() -> SecAccessControl? {
    SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet], nil)
}

// Maps a LocalAuthentication error to a status code.
private func laStatus(_ error: Error?) -> Int32 {
    guard let ns = error as NSError?, ns.domain == LAErrorDomain else {
        return SVTID_FAILED
    }
    switch LAError.Code(rawValue: ns.code) {
    case .userCancel?, .systemCancel?, .appCancel?, .userFallback?:
        return SVTID_CANCELLED
    case .authenticationFailed?:
        return SVTID_AUTH_FAILED
    case .biometryNotAvailable?, .biometryNotEnrolled?, .biometryLockout?,
         .passcodeNotSet?, .notInteractive?:
        return SVTID_NO_BIOMETRY
    default:
        return SVTID_FAILED
    }
}

@_cdecl("svtid_check")
public func svtidCheck() -> Int32 {
    guard SecureEnclave.isAvailable else { return SVTID_NO_ENCLAVE }
    var err: NSError?
    let ctx = LAContext()
    guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) else {
        return SVTID_NO_BIOMETRY
    }
    return SVTID_OK
}

@_cdecl("svtid_create")
public func svtidCreate(
    _ blob: UnsafeMutablePointer<UInt8>?, _ blobCap: Int,
    _ blobLen: UnsafeMutablePointer<Int>?, _ pub: UnsafeMutablePointer<UInt8>?
) -> Int32 {
    guard let blob = blob, let blobLen = blobLen, let pub = pub else { return SVTID_FAILED }
    guard SecureEnclave.isAvailable else { return SVTID_NO_ENCLAVE }
    guard let access = accessControl() else { return SVTID_FAILED }
    let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
    } catch {
        return SVTID_FAILED
    }
    let data = key.dataRepresentation
    let p = key.publicKey.x963Representation
    guard data.count <= blobCap, p.count == pubLen else { return SVTID_BUFFER }
    data.copyBytes(to: blob, count: data.count)
    p.copyBytes(to: pub, count: pubLen)
    blobLen.pointee = data.count
    return SVTID_OK
}

@_cdecl("svtid_public_key")
public func svtidPublicKey(
    _ blob: UnsafePointer<UInt8>?, _ blobLen: Int, _ pub: UnsafeMutablePointer<UInt8>?
) -> Int32 {
    guard let blob = blob, blobLen > 0, let pub = pub else { return SVTID_BAD_KEY }
    guard SecureEnclave.isAvailable else { return SVTID_NO_ENCLAVE }
    let data = Data(bytes: blob, count: blobLen)
    // Loading the key and reading its public half does not need Touch ID.
    guard let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data)
    else { return SVTID_BAD_KEY }
    let p = key.publicKey.x963Representation
    guard p.count == pubLen else { return SVTID_BAD_KEY }
    p.copyBytes(to: pub, count: pubLen)
    return SVTID_OK
}

@_cdecl("svtid_agree")
public func svtidAgree(
    _ blob: UnsafePointer<UInt8>?, _ blobLen: Int, _ peer: UnsafePointer<UInt8>?,
    _ reason: UnsafePointer<CChar>?, _ shared: UnsafeMutablePointer<UInt8>?
) -> Int32 {
    guard let blob = blob, blobLen > 0, let peer = peer, let reason = reason,
          let shared = shared
    else { return SVTID_FAILED }
    guard SecureEnclave.isAvailable else { return SVTID_NO_ENCLAVE }
    guard let access = accessControl() else { return SVTID_FAILED }

    let ctx = LAContext()
    let why = String(cString: reason)
    ctx.localizedReason = why
    ctx.localizedCancelTitle = "Use passphrase"
    var checkErr: NSError?
    guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &checkErr) else {
        return SVTID_NO_BIOMETRY
    }

    // Show the Touch ID sheet first, so cancel and failure come back as
    // LAError codes instead of an opaque key-agreement error. The key
    // operation below then reuses the authenticated context.
    let done = DispatchSemaphore(value: 0)
    var evalErr: Error?
    var ok = false
    ctx.evaluateAccessControl(access, operation: .useKeyKeyExchange, localizedReason: why) {
        success, error in
        ok = success
        evalErr = error
        done.signal()
    }
    done.wait()
    guard ok else { return laStatus(evalErr) }

    let data = Data(bytes: blob, count: blobLen)
    let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: data, authenticationContext: ctx)
    } catch {
        return SVTID_BAD_KEY
    }
    guard let peerKey = try? P256.KeyAgreement.PublicKey(
        x963Representation: Data(bytes: peer, count: pubLen))
    else { return SVTID_BAD_KEY }

    let secret: SharedSecret
    do {
        secret = try key.sharedSecretFromKeyAgreement(with: peerKey)
    } catch {
        let s = laStatus(error)
        // A fingerprint change invalidates a .biometryCurrentSet key; that
        // and any other key-side failure is reported as an auth failure.
        return s == SVTID_FAILED ? SVTID_AUTH_FAILED : s
    }
    let n = secret.withUnsafeBytes { raw -> Int in
        guard raw.count == sharedLen else { return 0 }
        raw.copyBytes(to: UnsafeMutableRawBufferPointer(start: shared, count: sharedLen))
        return raw.count
    }
    return n == sharedLen ? SVTID_OK : SVTID_FAILED
}
