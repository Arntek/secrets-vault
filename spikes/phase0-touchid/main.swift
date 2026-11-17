// Phase 0 prototype: can an unsigned (ad-hoc signed) command-line tool unlock a
// vault key with Touch ID through the Secure Enclave, with no paid Apple account?
//
//   touchid-spike enroll <dir>   create a Secure Enclave key (Touch ID required to use)
//                                and wrap a random test "vault key" to it
//   touchid-spike unlock <dir>   unwrap the test vault key; triggers the Touch ID sheet
//
// Everything written to <dir> is test data. No real secrets are involved.

import CryptoKit
import Foundation
import LocalAuthentication

func fail(_ msg: String, _ code: Int32 = 1) -> Never {
    FileHandle.standardError.write((msg + "\n").data(using: .utf8)!)
    exit(code)
}

func hkdfKey(_ shared: SharedSecret, _ ephPub: Data, _ sePub: Data) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: ephPub + sePub,
        sharedInfo: "secrets-vault/touchid/v0".data(using: .utf8)!,
        outputByteCount: 32)
}

struct Wrapped: Codable {
    let sePublicKey: String      // base64 x963
    let ephemeralPublicKey: String
    let sealed: String           // AES-GCM combined
    let checkHash: String        // sha256 of the test vault key, prototype check only
}

let args = CommandLine.arguments
guard args.count == 3 else { fail("usage: touchid-spike enroll|unlock <dir>", 2) }
let dir = URL(fileURLWithPath: args[2], isDirectory: true)
let blobURL = dir.appendingPathComponent("se-key.blob")
let wrapURL = dir.appendingPathComponent("wrapped.json")

guard SecureEnclave.isAvailable else { fail("Secure Enclave not available on this Mac") }

switch args[1] {
case "enroll":
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    var err: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet], &err)
    else { fail("access control: \(String(describing: err?.takeRetainedValue()))") }

    let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
    do { seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access) }
    catch { fail("create Secure Enclave key failed: \(error)") }

    // Random test vault key, wrapped to the Secure Enclave public key (ECIES-style).
    let vaultKey = SymmetricKey(size: .bits256)
    let eph = P256.KeyAgreement.PrivateKey()
    let shared = try! eph.sharedSecretFromKeyAgreement(with: seKey.publicKey)
    let sePub = seKey.publicKey.x963Representation
    let ephPub = eph.publicKey.x963Representation
    let wrapKey = hkdfKey(shared, ephPub, sePub)
    let vk = vaultKey.withUnsafeBytes { Data($0) }
    let sealed = try! AES.GCM.seal(vk, using: wrapKey).combined!

    let w = Wrapped(
        sePublicKey: sePub.base64EncodedString(),
        ephemeralPublicKey: ephPub.base64EncodedString(),
        sealed: sealed.base64EncodedString(),
        checkHash: Data(SHA256.hash(data: vk)).base64EncodedString())
    try! seKey.dataRepresentation.write(to: blobURL, options: .atomic)
    try! JSONEncoder().encode(w).write(to: wrapURL, options: .atomic)
    print("ENROLLED: Secure Enclave key created (Touch ID required to use). Test vault key wrapped.")

case "unlock":
    guard let blob = try? Data(contentsOf: blobURL),
          let wdata = try? Data(contentsOf: wrapURL),
          let w = try? JSONDecoder().decode(Wrapped.self, from: wdata)
    else { fail("not enrolled in \(dir.path)") }

    let ctx = LAContext()
    ctx.localizedReason = "unlock the 'test' vault"
    let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
    do { seKey = try .init(dataRepresentation: blob, authenticationContext: ctx) }
    catch { fail("load Secure Enclave key failed: \(error)") }

    let ephPub = Data(base64Encoded: w.ephemeralPublicKey)!
    let sePub = Data(base64Encoded: w.sePublicKey)!
    let start = Date()
    let shared: SharedSecret
    do {
        // This is the step that needs the fingerprint.
        shared = try seKey.sharedSecretFromKeyAgreement(
            with: P256.KeyAgreement.PublicKey(x963Representation: ephPub))
    } catch { fail("Touch ID / key agreement failed: \(error)", 3) }
    let wrapKey = hkdfKey(shared, ephPub, sePub)
    guard let box = try? AES.GCM.SealedBox(combined: Data(base64Encoded: w.sealed)!),
          let vk = try? AES.GCM.open(box, using: wrapKey)
    else { fail("unwrap failed: wrong key or tampered file", 4) }
    let ok = Data(SHA256.hash(data: vk)).base64EncodedString() == w.checkHash
    print(ok ? "UNLOCKED: test vault key recovered and verified (waited \(String(format: "%.1f", Date().timeIntervalSince(start)))s for Touch ID)"
             : "MISMATCH: recovered key does not match")
    exit(ok ? 0 : 5)

default:
    fail("usage: touchid-spike enroll|unlock <dir>", 2)
}
