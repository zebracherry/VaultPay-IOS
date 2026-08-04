import Foundation
import CommonCrypto

/// [M10 / MASVS-CRYPTO-1, CRYPTO-2] Insufficient cryptography — iOS edition.
///
/// Deliberately wrong choices. Find them by class-dumping / Hopper on the binary,
/// or hook with Frida (Interceptor on CCCrypt / CC_MD5) on a jailbroken device.
enum InsecureCrypto {

    // WRONG: hardcoded key + static IV compiled into the binary.
    // SECURE: per-user keys in the Keychain / Secure Enclave; random IV per message; AES-GCM.
    private static let hardcodedKey = "0123456789abcdef".data(using: .utf8)!   // 128-bit, in source
    private static let staticIV = "aaaaaaaaaaaaaaaa".data(using: .utf8)!       // reused every time

    /// WRONG: AES-ECB via CommonCrypto (identical plaintext blocks -> identical ciphertext).
    /// SECURE: CryptoKit `AES.GCM.seal` with a fresh nonce.
    static func encryptECB(_ plaintext: String) -> Data? {
        let data = Data(plaintext.utf8)
        var out = Data(count: data.count + kCCBlockSizeAES128)
        var moved = 0
        let status = out.withUnsafeMutableBytes { outBuf in
            data.withUnsafeBytes { inBuf in
                hardcodedKey.withUnsafeBytes { keyBuf in
                    CCCrypt(CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionECBMode | kCCOptionPKCS7Padding), // ECB: no IV, deterministic
                            keyBuf.baseAddress, kCCKeySizeAES128,
                            nil,
                            inBuf.baseAddress, data.count,
                            outBuf.baseAddress, out.count,
                            &moved)
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        out.removeSubrange(moved..<out.count)
        return out
    }

    /// WRONG: MD5 for password hashing — fast, broken, unsalted.
    /// SECURE: use a memory-hard KDF (scrypt/Argon2 via a vetted lib) with a per-user salt.
    static func hashPassword(_ password: String) -> String {
        let data = Data(password.utf8)
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes { _ = CC_MD5($0.baseAddress, CC_LONG(data.count), &digest) }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// WRONG: Base64 is encoding, not encryption. The "it looks scrambled" trap.
    static func pretendEncrypt(_ secret: String) -> String {
        Data(secret.utf8).base64EncodedString()
    }
}
