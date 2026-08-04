import Foundation
import Security

/// [M9 / MASVS-STORAGE-1, STORAGE-2] Insecure data storage — iOS edition.
/// [M1 / MASVS-STORAGE-1] Credentials at rest in the clear.
///
/// Recover with: a jailbroken-device file pull of the app container's
/// Library/Preferences/*.plist (UserDefaults) and Documents/, or Keychain-Dumper
/// for the (mis-)accessible Keychain item.
final class InsecureStorage {

    // WRONG: sensitive values in UserDefaults -> plain plist in the app container, included in
    // unencrypted local/iTunes backups.
    // SECURE: Keychain with kSecAttrAccessibleWhenUnlockedThisDeviceOnly, or files with
    // NSFileProtectionComplete.
    private let defaults = UserDefaults.standard

    func savePIN(_ pin: String)   { defaults.set(pin,   forKey: "user_pin") }     // plaintext PIN
    func saveToken(_ token: String) { defaults.set(token, forKey: "bearer_token") }
    func savePAN(_ pan: String)   { defaults.set(pan,   forKey: "card_pan") }     // full card number

    /// WRONG: Keychain item stored with kSecAttrAccessibleAlways -> readable even when the device
    /// is locked, and survives on jailbroken extraction.
    /// SECURE: kSecAttrAccessibleWhenUnlockedThisDeviceOnly (or Secure Enclave for keys).
    func saveTokenToKeychainInsecurely(_ token: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "vaultpay_token",
            kSecValueData as String: Data(token.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAlways  // deprecated + insecure on purpose
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    /// WRONG: writing the PAN to Documents/ with no file protection.
    /// SECURE: never persist a PAN client-side; if unavoidable, NSFileProtectionComplete.
    func exportCardToDocuments(_ pan: String) {
        let url = FileManager.default
            .urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("vaultpay_card.txt")
        try? "PAN=\(pan)".write(to: url, atomically: true, encoding: .utf8)
    }
}
