import Foundation

/// [M3 / MASVS-AUTH-1, AUTH-2] Insecure authentication / authorization — iOS edition.
/// [M1 / MASVS-STORAGE-1] Hardcoded admin credentials in the binary.
///
/// Two planted flaws:
///  1) verifyJWT() decodes the payload WITHOUT verifying the signature and honours alg:"none".
///  2) isAdmin() trusts an unverified client-side claim -> privilege escalation.
///
/// SECURE: verify the signature server-side against a fixed algorithm allow-list; never make
/// authorization decisions from unverified client-held claims.
enum AuthManager {

    // WRONG: backdoor credentials compiled in — recoverable via strings/class-dump.
    private static let adminUser = "admin"
    private static let adminPass = "VaultP@y2024!"

    static func localLogin(user: String, pass: String) -> Bool {
        user == adminUser && pass == adminPass
    }

    /// WRONG: no signature check; alg:none accepted.
    static func verifyJWT(_ jwt: String) -> [String: Any]? {
        let parts = jwt.split(separator: ".")
        guard parts.count >= 2 else { return nil }
        // (Header parsed but the "alg" is never enforced — none or any value is accepted.)
        guard let payloadData = base64URLDecode(String(parts[1])),
              let json = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any]
        else { return nil }
        return json
    }

    /// WRONG: authorization from an unverified claim.
    static func isAdmin(_ claims: [String: Any]) -> Bool {
        (claims["role"] as? String) == "admin"
    }

    private static func base64URLDecode(_ s: String) -> Data? {
        var str = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while str.count % 4 != 0 { str += "=" }
        return Data(base64Encoded: str)
    }
}
