import Foundation
import SQLite3

/// [M4 / MASVS-CODE-4] SQL injection via a raw, string-built query — iOS edition.
///
/// loginRaw() concatenates untrusted input straight into SQL and runs it with sqlite3_exec /
/// sqlite3_prepare on a hand-built string. Input like  username = "' OR '1'='1' --"  returns
/// every row. Exercise it from the login screen or a Frida call.
///
/// SECURE: use parameter binding (sqlite3_bind_text with '?' placeholders) — see loginSafe().
final class VaultDatabase {
    private var db: OpaquePointer?

    init() {
        let url = FileManager.default
            .urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("vault.sqlite")
        sqlite3_open(url.path, &db)
        sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS users(username TEXT, password TEXT)", nil, nil, nil)
    }

    /// The vulnerability: SQL is built by concatenation.
    func loginRaw(username: String, password: String) -> Bool {
        let sql = "SELECT * FROM users WHERE username = '\(username)' AND password = '\(password)'"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return false }
        defer { sqlite3_finalize(stmt) }
        return sqlite3_step(stmt) == SQLITE_ROW
    }

    /// The correct reference implementation: parameterised, injection-safe.
    func loginSafe(username: String, password: String) -> Bool {
        let sql = "SELECT * FROM users WHERE username = ? AND password = ? LIMIT 1"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return false }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, (username as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 2, (password as NSString).utf8String, -1, nil)
        return sqlite3_step(stmt) == SQLITE_ROW
    }
}
