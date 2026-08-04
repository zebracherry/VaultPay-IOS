import Foundation
import os

/// [M6 / MASVS-PRIVACY-3] PII and secrets written to the system log; [M1] token logged too.
///
/// os_log/NSLog output is readable via Console.app / the unified log and captured in sysdiagnose
/// bundles. On a jailbroken device it's trivially observable.
///
/// SECURE: never log PII/secrets; use os_log with .private redaction and strip debug logging in
/// release builds.
enum PrivacyLogger {
    private static let log = OSLog(subsystem: "nz.co.vaultpay", category: "auth")

    static func logLogin(user: String, pan: String, token: String) {
        // WRONG: full PAN + bearer token in the clear, marked .public.
        os_log("login user=%{public}@ pan=%{public}@ token=%{public}@", log: log, type: .debug,
               user, pan, token)
    }

    static func logDeviceIdentifier(_ idfv: String) {
        // WRONG: sending a device-tied identifier to "analytics" with no consent (M6 / PRIVACY-1,4).
        os_log("analytics device_id=%{public}@", log: log, type: .info, idfv)
    }
}
