import SwiftUI

/// Minimal UI that wires the vulnerable primitives together so the app is runnable and testable.
/// This is deliberately thin — the security-relevant logic lives in the per-concern files.
struct ContentView: View {
    @StateObject private var router = DeepLinkRouter.shared
    @State private var username = ""
    @State private var password = ""
    @State private var status = ""

    private let db = VaultDatabase()
    private let storage = InsecureStorage()

    var body: some View {
        VStack(spacing: 16) {
            Text("VaultPay").font(.largeTitle).bold()
            Text("⚠️ Intentionally vulnerable — test builds only")
                .font(.footnote).foregroundColor(.secondary)

            TextField("Username", text: $username)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .textFieldStyle(.roundedBorder)
            SecureField("Password", text: $password)
                .textFieldStyle(.roundedBorder)

            Button("Log in") {
                // [M4] injectable path; [M9/M1] persists secrets insecurely; [M6] logs them.
                let ok = db.loginRaw(username: username, password: password)
                storage.savePIN("1234")
                storage.saveToken("demo.bearer.token")
                PrivacyLogger.logLogin(user: username, pan: "4111111111111111",
                                       token: "demo.bearer.token")
                status = ok ? "Login OK" : "Login failed"
            }
            .buttonStyle(.borderedProminent)

            Text(status)

            // [M4] If a deep link arrived, render its (untrusted) URL in a WKWebView.
            if let pending = router.pendingURL {
                DeepLinkWebView(urlString: pending).frame(height: 240)
            }
        }
        .padding()
    }
}
