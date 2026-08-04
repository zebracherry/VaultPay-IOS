import SwiftUI
import WebKit

/// [M4 / MASVS-PLATFORM-2] Unvalidated deep-link input rendered in a WKWebView with a JS bridge.
///
/// The app registers the custom scheme `vaultpay://` (see Info.plist). A link such as
///   vaultpay://open?url=https://evil.example/steal
/// flows unvalidated into loadURL, JavaScript is enabled, and a WKScriptMessageHandler bridge is
/// exposed so loaded content can call back into native code.
///
/// SECURE: allow-list the host/scheme, validate the URL, avoid message handlers for untrusted
/// content, and don't expose native capabilities to arbitrary pages.
struct DeepLinkWebView: UIViewRepresentable {
    let urlString: String   // attacker-controlled via the deep link

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.defaultWebpagePreferences.allowsContentJavaScript = true          // WRONG for untrusted
        config.userContentController.add(context.coordinator, name: "VaultPay")  // native bridge exposed
        let webView = WKWebView(frame: .zero, configuration: config)
        if let url = URL(string: urlString) { webView.load(URLRequest(url: url)) }
        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator() }

    final class Coordinator: NSObject, WKScriptMessageHandler {
        // Reachable from any loaded page: window.webkit.messageHandlers.VaultPay.postMessage(...)
        func userContentController(_ controller: WKUserContentController,
                                   didReceive message: WKScriptMessage) {
            // WRONG: would return the real token to whatever page is loaded.
            NSLog("VaultPay bridge invoked with: \(message.body)")
        }
    }
}
