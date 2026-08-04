import SwiftUI

@main
struct VaultPayApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                // [M4] Handle the vaultpay:// deep link and pass the attacker-controlled url through.
                .onOpenURL { incoming in
                    guard let comps = URLComponents(url: incoming, resolvingAgainstBaseURL: false),
                          comps.host == "open",
                          let target = comps.queryItems?.first(where: { $0.name == "url" })?.value
                    else { return }
                    DeepLinkRouter.shared.pendingURL = target   // rendered unvalidated in a WKWebView
                }
        }
    }
}

/// Tiny holder so the deep-link target reaches the view layer. Intentionally trusts the input.
final class DeepLinkRouter: ObservableObject {
    static let shared = DeepLinkRouter()
    @Published var pendingURL: String?
}
