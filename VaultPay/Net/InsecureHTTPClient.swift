import Foundation

/// [M5 / MASVS-NETWORK-1, NETWORK-2] Insecure communication — iOS edition.
///
/// A URLSessionDelegate that accepts ANY server trust -> MITM is trivial and no pinning is done.
/// Paired with App Transport Security disabled in Info.plist (NSAllowsArbitraryLoads).
///
/// Detect: MobSF flags the ATS exception and the trust-all delegate. Confirm with Burp/mitmproxy —
/// traffic intercepts with no pinning bypass required.
///
/// SECURE: keep ATS on; implement pinning by comparing the server public key/cert in the delegate;
/// never call .useCredential with an unconditional URLCredential(trust:).
final class InsecureHTTPClient: NSObject, URLSessionDelegate {

    // WRONG: plain HTTP base URL.
    static let baseURL = "http://api.vaultpay.internal/"

    lazy var session: URLSession = {
        URLSession(configuration: .default, delegate: self, delegateQueue: nil)
    }()

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // WRONG: trust whatever the server presents.
        if let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
