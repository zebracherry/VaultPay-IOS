# VaultPay-iOS 💳🔓

**A modern, intentionally vulnerable iOS app for learning mobile penetration testing.**

The iOS counterpart to [VaultPay (Android)](https://github.com/zebracherry/VaultPay). A mock
fintech wallet built with **Swift + SwiftUI**, deliberately seeded with every risk in the
**OWASP Mobile Top 10 (2024)**, each cross-mapped to an **OWASP MASVS v2.1.0** control — using
iOS-native insecure primitives (Keychain, `UserDefaults`, CommonCrypto/CryptoKit, `URLSession`,
`WKWebView`) rather than Android equivalents. Find the bugs, then read the `SECURE:` notes to learn
the fix.

> ## ⚠️ Intentionally vulnerable — read before you build
> Insecure **by design**. Build and run **only** on the iOS Simulator or a dedicated, disposable
> test device. **Never** install on a device you use, connect it to real accounts or networks, or
> submit it anywhere. You are responsible for keeping it contained.

> ## 🖥️ macOS required
> iOS apps build only on macOS with **Xcode** (26.x line at time of writing; iOS 16 deployment
> target). There is no Windows/Linux path to compile or run this. If you don't have a Mac, the
> source is still useful to read, but you'll need macOS (or a cloud Mac) to build and test.

---

## Why a separate iOS app?

Same OWASP mapping, **different platform mechanics** — which is exactly the point. The value is in
seeing how each risk manifests natively on iOS:

| Concept | Android (VaultPay) | iOS (this repo) |
|---|---|---|
| Insecure storage | SharedPreferences, external storage | `UserDefaults` plist, Keychain misuse, `Documents/` |
| Crypto | `javax.crypto` (AES-ECB, MD5) | CommonCrypto / CryptoKit (AES-ECB, `CC_MD5`) |
| Transport | `usesCleartextTraffic`, TrustManager | ATS `NSAllowsArbitraryLoads`, trust-all `URLSessionDelegate` |
| WebView | `WebView` + `addJavascriptInterface` | `WKWebView` + `WKScriptMessageHandler` |
| Deep link | exported intent-filter | `CFBundleURLSchemes` + `onOpenURL` |
| Binary/resilience | root detection, R8/ProGuard | jailbreak detection, symbol stripping |

Hand someone both repos and you can show "here's M9 on Android, here's M9 on iOS" — the
cross-platform muscle a purple team wants.

---

## What's inside — OWASP Mobile Top 10 (2024) coverage

| Risk | Where it lives | MASVS v2.1.0 | How to test (iOS) |
|---|---|---|---|
| **M1 Improper Credential Usage** | `AuthManager` admin creds; token in `InsecureStorage` / Keychain | STORAGE-1, CRYPTO-1 | class-dump / `strings`, MobSF secret scan |
| **M2 Inadequate Supply Chain Security** | Outdated pinned SPM dependency slot in `project.yml` | CODE-2 | MobSF dep scan, OWASP dependency-check |
| **M3 Insecure Authentication/Authorization** | `AuthManager.verifyJWT` (alg:none), `isAdmin` (client claim) | AUTH-1, AUTH-2 | Forge `{"alg":"none"}` JWT; Frida hook; Burp on login |
| **M4 Insufficient Input/Output Validation** | `VaultDatabase.loginRaw` (SQLi); `DeepLinkWebView` (`WKWebView` + bridge) | CODE-4, PLATFORM-2 | `' OR '1'='1' --`; open `vaultpay://open?url=…` |
| **M5 Insecure Communication** | `InsecureHTTPClient` (trust-all delegate); ATS disabled in `Info.plist` | NETWORK-1, NETWORK-2 | Burp / mitmproxy — no pinning to bypass |
| **M6 Inadequate Privacy Controls** | `PrivacyLogger` (PII/PAN/token to os_log, IDFV to analytics); broad usage strings | PRIVACY-1..4 | Console.app / unified log; MobSF plist review |
| **M7 Insufficient Binary Protections** | No obfuscation, symbols kept, no jailbreak/anti-tamper checks | RESILIENCE-1..4 | class-dump readability; Frida attaches freely |
| **M8 Security Misconfiguration** | Unvalidated URL scheme; `UIFileSharingEnabled`; debug config | PLATFORM-1, STORAGE-2 | MobSF plist analysis; Files-app container access |
| **M9 Insecure Data Storage** | `UserDefaults` PIN/token/PAN; Keychain `kSecAttrAccessibleAlways`; `Documents/` PAN export | STORAGE-1, STORAGE-2 | container pull; Keychain-Dumper |
| **M10 Insufficient Cryptography** | `InsecureCrypto` (AES-ECB, hardcoded key + static IV, MD5, Base64-as-crypto) | CRYPTO-1, CRYPTO-2 | Hopper/class-dump; Frida hook `CCCrypt` / `CC_MD5` |

---

## Project layout

```
VaultPay-iOS/
├── project.yml              # XcodeGen spec (M2 supply-chain slot, M7 build settings)
├── README.md · LICENSE · .gitignore
└── VaultPay/
    ├── Info.plist           # M5 (ATS), M6 (usage strings), M8 (URL scheme, file sharing)
    ├── VaultPayApp.swift     # app entry + M4 deep-link routing
    ├── ContentView.swift     # minimal SwiftUI login wiring the vulns together
    ├── Auth/AuthManager.swift        # M3, M1
    ├── Crypto/InsecureCrypto.swift   # M10
    ├── Storage/InsecureStorage.swift # M9, M1
    ├── Storage/VaultDatabase.swift   # M4 (SQLi) + safe reference
    ├── Net/InsecureHTTPClient.swift  # M5
    ├── Web/DeepLinkWebView.swift     # M4
    └── Privacy/PrivacyLogger.swift   # M6
```

---

## Build (macOS)

The repo ships a **XcodeGen spec** rather than a committed `.xcodeproj`, so the project file is
generated cleanly on your machine:

```bash
brew install xcodegen        # once
git clone https://github.com/zebracherry/VaultPay-iOS.git
cd VaultPay-iOS
xcodegen generate            # produces VaultPay.xcodeproj from project.yml
open VaultPay.xcodeproj       # build & run on the iOS Simulator
```

No Mac/XcodeGen? You can instead create a new SwiftUI app in Xcode (bundle id `nz.co.vaultpay`),
delete its default files, drag the `VaultPay/` sources in, and set the `Info.plist` — the
`project.yml` documents every setting to replicate.

## Suggested learning path (iOS)

1. **Static first.** Run the built `.app`/`.ipa` through **MobSF**; confirm hits in **class-dump**
   / **Hopper**. Expect secrets (M1), ATS disabled (M5), the URL scheme + file sharing (M8), broad
   usage strings (M6), and no binary protections (M7).
2. **Storage.** On a jailbroken device (or Simulator container on disk), inspect the app group:
   `Library/Preferences/*.plist` for the PIN/token/PAN (M9, M1), `Documents/vaultpay_card.txt` for
   the PAN export, and **Keychain-Dumper** for the mis-scoped Keychain item.
3. **Network.** Proxy through Burp/mitmproxy — traffic intercepts with no pinning to defeat (M5).
4. **Dynamic.** Attach **Frida/Objection**: hook `CCCrypt`/`CC_MD5` to observe the broken crypto
   (M10), and `AuthManager.verifyJWT` to watch the alg:none bypass (M3).
5. **Attack surface.** Trigger the deep link — `xcrun simctl openurl booted
   "vaultpay://open?url=https://example.com"` — to drive the `WKWebView` bridge (M4).
6. **Report.** Cite the **MASVS** control ID and pull the matching **MASTG** test case
   (`MASTG-TEST-…`) as the evidence method — same structure as a WSTG-based web report.

## Standards reference

- **OWASP Mobile Top 10 (2024)** — the risk list this app is built against.
- **OWASP MASVS v2.1.0** — 8 categories, 24 controls (the *what*). L1/L2/R levels are retired; risk
  tiers now live in MASTG as MAS-L1 / MAS-L2 / MAS-R profiles.
- **OWASP MASTG** — per-requirement iOS test cases (the *how*).

## License

[MIT](LICENSE), with an additional intentionally-vulnerable-software notice. Education and
authorised testing only.
