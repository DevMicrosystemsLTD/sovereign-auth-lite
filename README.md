# WordPress Passwordless Authentication (WebAuthn / FIDO2) — Sovereign Auth Lite

🚀 **This is the open-source Lite core. For Enterprise Zero-Knowledge recovery (12-word BIP-39), multi-device management, and break-glass offline access, get [Sovereign Auth Pro](https://dev-net.it/auth).**

Sovereign Auth replaces WordPress's legacy email and password login flow with native biometric authentication (**Face ID, Touch ID, Windows Hello, and Hardware Security Keys**) via the WebAuthn/FIDO2 standard.

No third-party identity providers. No password fields to brute-force. No credential stuffing.

## 🛑 Why remove passwords from WordPress?
Passwords are the weakest link in WordPress security. By completely ripping out the password field and replacing it with public-key cryptography (WebAuthn), you eliminate:
* Brute-force attacks on `wp-login.php`
* Credential stuffing from leaked databases
* Phishing attacks (WebAuthn is origin-bound by design)

## ⚡ Core Features (Lite Version)
* **True Passwordless Login:** Completely bypasses the vulnerable WordPress password field.
* **WebAuthn / FIDO2 Native:** Support for Face ID, Touch ID, Windows Hello, YubiKeys, and other FIDO2 tokens.
* **No External SDKs or SaaS:** Everything is handled natively between the browser API and your server. Zero data sent to 3rd-party identity providers.
* **Strict Security Fallback:** If a user loses their biometric device, they lose access to the account. *There is no insecure email recovery loop in the Lite version.*

## 💎 Upgrade to Sovereign Auth PRO
Engineered for Security Consultants, Agencies, and SysAdmins. The [Pro Version](https://dev-net.it/auth) unlocks the ultimate Zero-Knowledge authentication architecture:

* **12-Word Recovery Phrase (BIP-39):** Drop the insecure email-based recovery. Generate a cryptographic 12-word seed phrase (and QR code) that is strictly one-way hashed via fast lookup + bcrypt.
* **Emergency Break-Glass Access:** A server-side constant in `wp-config.php` that bypasses all hooks to restore native login. It never touches the browser.
* **Self-Service Device Dashboard:** Users manage, add, and revoke multiple biometric devices from the frontend via a simple shortcode.
* **Advanced Rate Limiting:** Per-account and per-IP throttling on every authentication and recovery attempt.

👉 **[Explore the architecture & 90-second demo](https://dev-net.it/auth)**

## ⚙️ Requirements
* **WordPress:** 6.2 or later
* **PHP:** 8.1 or later
* **Strict HTTPS:** A valid SSL certificate is mandatory. The WebAuthn API will refuse to run in a non-secure browsing context.

## 🚀 Installation & Quick Start
1. Download the latest release from this repository.
2. Upload the unzipped folder to your `/wp-content/plugins/` directory.
3. Activate the plugin through the 'Plugins' menu in WordPress.
4. Follow the prompt on your profile page to register your first biometric device.
