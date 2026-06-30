# Sovereign Auth Lite — Passwordless WordPress Login

🚀 **This is the Lite core. For Enterprise Zero-Knowledge recovery (12-word BIP-39), multi-device management, and break-glass offline access, get Sovereign Auth Pro at [dev-net.it/auth](https://dev-net.it/auth)**

Sovereign Auth replaces WordPress's legacy email + password login with native biometric authentication (Face ID, Touch ID, Windows Hello, hardware security keys) via the WebAuthn/FIDO2 standard.

No third-party identity providers. No password fields. No traces.

## ⚡ Core Features (Lite Version)
* **WebAuthn/FIDO2 Native Registration & Login:** Support for Face ID, Touch ID, Windows Hello, and hardware security keys.
* **True Passwordless:** Completely bypasses the vulnerable WordPress password field.
* **No External SDKs:** Everything is handled natively between the browser API and your server. Zero data sent to 3rd-party SaaS providers.
* **No Fallback:** If you lose your biometric device, you lose access to the account. There is no email recovery in the Lite version.
## 💎 Upgrade to Sovereign Auth PRO
Engineered for Security Consultants, Agencies, and Privacy Professionals. The [Pro Version](https://dev-net.it/auth) unlocks the ultimate Zero-Knowledge architecture:

* **12-Word Recovery Phrase (BIP-39):** Drop the insecure email-based recovery. Generate a cryptographic 12-word seed phrase (and QR code) that is strictly one-way hashed.
* **Emergency Break-Glass Access:** A server-side constant in `wp-config.php` that bypasses all hooks to restore native login. Never exposed to the web.
* **Self-Service Device Dashboard:** Users can manage, add, and revoke multiple biometric devices from the frontend via shortcode.
* **Advanced Rate Limiting:** Per-account and per-IP throttling on every recovery attempt.

👉 **[Get Sovereign Auth Pro](https://dev-net.it/auth)**

## ⚙️ Requirements
* WordPress 6.2 or later
* PHP 8.1 or later
* **A valid SSL certificate (HTTPS).** WebAuthn will not run in a non-secure browsing context.
