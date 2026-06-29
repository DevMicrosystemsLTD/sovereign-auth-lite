=== Sovereign Auth ===
Contributors: devnetit, freemius
Plugin Name: Sovereign Auth — Zero-Knowledge Biometric Gateway
Requires at least: 6.2
Tested up to: 6.5
Requires PHP: 8.1
Stable tag: 1.4.0
License: Commercial — see EULA.txt
License URI: https://dev-net.it/eula

Passwordless WordPress login via WebAuthn/FIDO2 biometrics, backed by a 12-word recovery phrase. No email, no password, no traces.

== Description ==

Sovereign Auth replaces WordPress's email + password login with native biometric
authentication (Face ID, Touch ID, Windows Hello, hardware security keys) via the
WebAuthn/FIDO2 standard.

There is no password field anywhere in the registration or login flow. Account
recovery is handled by a single 12-word recovery phrase (drawn from the standard
BIP-39 wordlist), which the user can restore access with either by scanning a QR
code or by typing the words manually.

= Key features =

* WebAuthn/FIDO2 registration and login — Face ID, Touch ID, Windows Hello, and
  hardware security keys
* 12-word recovery phrase, generated server-side with a cryptographically secure
  random number generator
* Recovery via QR code (camera scan or image upload) or manual phrase entry —
  both paths verify identically server-side
* Recovery secrets are never stored in plain text: a fast lookup hash plus a
  bcrypt verification hash, both one-way
* Per-account lockout and per-IP rate limiting on every recovery attempt
* Server-side emergency break-glass access, controlled by a constant in
  wp-config.php — never exposed to the browser
* Minimal admin settings page with license status and live diagnostics
* Self-contained: no third-party identity provider, no phone number, no email
  address required to authenticate
* Self-Service Device Management Dashboard via the `[sovauth_devices]` shortcode

= Requirements =

* WordPress 6.2 or later
* PHP 8.1 or later
* **A valid SSL certificate (HTTPS).** WebAuthn will not run in a non-secure
  browsing context. This is a browser-level restriction, not a plugin setting.
* A modern browser/device with platform biometrics or a connected security key

== Installation ==

1. In your WordPress admin, go to **Plugins → Add New → Upload Plugin**.
2. Choose the `sovereign-auth.zip` file and click **Install Now**.
3. Click **Activate**.
4. Confirm your site is served over HTTPS — biometric registration will fail
   silently in the browser otherwise.
5. To allow new users to register, go to **Settings → General** and check the box for **"Anyone can register"**. The plugin will automatically show a "Register" button on the login screen.
6. Visit your login page to confirm the new interface renders, and the
   registration page to create your first biometric account.
7. You can place the `[sovauth_devices]` shortcode on any page to let users manage (view, add, revoke) their biometric devices.
8. (Optional) Go to **Settings → Sovereign Auth** to enter your license key and
   review plugin status.

Alternative install via FTP/SFTP: upload the unzipped `sovereign-auth` folder to
`/wp-content/plugins/`, then activate it from the Plugins screen as above.

== Frequently Asked Questions ==

= What happens if a user loses their recovery phrase AND their device? =

They lose access to that account. By design, there is no email-based "forgot
password" flow and no password to reset — the 12-word phrase is the only
account-recovery mechanism. Make sure your users understand this before they
register. See EULA.txt for the full liability disclaimer.

= Does this work over plain HTTP? =

No. WebAuthn is a browser API that refuses to run outside a secure context
(HTTPS), except on `localhost` for local development. This is enforced by the
browser, not by this plugin.

= Can I use this on a non-WordPress site? =

Not with this build. Every part of the plugin is wired directly into
WordPress's user system, session handling, and admin hooks.

= What if the site administrator gets locked out? =

Define `SOVAUTH_EMERGENCY_ACCESS` as `true` in `wp-config.php`. While that
constant is set, none of the plugin's login/registration hooks run at all, and
WordPress's native username/password login renders exactly as it would without
this plugin installed. Remove the constant once normal access is restored.

= Does deleting the plugin remove its data? =

Yes. Deleting (not just deactivating) the plugin from the Plugins screen runs
its uninstaller, which drops the credentials table and removes every related
usermeta key, transient, and option this plugin created.

== Changelog ==

= 1.4.0 =
* Added: Full English internationalization (i18n) across all admin and frontend interfaces.
* Added: Freemius SDK integration — real, server-verified license activation replaces the old local-format-only license check.
* Added: `[sovauth_devices]` shortcode for a frontend Self-Service Device Management Dashboard.
* Added: "Register" button injected automatically on the login screen when WordPress registration is enabled.
* Added: Admin Logout Protection — administrators are now securely prevented from logging out if they have not registered a biometric device, preventing accidental lockouts.
* Added: Secure Recovery Phrase generation for existing admins/users when they add their first device via the backend dashboard.
* Added: In-plugin Guide & Recommendations section on the settings page, detailing how to use the plugin and alerting against incompatible login-flow plugins.
* Removed: custom "License Key" admin field (Freemius provides its own Account/License screen automatically).
* Fixed: CSS Grid layout overflow in the 12-word recovery phrase display.

= 1.3.0 =
* Added: minimal admin settings page (Settings → Sovereign Auth) with license
  key field and live plugin-status diagnostics
* Added: uninstall routine — full cleanup of the credentials table, all
  related usermeta, transients, and options on plugin deletion

= 1.2.0 =
* Added: server-side emergency break-glass access via a wp-config.php constant

= 1.1.0 =
* Replaced the original QR-token + 6-digit PIN recovery system with a single
  12-word recovery phrase, presented as both readable text and a QR code
* Recovery accepts either a scanned/uploaded QR code or manual phrase entry
* Removed the PIN entirely from both registration and recovery

= 1.0.1 =
* Bug fixes: resident key enforcement, orphan account prevention, CBOR bounds
  checking, buffer-to-base64url conversion on large credential payloads

= 1.0.0 =
* Initial release: WebAuthn/FIDO2 registration and login, QR + PIN backup
  authentication

== Disclaimer ==

This software is provided "as is", without warranty of any kind. See EULA.txt
for the full license terms, including the limitation of liability for lost
account access. Use of this plugin constitutes acceptance of those terms.
