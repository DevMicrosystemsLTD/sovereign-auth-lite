<?php
/**
 * Sovereign Auth — Admin Settings Page
 *
 * Adds a single, low-profile page under Settings → Sovereign Auth with:
 *
 *   1. Security & Anonymity — Tor/onion mode toggle.
 *
 *   2. Plugin Status — real, useful diagnostics: PHP/HTTPS prerequisites,
 *      how many users have biometrics registered, how many have a
 *      recovery phrase configured, current version, and real license
 *      status (via the Freemius SDK — see sovereign-auth.php).
 *
 * NOTE: the local "License Key" field that used to live on this page
 * (format-check only, no real verification) has been removed. License
 * activation/account management is now handled by Freemius's own
 * auto-generated screen, reachable from this same admin menu once the
 * SDK is configured. Don't re-add a custom license field here — it
 * would just create a second, conflicting source of truth.
 */

defined( 'ABSPATH' ) || exit;

final class SovAuth_Admin {

    private const OPT_TOR_MODE       = 'sovauth_tor_mode';
    private const NONCE_ACTION       = 'sovauth_admin_save';

    public function register_page(): void {
        add_action( 'admin_menu', [ $this, 'add_menu' ] );
        add_action( 'admin_notices', [ $this, 'prompt_registration' ] );
    }

    public function prompt_registration(): void {
        global $wpdb;
        $userId = get_current_user_id();
        if ( ! $userId ) return;
        
        $hasDevice = (bool) $wpdb->get_var( $wpdb->prepare(
            "SELECT 1 FROM {$wpdb->prefix}sovauth_credentials WHERE user_id = %d LIMIT 1",
            $userId
        ) );

        if ( $hasDevice ) return;

        // Render the notice without JS
        $setupUrl = esc_url( wp_login_url() . '?action=sovauth_admin_setup' );
        ?>
        <div class="notice notice-error" style="padding: 15px;">
            <h3 style="margin-top: 0;"><?php esc_html_e( 'Sovereign Auth — Action Required!', 'sovereign-auth' ); ?></h3>
            <p style="font-size: 14px;"><strong><?php esc_html_e( 'WARNING:', 'sovereign-auth' ); ?></strong> <?php esc_html_e( 'You have not registered a biometric device for your account yet. If you log out without registering one, you will be locked out of the site!', 'sovereign-auth' ); ?></p>
            <p style="font-size: 14px;"><?php esc_html_e( 'Register your face or fingerprint (WebAuthn/FIDO2) now before logging out.', 'sovereign-auth' ); ?></p>
            <a href="<?php echo $setupUrl; ?>" class="button button-primary button-hero" style="margin-top:10px;">
                <?php esc_html_e( 'Register Device Now', 'sovereign-auth' ); ?>
            </a>
        </div>
        <?php
    }

    public function add_menu(): void {
        add_options_page(
            'Sovereign Auth',
            'Sovereign Auth',
            'manage_options',
            'sovereign-auth',
            [ $this, 'render_page' ]
        );
    }

    public function render_page(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have permission to access this page.', 'sovereign-auth' ) );
        }

        $notice = '';
        if ( ! empty( $_POST['sovauth_action'] ) && check_admin_referer( self::NONCE_ACTION ) ) {
            $notice = $this->handle_post();
        }

        if ( ! empty( $_GET['sovauth_revoke'] ) ) {
            $revokeId = (int) $_GET['sovauth_revoke'];
            if ( check_admin_referer( 'sovauth_revoke_' . $revokeId ) ) {
                global $wpdb;
                $wpdb->delete( "{$wpdb->prefix}sovauth_credentials", [ 'id' => $revokeId ] );
                $notice = "Device revoked successfully.";
            }
        }

        $torMode = (string) get_option( self::OPT_TOR_MODE, 'no' );
        $stats   = $this->collectStatus();

        echo '<div class="wrap"><h1>Sovereign Auth</h1>';

        if ( $notice ) {
            echo '<div class="notice notice-success"><p>' . esc_html( $notice ) . '</p></div>';
        }

        echo '<h2 class="title">Security & Anonymity</h2>';
        echo '<form method="post">';
        wp_nonce_field( self::NONCE_ACTION );
        echo '<input type="hidden" name="sovauth_action" value="save_settings">';
        echo '<table class="form-table"><tbody><tr><th scope="row">Tor / Onion Mode</th><td>';
        echo '<label><input type="checkbox" name="tor_mode" value="1" ' . checked( $torMode, 'yes', false ) . '> Enable Proof of Work & Disable IP Tracking</label>';
        echo '<p class="description">Required for .onion sites. Replaces IP-based rate limiting with a JavaScript cryptographic puzzle (Proof of Work) to block brute-force attacks without banning the Tor proxy IP.</p>';
        echo '</td></tr></tbody></table>';
        
        submit_button( 'Save Settings' );
        echo '</form>';

        /* ── Plugin Status ── */
        echo '<h2 class="title">Plugin Status</h2>';
        echo '<table class="widefat striped" style="max-width:640px;"><tbody>';
        $licensed = function_exists( 'sav_fs' ) && sav_fs()->can_use_premium_code();
        $this->statusRow( 'License (Freemius)', $licensed ? 'Active' : 'Inactive / Trial', $licensed );
        $this->statusRow( 'Version', SOVAUTH_VER, true );
        $this->statusRow( 'PHP version', PHP_VERSION, version_compare( PHP_VERSION, '8.1', '>=' ) );
        $this->statusRow( 'HTTPS (required for WebAuthn)', is_ssl() ? 'Enabled' : 'Not detected', is_ssl() );
        $this->statusRow( 'Users with biometric registered', (string) $stats['biometric_users'], true );
        $this->statusRow( 'Users with recovery phrase configured', (string) $stats['recovery_users'], true );
        $this->statusRow( 'Emergency access (wp-config.php)', Sovereign_Auth::emergency_access_active() ? 'ACTIVE — Sovereign Auth UI is disabled' : 'Off', ! Sovereign_Auth::emergency_access_active() );
        echo '</tbody></table>';

        /* ── Manage Credentials ── */
        global $wpdb;
        $userId = get_current_user_id();
        $hasDevice = (bool) $wpdb->get_var( $wpdb->prepare(
            "SELECT 1 FROM {$wpdb->prefix}sovauth_credentials WHERE user_id = %d LIMIT 1",
            $userId
        ) );
        $setupUrl = esc_url( wp_login_url() . '?action=sovauth_admin_setup' );

        ?>
        <h2 class="title" style="margin-top: 30px;">Personal Biometric Devices</h2>
        <div id="sovauth-dashboard-root" class="sovauth-dash-root" style="margin-top: 15px; border: 1px solid #ccd0d4; padding: 15px; background: #fff; max-width: 800px;">
            <div class="sov-dash-header" style="display:flex; justify-content:space-between; align-items:center;">
                <h4 style="margin:0;"><?php esc_html_e( 'Your Devices', 'sovereign-auth' ); ?></h4>
                <?php if ( ! $hasDevice ) : ?>
                    <a href="<?php echo $setupUrl; ?>" class="sov-btn sov-btn--primary button button-primary button-hero">
                        <?php esc_html_e( '+ Register Now', 'sovereign-auth' ); ?>
                    </a>
                <?php else : ?>
                    <button type="button" id="sov-dash-add-btn" class="sov-btn sov-btn--primary button button-primary">
                        <?php esc_html_e( '+ Add Device', 'sovereign-auth' ); ?>
                    </button>
                <?php endif; ?>
            </div>
            <div id="sov-dash-error" class="sov-error sov-hidden" style="color: #d63638; margin-top:10px; font-weight: bold;"></div>
            <div id="sov-dash-success" class="sov-status sov-status--success sov-hidden" style="color: #00a32a; margin-top:10px; font-weight: bold;"></div>
            <div class="sov-dash-list" id="sov-dash-list" style="margin-top:15px;">
                <p class="sov-status sov-status--info"><?php esc_html_e( 'Loading devices...', 'sovereign-auth' ); ?></p>
            </div>
        </div>
        <?php

        wp_enqueue_style( 'sovereign-auth-dashboard', SOVAUTH_URL . 'assets/css/sovereign-auth-dashboard.css', [], SOVAUTH_VER );
        wp_enqueue_script( 'qrcodejs', 'https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js', [], '1.0.0', true );
        wp_enqueue_script( 'sovereign-auth-dashboard', SOVAUTH_URL . 'assets/js/sovereign-auth-dashboard.js', [ 'qrcodejs' ], SOVAUTH_VER, true );
        
        wp_localize_script( 'sovereign-auth-dashboard', 'SovAuthDash', [
            'isPremium'    => function_exists( 'sav_fs' ) && sav_fs()->can_use_premium_code(),
            'api'          => esc_url( rest_url( 'sovereign-auth/v1' ) ),
            'nonce'        => wp_create_nonce( 'wp_rest' ),
            'powChallenge' => wp_create_nonce( 'sovauth_pow' ),
            'torMode'      => (string) get_option( self::OPT_TOR_MODE, 'no' ) === 'yes',
            'i18n'         => [
                'confirmRevoke' => __( 'Are you sure you want to revoke access to this device?', 'sovereign-auth' ),
                'errRevoke'     => __( 'Unable to remove the device.', 'sovereign-auth' ),
                'addDevice'     => __( '+ Add Device', 'sovereign-auth' ),
                'waitBio'       => __( 'Waiting for biometric...', 'sovereign-auth' ),
                'successAdd'    => __( 'Device successfully added.', 'sovereign-auth' ),
                'neverUsed'     => __( 'Never used', 'sovereign-auth' ),
                'revoke'        => __( 'Revoke', 'sovereign-auth' ),
                'unknownDevice' => __( 'Unknown Device', 'sovereign-auth' ),
                'loading'       => __( 'Loading devices...', 'sovereign-auth' ),
                'errWebauthnSupport' => __( 'WebAuthn is not supported on this browser or device.', 'sovereign-auth' ),
                'errNoCred'          => __( 'No credential returned from the authenticator.', 'sovereign-auth' ),
            ]
        ] );

        /* ── Guide & Recommendations ── */
        $this->renderGuide();

        echo '</div>';
    }


    private function handle_post(): string {
        $action = sanitize_text_field( wp_unslash( $_POST['sovauth_action'] ?? '' ) );

        if ( $action === 'save_settings' ) {
            $tor = ! empty( $_POST['tor_mode'] ) ? 'yes' : 'no';
            update_option( self::OPT_TOR_MODE, $tor );
            return 'Settings saved.';
        }

        return '';
    }

    private function collectStatus(): array {
        global $wpdb;

        $biometricUsers = (int) $wpdb->get_var(
            "SELECT COUNT(DISTINCT user_id) FROM {$wpdb->prefix}sovauth_credentials"
        );

        $recoveryUsers = (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = %s",
            '_sovauth_recovery_lookup_hash'
        ) );

        return [
            'biometric_users' => $biometricUsers,
            'recovery_users'  => $recoveryUsers,
        ];
    }

    private function statusRow( string $label, string $value, bool $ok ): void {
        $dot = $ok ? '🟢' : '🟠';
        printf(
            '<tr><td>%s</td><td>%s %s</td></tr>',
            esc_html( $label ),
            $dot,
            esc_html( $value )
        );
    }

    private function renderGuide(): void {
        ?>
        <h2 class="title" style="margin-top: 40px;">Guide &amp; Recommendations</h2>
        <div style="background: #fff; border: 1px solid #ccd0d4; padding: 20px; max-width: 800px; border-radius: 4px;">
            <p><strong>Welcome to Sovereign Auth!</strong></p>
            <p>This plugin replaces traditional passwords with high-security WebAuthn/FIDO2 biometrics (such as Touch ID, Face ID, or Windows Hello), drastically improving security and user experience.</p>
            
            <h3 style="margin-bottom: 5px;">How it Works</h3>
            <ul style="list-style: disc; padding-left: 20px; margin-top: 5px;">
                <li><strong>No Passwords:</strong> Users log in directly using their device's built-in biometric sensor.</li>
                <li><strong>Device Bound:</strong> A biometric credential is mathematically tied to the specific device used to register it.</li>
                <li><strong>Adding Devices:</strong> Users can (and should) add multiple devices (e.g., a phone and a laptop) for redundancy.</li>
            </ul>

            <h3 style="margin-bottom: 5px;">Best Practices &amp; Recovery</h3>
            <ul style="list-style: disc; padding-left: 20px; margin-top: 5px;">
                <li><strong>Save the Recovery Phrase:</strong> If a user loses all their registered devices, the only way to regain access is through the 12-word recovery phrase generated during their first device registration. Make sure you have saved yours!</li>
                <li><strong>Administrator Lockout Protection:</strong> For security, administrators are prevented from logging out until they have successfully registered at least one biometric device.</li>
                <li><strong>Tor / Onion Mode:</strong> If your site operates over the Tor network, enable Tor Mode. This switches the anti-brute-force mechanism from IP-based rate limiting to a cryptographic Proof of Work puzzle, preventing malicious traffic without banning legitimate Tor exit nodes.</li>
            </ul>

            <h3 style="margin-bottom: 5px; color: #d63638;">Important Warnings &amp; Conflicts</h3>
            <ul style="list-style: disc; padding-left: 20px; margin-top: 5px;">
                <li><strong>Incompatible Plugins:</strong> Sovereign Auth radically alters and replaces the default WordPress login screen. It is <strong>NOT</strong> compatible with other plugins that modify the login flow. You must disable any Two-Factor Authentication (2FA) plugins, Custom Login Page builders, or CAPTCHA plugins on the login form, otherwise you will experience severe conflicts and lockouts.</li>
            </ul>
        </div>
        <?php
    }
}
