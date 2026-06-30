<?php

/**
 * Plugin Name:       Sovereign Auth
 * Plugin URI:        https://dev-net.it
 * Description:       Zero-Knowledge Biometric Gateway — WebAuthn/FIDO2. No email. No password. No traces.
 * Version:           1.4.0
 * Author:            dev-net.it
 * Author URI:        https://dev-net.it
 * License:           Proprietary — Commercial License
 * Requires at least: 6.2
 * Requires PHP:      8.1
 * Text Domain:       sovereign-auth
 *
 * PROPRIETARY SOFTWARE — Unauthorized distribution prohibited.
 * License key validation: https://dev-net.it/verify
 */
defined( 'ABSPATH' ) || exit;

/* ═══════════════════════════════════════════════════════════
   CONSTANTS
═══════════════════════════════════════════════════════════ */
if ( !defined( 'SOVAUTH_VER' ) ) {
    define( 'SOVAUTH_VER', '1.4.1' );
}
define( 'SOVAUTH_PATH', plugin_dir_path( __FILE__ ) );
define( 'SOVAUTH_URL', plugin_dir_url( __FILE__ ) );
define( 'SOVAUTH_CHALLENGE_TTL', 300 );
// 5 min  — WebAuthn challenge expiry
define( 'SOVAUTH_PENDING_TTL', 600 );
// 10 min — pending registration expiry
define( 'SOVAUTH_DB_VER', '1.0' );
/* ═══════════════════════════════════════════════════════════
   PSR-4-STYLE AUTOLOADER
═══════════════════════════════════════════════════════════ */
spl_autoload_register( static function ( string $class ) : void {
    if ( !str_starts_with( $class, 'SovAuth_' ) ) {
        return;
    }
    $slug = strtolower( str_replace( ['SovAuth_', '_'], ['', '-'], $class ) );
    $file = SOVAUTH_PATH . "includes/class-{$slug}.php";
    if ( is_readable( $file ) ) {
        require_once $file;
    }
} );
/* ═══════════════════════════════════════════════════════════
   CORE BOOTSTRAP
═══════════════════════════════════════════════════════════ */
final class Sovereign_Auth {
    private static ?self $instance = null;

    public static function boot() : void {
        if ( null !== self::$instance ) {
            return;
        }
        self::$instance = new self();
    }

    private function __construct() {
        register_activation_hook( __FILE__, [$this, 'on_activate'] );
        register_deactivation_hook( __FILE__, [$this, 'on_deactivate'] );
        add_action( 'plugins_loaded', [$this, 'init'], 0 );
    }

    /* ── Lifecycle ─────────────────────────────────────────── */
    public function on_activate() : void {
        $this->create_tables();
        flush_rewrite_rules();
    }

    public function on_deactivate() : void {
        flush_rewrite_rules();
    }

    private function create_tables() : void {
        global $wpdb;
        $cc = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}sovauth_credentials (\n            id            BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,\n            user_id       BIGINT UNSIGNED  NOT NULL,\n            credential_id VARCHAR(512)     NOT NULL,\n            public_key    MEDIUMTEXT       NOT NULL,\n            sign_count    BIGINT UNSIGNED  NOT NULL DEFAULT 0,\n            device_name   VARCHAR(255)     NOT NULL DEFAULT '',\n            aaguid        CHAR(36)         NOT NULL DEFAULT '',\n            created_at    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,\n            last_used     DATETIME                  DEFAULT NULL,\n            PRIMARY KEY  (id),\n            UNIQUE  KEY  uq_credential_id (credential_id(191)),\n            KEY          k_user_id        (user_id)\n        ) {$cc};";
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );
        update_option( 'sovauth_db_ver', SOVAUTH_DB_VER );
    }

    /* ── Init ──────────────────────────────────────────────── */
    public function init() : void {
        add_action( 'wp_loaded', [$this, 'intercept_admin_logout'] );
        add_action( 'rest_api_init', [new SovAuth_Rest_API(), 'register_routes'] );
        // Admin settings page (License + Status) — always available,
        // independent of emergency-access mode below: an admin needs
        // Plugin Status visibility especially during an emergency.
        ( new SovAuth_Admin() )->register_page();
        // Register frontend dashboard shortcode
        ( new SovAuth_Frontend_Dashboard() )->init();
        /*
         * EMERGENCY ACCESS — server-side break-glass.
         *
         * If SOVAUTH_EMERGENCY_ACCESS is defined `true` in wp-config.php,
         * NONE of the login/register page hooks below are registered.
         * WordPress's native login and registration screens render fully
         * untouched: no injected CSS, no injected JS, no hidden fields,
         * no Sovereign Auth UI at all.
         *
         * Why wp-config.php and not a URL parameter or a JS flag: this
         * constant lives on the server's filesystem, reachable only via
         * FTP/SSH/hosting-panel access — never via anything a browser can
         * send. A client-side toggle would ship in cleartext inside a
         * publicly-loaded JS file on every site running this plugin,
         * which isn't a "secret" at all — anyone could read it via
         * view-source on ANY Sovereign Auth install and re-expose the
         * password form on someone else's site. This constant can't be
         * discovered or flipped by anyone who only has a URL.
         *
         * To use it: add this line to wp-config.php, anywhere before the
         * final require of wp-settings.php, then remove it once normal
         * access is restored:
         *
         *     define( 'SOVAUTH_EMERGENCY_ACCESS', true );
         */
        if ( self::emergency_access_active() ) {
            return;
        }
        // ── Login / register page hooks ──
        add_action( 'login_enqueue_scripts', [$this, 'enqueue_assets'] );
        // HOTFIX UI: inject critical CSS into <head> BEFORE any external
        // stylesheet loads — eliminates the flash where WP's native form
        // fields are momentarily visible before our CSS file arrives.
        add_action( 'login_head', [$this, 'inject_critical_css'] );
        add_action( 'login_form', [$this, 'inject_login_ui'] );
        add_action( 'register_form', [$this, 'inject_register_ui'] );
        add_action( 'login_init', [$this, 'handle_admin_setup_route'] );

    }

    /**
     * Intercept admin logout if no device is registered.
     */
    public function intercept_admin_logout() : void {
        if ( isset( $_GET['action'] ) && $_GET['action'] === 'logout' && is_user_logged_in() ) {
            if ( current_user_can( 'manage_options' ) ) {
                global $wpdb;
                $userId = get_current_user_id();
                $hasDevice = (bool) $wpdb->get_var( $wpdb->prepare( "SELECT 1 FROM {$wpdb->prefix}sovauth_credentials WHERE user_id = %d LIMIT 1", $userId ) );
                if ( !$hasDevice ) {
                    $adminUrl = admin_url( 'options-general.php?page=sovereign-auth' );
                    wp_die( sprintf(
                        '%s<br><br><a href="%s" class="button button-primary" style="display:inline-block;margin-top:10px;">%s</a>',
                        esc_html__( 'WARNING: You must register a biometric device before logging out to avoid losing access to your account.', 'sovereign-auth' ),
                        esc_url( $adminUrl ),
                        esc_html__( 'Register Device Now', 'sovereign-auth' )
                    ), esc_html__( 'Registration Required', 'sovereign-auth' ), [
                        'response' => 403,
                    ] );
                }
            }
        }
    }

    public function handle_admin_setup_route() : void {
        if ( isset( $_GET['action'] ) && $_GET['action'] === 'sovauth_admin_setup' && is_user_logged_in() ) {
            login_header( __( 'Sovereign Auth Setup', 'sovereign-auth' ), '', new \WP_Error() );
            $this->inject_register_ui();
            login_footer();
            exit;
        }
    }

    /**
     * True only if SOVAUTH_EMERGENCY_ACCESS is defined and strictly `true`
     * in wp-config.php. See the docblock in init() for the full rationale.
     */
    public static function emergency_access_active() : bool {
        return false;
    }

    /* ── Critical CSS (HOTFIX UI — double-username prevention) ─ */
    /**
     * Output a tiny inline <style> block in <head> that hides every WP
     * native form element BEFORE the external stylesheet loads.
     *
     * This is the first line of defence against "double username" and any
     * flash of native WP fields. The main stylesheet and the JS init()
     * function act as belt-and-suspenders on top of this.
     */
    public function inject_critical_css() : void {
        ?>
        <style id="sovauth-pre">
            /* ── Sovereign Auth — pre-load WP field suppression ── */
            /* All direct children of both forms, except our root, are gone. */
            #loginform   > *:not(.sovauth-root),
            #registerform > *:not(.sovauth-root) { display: none !important; }

            /* Belt-and-suspenders: individual element IDs / classes that
               may appear in varying positions across WP versions / themes. */
            #user_login, #user_pass, #user_email, #wp-submit,
            label[for="user_login"], label[for="user_pass"], label[for="user_email"],
            .user-pass-wrap, .wp-pwd, .forgetmenot, .login-submit,
            #nav, #backtoblog, #login_error, .message,
            .login .privacy-policy-page-link { display: none !important; }
        </style>
        <?php 
    }

    /* ── Asset enqueue ─────────────────────────────────────── */
    public function enqueue_assets() : void {
        wp_enqueue_script(
            'sovereign-auth',
            SOVAUTH_URL . 'assets/js/sovereign-auth-v2.js',
            [],
            SOVAUTH_VER,
            true
        );
        wp_enqueue_style(
            'sovereign-auth',
            SOVAUTH_URL . 'assets/css/sovereign-auth.css',
            [],
            SOVAUTH_VER
        );
        wp_localize_script( 'sovereign-auth', 'SovAuthConfig', [
            'isAdminSetup' => ( isset( $_GET['action'] ) && $_GET['action'] === 'sovauth_admin_setup' ? 1 : 0 ),
            'currentUser'  => ( is_user_logged_in() ? wp_get_current_user()->user_login : '' ),
            'isPremium'    => false,
            'api'          => esc_url( rest_url( 'sovereign-auth/v1' ) ),
            'nonce'        => wp_create_nonce( 'wp_rest' ),
            'powChallenge' => wp_create_nonce( 'sovauth_pow' ),
            'torMode'      => get_option( 'sovauth_tor_mode' ) === 'yes',
            'rpId'         => wp_parse_url( get_site_url(), PHP_URL_HOST ),
            'rpName'       => esc_attr( get_bloginfo( 'name' ) ),
            'redirect'     => esc_url( admin_url() ),
            'canRegister'  => (bool) get_option( 'users_can_register' ),
            'regUrl'       => esc_url( wp_registration_url() ),
            'i18n'         => [
                'errWebauthnSupport' => __( 'WebAuthn not supported on this device or browser.', 'sovereign-auth' ),
                'errNoCred'          => __( 'No credential returned from authenticator.', 'sovereign-auth' ),
                'errAuthCancel'      => __( 'Authentication cancelled.', 'sovereign-auth' ),
                'tabBio'             => __( '🔐 Biometric', 'sovereign-auth' ),
                'btnSignInBio'       => __( 'Sign in with Biometric', 'sovereign-auth' ),
                'lblBioStatus'       => __( 'Face ID · Touch ID · Windows Hello', 'sovereign-auth' ),
                'statusWaitBio'      => __( 'Waiting for biometric…', 'sovereign-auth' ),
                'statusAuthSuccess'  => __( 'Authenticated ✓', 'sovereign-auth' ),
                'statusAuthFail'     => __( 'Failed — try again', 'sovereign-auth' ),
                'statusVerifying'    => __( 'Verifying…', 'sovereign-auth' ),
                'errEmpty'           => __( 'Please enter a value.', 'sovereign-auth' ),
                'tabReg'             => __( 'Sign Up', 'sovereign-auth' ),
                'tabAuth'            => __( '🔑 Login', 'sovereign-auth' ),
                'lblUser'            => __( 'Choose a Username', 'sovereign-auth' ),
                'lblEmail'           => __( 'Email (Optional)', 'sovereign-auth' ),
                'phUsername'         => __( 'Choose a username', 'sovereign-auth' ),
                'btnContBio'         => __( 'Continue → Biometric Setup', 'sovereign-auth' ),
                'lblNoEmail'         => __( 'No email. No password. Your biometric is the key.', 'sovereign-auth' ),
                'btnRegBio'          => __( '🔐 Register Biometric', 'sovereign-auth' ),
                'lblConfirmBio'      => __( 'Confirm with Face ID, Touch ID, or Windows Hello', 'sovereign-auth' ),
                'lblStep2'           => __( 'Step 2 of 3: Register Biometric', 'sovereign-auth' ),
                'lblBioLocal'        => __( 'Your biometric never leaves this device.', 'sovereign-auth' ),
                'btnContDash'        => __( 'Continue to Dashboard →', 'sovereign-auth' ),
                'errUserLength'      => __( 'Username must be at least 3 characters.', 'sovereign-auth' ),
                'errUserTaken'       => __( 'Username already in use, please choose another.', 'sovereign-auth' ),
                'statusWaitBioConf'  => __( 'Waiting for biometric confirmation…', 'sovereign-auth' ),
                'statusFailed'       => __( 'Failed — ', 'sovereign-auth' ),
                'btnGoRegister'      => __( 'New user? Register', 'sovereign-auth' ),
            ],
        ] );
    }

    /* ── UI injection ──────────────────────────────────────── */
    public function inject_login_ui() : void {
        echo '<div id="sovauth-login-root" class="sovauth-root" aria-label="Sovereign Auth"></div>';
    }

    public function inject_register_ui() : void {
        echo '<div id="sovauth-register-root" class="sovauth-root" aria-label="Sovereign Auth"></div>';
    }

    /* ── Registration helpers ──────────────────────────────── */
    public function strip_registration_errors( \WP_Error $errors ) : \WP_Error {
        if ( !empty( $_POST['sovauth_flow'] ) ) {
            $errors->remove( 'empty_email' );
            $errors->remove( 'invalid_email' );
        }
        return $errors;
    }

    public function whitelist_synthetic_email( bool|string $result, string $email ) : bool|string {
        if ( str_contains( $email, '@noemail.' ) ) {
            return true;
        }
        return $result;
    }

}

Sovereign_Auth::boot();