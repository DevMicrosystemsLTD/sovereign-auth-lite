<?php
/**
 * Sovereign Auth — Frontend Dashboard Shortcode
 */

defined( 'ABSPATH' ) || exit;

final class SovAuth_Frontend_Dashboard {

    public function init(): void {
        add_shortcode( 'sovauth_devices', [ $this, 'render_shortcode' ] );
    }

    public function render_shortcode(): string {
        if ( ! is_user_logged_in() ) {
            return '<p>' . esc_html__( 'You must be logged in to manage your devices.', 'sovereign-auth' ) . '</p>';
        }

        wp_enqueue_style( 'sovereign-auth-dashboard', SOVAUTH_URL . 'assets/css/sovereign-auth-dashboard.css', [], SOVAUTH_VER );
        wp_enqueue_script( 'qrcodejs', 'https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js', [], '1.0.0', true );
        wp_enqueue_script( 'sovereign-auth-dashboard', SOVAUTH_URL . 'assets/js/sovereign-auth-dashboard.js', [ 'qrcodejs' ], SOVAUTH_VER, true );
        
        wp_localize_script( 'sovereign-auth-dashboard', 'SovAuthDash', [
            'isPremium'    => function_exists( 'sav_fs' ) && sav_fs()->can_use_premium_code(),
            'api'          => esc_url( rest_url( 'sovereign-auth/v1' ) ),
            'nonce'        => wp_create_nonce( 'wp_rest' ),
            'powChallenge' => wp_create_nonce( 'sovauth_pow' ),
            'torMode'      => get_option( 'sovauth_tor_mode' ) === 'yes',
            'i18n'         => [
                'confirmRevoke' => __( 'Are you sure you want to revoke access to this device?', 'sovereign-auth' ),
                'errRevoke'     => __( 'Unable to remove the device.', 'sovereign-auth' ),
                'addDevice'     => __( '+ Register Device', 'sovereign-auth' ),
                'waitBio'       => __( 'Waiting for biometric...', 'sovereign-auth' ),
                'successAdd'    => __( 'Device successfully added.', 'sovereign-auth' ),
                'neverUsed'     => __( 'Never used', 'sovereign-auth' ),
                'revoke'        => __( 'Revoke', 'sovereign-auth' ),
                'unknownDevice' => __( 'Unknown Device', 'sovereign-auth' ),
                'loading'       => __( 'Loading devices...', 'sovereign-auth' ),
                'errWebauthnSupport' => __( 'WebAuthn is not supported on this browser or device.', 'sovereign-auth' ),
                'errNoCred'          => __( 'No credential returned from the authenticator.', 'sovereign-auth' ),
                'saveRecovery'       => __( 'Please save your 12-word recovery phrase and QR code immediately. This is the ONLY way to recover your account if you lose this device.', 'sovereign-auth' ),
                'btnDlQR'            => __( '⬇ Download QR', 'sovereign-auth' ),
                'btnCopyWords'       => __( '⧉ Copy Words', 'sovereign-auth' ),
                'lblSavedQR'         => __( 'I have saved my recovery info', 'sovereign-auth' ),
            ]
        ] );

        ob_start();
        ?>
        <div id="sovauth-dashboard-root" class="sovauth-dash-root">
            <div class="sov-dash-header">
                <h3><?php esc_html_e( 'Biometric Devices', 'sovereign-auth' ); ?></h3>
                <button type="button" id="sov-dash-add-btn" class="sov-btn sov-btn--primary">
                    <?php esc_html_e( '+ Add Device', 'sovereign-auth' ); ?>
                </button>
            </div>
            <div id="sov-dash-error" class="sov-error sov-hidden"></div>
            <div id="sov-dash-success" class="sov-status sov-status--success sov-hidden"></div>
            <div class="sov-dash-list" id="sov-dash-list">
                <p class="sov-status sov-status--info"><?php esc_html_e( 'Loading devices...', 'sovereign-auth' ); ?></p>
            </div>
        </div>
        <?php
        return ob_get_clean();
    }
}
