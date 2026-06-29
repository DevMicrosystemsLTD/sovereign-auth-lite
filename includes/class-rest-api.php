<?php
/**
 * Sovereign Auth — REST API  (v1.0.1)
 *
 * FIXES:
 *  Bug #3 — Orphan accounts: /user/create now only stores pending data in a transient.
 *            wp_insert_user() is called ONLY after successful WebAuthn attestation
 *            inside webauthn_reg_verify(). No successful WebAuthn = no WP user.
 *
 *  Bug #4 — wp_delete_user() unavailability: admin/user.php is required explicitly
 *            before any call to that function.
 *
 *  Bug #5 — Add-device for logged-in users: webauthn_reg_options() and
 *            webauthn_reg_verify() now support BOTH flows:
 *            a) pending_token present → new-user registration
 *            b) no pending_token + is_user_logged_in() → add-device
 *
 *  Bug #6 — wp_die() in rate limiter and resolvePendingData(): replaced with
 *            SovAuth_API_Exception + per-endpoint try/catch, all returning
 *            proper WP_REST_Response objects with correct HTTP status codes.
 *
 *  ARCH CHANGE — "Ultimate Recovery Suite": the PIN is gone entirely.
 *            /user/create no longer collects or hashes a PIN.
 *            webauthn_reg_verify() now calls SovAuth_Backup_Auth::setup()
 *            (instead of setupWithHashedPin()) and returns a 12-word
 *            `recovery_phrase` array instead of `backup_token`. The client
 *            renders that phrase as both text and a QR code (the QR simply
 *            encodes the phrase string — there is no separate token).
 *            backup_verify() now accepts `phrase` (array of 12 words, or a
 *            single string) instead of `token` + `pin`.
 */

defined( 'ABSPATH' ) || exit;

/* ── Typed exception so REST handlers can produce clean responses ── */
final class SovAuth_API_Exception extends \RuntimeException {
    public function __construct(
        public readonly string $apiCode,
        string                 $message,
        public readonly int    $status = 400
    ) {
        parent::__construct( $message );
    }
}

/* ══════════════════════════════════════════════════════════════════
   REST CONTROLLER
══════════════════════════════════════════════════════════════════ */
final class SovAuth_Rest_API {

    private const NS = 'sovereign-auth/v1';

    /* ── Route registration ─────────────────────────────────── */

    public function register_routes(): void {
        $pub = [ 'permission_callback' => '__return_true' ];
        $aut = [ 'permission_callback' => fn() => is_user_logged_in() ];

        register_rest_route( self::NS, '/user/create',               [ 'methods' => 'POST',   'callback' => [ $this, 'user_create'           ], ...$pub ] );
        register_rest_route( self::NS, '/webauthn/register/options', [ 'methods' => 'POST',   'callback' => [ $this, 'webauthn_reg_options'   ], ...$pub ] );
        register_rest_route( self::NS, '/webauthn/register/verify',  [ 'methods' => 'POST',   'callback' => [ $this, 'webauthn_reg_verify'    ], ...$pub ] );
        register_rest_route( self::NS, '/webauthn/auth/options',     [ 'methods' => 'POST',   'callback' => [ $this, 'webauthn_auth_options'  ], ...$pub ] );
        register_rest_route( self::NS, '/webauthn/auth/verify',      [ 'methods' => 'POST',   'callback' => [ $this, 'webauthn_auth_verify'   ], ...$pub ] );
        register_rest_route( self::NS, '/backup/verify',             [ 'methods' => 'POST',   'callback' => [ $this, 'backup_verify'          ], ...$pub ] );
        register_rest_route( self::NS, '/credentials',               [ 'methods' => 'GET',    'callback' => [ $this, 'credentials_list'       ], ...$aut ] );
        register_rest_route( self::NS, '/credentials/(?P<id>\d+)',   [ 'methods' => 'DELETE', 'callback' => [ $this, 'credentials_delete'     ], ...$aut ] );
    }

    /* ══════════════════════════════════════════════════════════
       POST /user/create
       FIX #3: NO wp_insert_user here — only store pending data.
    ══════════════════════════════════════════════════════════ */

    public function user_create( \WP_REST_Request $req ): \WP_REST_Response {
        try {
            $this->enforcePoW( $req );
            $this->ipRateLimit( 'user_create', 10, 3600 );

            $username = sanitize_user( (string) $req->get_param( 'username' ), true );
            $email    = sanitize_email( (string) $req->get_param( 'email' ) );

            if ( empty( $username ) || strlen( $username ) < 3 ) {
                throw new SovAuth_API_Exception( 'invalid_username', 'Username must be at least 3 characters.', 400 );
            }
            if ( username_exists( $username ) ) {
                throw new SovAuth_API_Exception( 'username_exists', 'Username already taken.', 409 );
            }

            $isPremium = function_exists( 'sav_fs' ) && sav_fs()->can_use_premium_code();
            if ( ! $isPremium ) {
                if ( ! is_email( $email ) ) {
                    throw new SovAuth_API_Exception( 'invalid_email', __( 'A valid email address is required in the free version.', 'sovereign-auth' ), 400 );
                }
                if ( email_exists( $email ) ) {
                    throw new SovAuth_API_Exception( 'email_exists', __( 'Email address already in use.', 'sovereign-auth' ), 409 );
                }
            }

            // No PIN to collect anymore. The recovery phrase is generated
            // entirely server-side, AFTER biometric registration succeeds
            // (see webauthn_reg_verify() below) — the pending transient
            // only needs to remember the chosen username (and email).
            $pendingToken = bin2hex( random_bytes( 32 ) );
            $pendingHash  = hash( 'sha256', $pendingToken );

            set_transient( 'sovauth_pending_' . $pendingHash, [
                'username' => $username,
                'email'    => $email,
            ], SOVAUTH_PENDING_TTL );

            // WebAuthn options (no real user yet — pending flow)
            $webauthn = new SovAuth_WebAuthn();
            $options  = $webauthn->registrationOptionsPending( $username, $pendingToken );

            return new \WP_REST_Response( [
                'success'          => true,
                'pending_token'    => $pendingToken,
                'webauthn_options' => $options,
            ], 200 );

        } catch ( SovAuth_API_Exception $e ) {
            return $this->err( $e->apiCode, $e->getMessage(), $e->status );
        } catch ( \Throwable $e ) {
            return $this->err( 'server_error', $e->getMessage(), 500 );
        }
    }

    /* ══════════════════════════════════════════════════════════
       POST /webauthn/register/options
       FIX #5: supports pending flow AND logged-in add-device flow.
    ══════════════════════════════════════════════════════════ */

    public function webauthn_reg_options( \WP_REST_Request $req ): \WP_REST_Response {
        try {
            $this->enforcePoW( $req );
            $pendingToken = (string) ( $req->get_param( 'pending_token' ) ?? '' );
            $webauthn     = new SovAuth_WebAuthn();

            if ( $pendingToken ) {
                // Refresh options for the pending (new-user) flow
                [ $pending ] = $this->resolvePendingData( $pendingToken );
                $options      = $webauthn->registrationOptionsPending( $pending['username'], $pendingToken );

            } elseif ( is_user_logged_in() ) {
                // Add-device for already-authenticated user
                $userId  = get_current_user_id();
                $user    = get_userdata( $userId );
                $options = $webauthn->registrationOptions( $userId, $user->user_login );

            } else {
                throw new SovAuth_API_Exception( 'unauthorized', 'Authentication required.', 401 );
            }

            return new \WP_REST_Response( $options, 200 );

        } catch ( SovAuth_API_Exception $e ) {
            return $this->err( $e->apiCode, $e->getMessage(), $e->status );
        } catch ( \Throwable $e ) {
            return $this->err( 'server_error', $e->getMessage(), 500 );
        }
    }

    /* ══════════════════════════════════════════════════════════
       POST /webauthn/register/verify
       FIX #3: wp_insert_user() only runs AFTER successful attestation.
       FIX #4: admin/user.php required before wp_delete_user().
       FIX #5: handles both new-user and add-device flows.
    ══════════════════════════════════════════════════════════ */

    public function webauthn_reg_verify( \WP_REST_Request $req ): \WP_REST_Response {
        try {
            $this->enforcePoW( $req );
            $params       = $req->get_json_params();
            $pendingToken = (string) ( $params['pending_token'] ?? '' );
            $credential   = $params['credential'] ?? null;
            $deviceName   = sanitize_text_field( $params['device_name'] ?? '' );

            if ( ! $credential ) {
                throw new SovAuth_API_Exception( 'missing_credential', 'No credential provided.', 400 );
            }

            $isNewUser = $pendingToken !== '';

            if ( $isNewUser ) {
                /* ── New user: verify → create → store ── */
                [ $pendingData, $pendingHash ] = $this->resolvePendingData( $pendingToken );

                $webauthn = new SovAuth_WebAuthn();
                $credData = $webauthn->verifyAttestation( $credential, 0, $pendingToken );

                // WebAuthn passed — NOW safe to create the WP user
                $domain = wp_parse_url( get_site_url(), PHP_URL_HOST );
                $isPremium = function_exists( 'sav_fs' ) && sav_fs()->can_use_premium_code();
                $userEmail = $isPremium ? ( $pendingData['username'] . '@noemail.' . $domain ) : $pendingData['email'];

                $userId = wp_insert_user( [
                    'user_login' => $pendingData['username'],
                    'user_pass'  => wp_generate_password( 64, true, true ),
                    'user_email' => $userEmail,
                    'role'       => get_option( 'default_role', 'subscriber' ),
                ] );

                if ( is_wp_error( $userId ) ) {
                    throw new SovAuth_API_Exception( 'creation_failed', $userId->get_error_message(), 500 );
                }

                // Persist credential
                $this->storeCredential( $userId, $credData, $deviceName, true );

                // Generate the recovery phrase ONLY for Premium.
                $recoveryPhrase = null;
                if ( $isPremium ) {
                    $backup         = new SovAuth_Backup_Auth();
                    $recoveryPhrase = $backup->setup( $userId );
                }

                // Cleanup transient
                delete_transient( 'sovauth_pending_' . $pendingHash );

                // Login
                wp_set_current_user( $userId );
                wp_set_auth_cookie( $userId, false );

                return new \WP_REST_Response( [
                    'success'         => true,
                    'credential_id'   => $credData['credential_id'],
                    'recovery_phrase' => $recoveryPhrase,
                    'redirect'        => admin_url(),
                ], 201 );

            } else {
                /* ── Add device for logged-in user ── */
                if ( ! is_user_logged_in() ) {
                    throw new SovAuth_API_Exception( 'unauthorized', 'Not authenticated.', 401 );
                }

                $userId   = get_current_user_id();
                $isPremium = function_exists( 'sav_fs' ) && sav_fs()->can_use_premium_code();
                if ( ! $isPremium ) {
                    global $wpdb;
                    $count = (int) $wpdb->get_var( $wpdb->prepare(
                        "SELECT COUNT(*) FROM {$wpdb->prefix}sovauth_credentials WHERE user_id = %d",
                        $userId
                    ) );
                    if ( $count >= 1 ) {
                        throw new SovAuth_API_Exception( 'device_limit', __( 'The free version allows only one device. Upgrade to Pro.', 'sovereign-auth' ), 403 );
                    }
                }

                $webauthn = new SovAuth_WebAuthn();
                $credData = $webauthn->verifyAttestation( $credential, $userId );

                $this->storeCredential( $userId, $credData, $deviceName, false );

                $recoveryPhrase = null;
                $isConfigured   = false;
                if ( $isPremium ) {
                    $backup = new SovAuth_Backup_Auth();
                    if ( ! $backup->isConfigured( $userId ) ) {
                        $recoveryPhrase = $backup->setup( $userId );
                    } else {
                        $isConfigured = true;
                    }
                }

                return new \WP_REST_Response( [
                    'success'         => true,
                    'credential_id'   => $credData['credential_id'],
                    'recovery_phrase' => $recoveryPhrase,
                    'is_premium'      => $isPremium,
                    'is_configured'   => $isConfigured,
                ], 200 );
            }

        } catch ( SovAuth_API_Exception $e ) {
            return $this->err( $e->apiCode, $e->getMessage(), $e->status );
        } catch ( \Throwable $e ) {
            return $this->err( 'server_error', $e->getMessage(), 500 );
        }
    }

    /* ══════════════════════════════════════════════════════════
       POST /webauthn/auth/options
    ══════════════════════════════════════════════════════════ */

    public function webauthn_auth_options( \WP_REST_Request $req ): \WP_REST_Response {
        try {
            $this->enforcePoW( $req );
            $this->ipRateLimit( 'auth_options', 30, 60 );
            $webauthn = new SovAuth_WebAuthn();
            return new \WP_REST_Response( $webauthn->authOptions(), 200 );

        } catch ( SovAuth_API_Exception $e ) {
            return $this->err( $e->apiCode, $e->getMessage(), $e->status );
        } catch ( \Throwable $e ) {
            return $this->err( 'server_error', $e->getMessage(), 500 );
        }
    }

    /* ══════════════════════════════════════════════════════════
       POST /webauthn/auth/verify
    ══════════════════════════════════════════════════════════ */

    public function webauthn_auth_verify( \WP_REST_Request $req ): \WP_REST_Response {
        try {
            $this->enforcePoW( $req );
            $this->ipRateLimit( 'auth_verify', 20, 60 );

            $params       = $req->get_json_params();
            $challengeKey = sanitize_text_field( $params['challenge_key'] ?? '' );
            $credential   = $params['credential'] ?? null;
            $remember     = (bool) ( $params['remember'] ?? false );

            if ( ! $challengeKey || ! $credential ) {
                throw new SovAuth_API_Exception( 'missing_params', 'challenge_key and credential are required.', 400 );
            }

            $webauthn = new SovAuth_WebAuthn();
            $userId   = $webauthn->verifyAuthentication( $challengeKey, $credential );
            $user     = get_userdata( $userId );

            if ( ! $user ) {
                throw new SovAuth_API_Exception( 'user_not_found', 'Authenticated user no longer exists.', 500 );
            }

            wp_set_current_user( $userId );
            wp_set_auth_cookie( $userId, $remember );
            do_action( 'wp_login', $user->user_login, $user );

            return new \WP_REST_Response( [ 'success' => true, 'redirect' => admin_url() ], 200 );

        } catch ( SovAuth_API_Exception $e ) {
            return $this->err( $e->apiCode, $e->getMessage(), $e->status );
        } catch ( \Throwable $e ) {
            return $this->err( 'auth_error', $e->getMessage(), 401 );
        }
    }

    /* ══════════════════════════════════════════════════════════
       POST /backup/verify
    ══════════════════════════════════════════════════════════ */

    public function backup_verify( \WP_REST_Request $req ): \WP_REST_Response {
        if ( ! function_exists( 'sav_fs' ) || ! sav_fs()->can_use_premium_code() ) {
            return new \WP_REST_Response( [
                'code'    => 'rest_forbidden',
                'message' => __( 'Zero-Knowledge Recovery (12-word phrase / QR) is a Premium feature. Upgrade to Pro to use this feature.', 'sovereign-auth' ),
                'data'    => [ 'status' => 403 ]
            ], 403 );
        }

        try {
            $this->enforcePoW( $req );
            $this->ipRateLimit( 'backup_verify', 15, 300 );

            $params   = $req->get_json_params();
            $phrase   = $params['phrase'] ?? '';
            $remember = (bool) ( $params['remember'] ?? false );

            // Accept either a JSON array of 12 words (manual input boxes
            // or a decoded-then-split QR) or a single string (textarea /
            // raw QR payload) — sanitize element-by-element either way.
            $phrase = is_array( $phrase )
                ? array_map( 'sanitize_text_field', $phrase )
                : sanitize_textarea_field( (string) $phrase );

            $backup = new SovAuth_Backup_Auth();
            $userId = $backup->verify( $phrase );
            $user   = get_userdata( $userId );

            if ( ! $user ) {
                throw new SovAuth_API_Exception( 'user_not_found', 'User not found.', 500 );
            }

            wp_set_current_user( $userId );
            wp_set_auth_cookie( $userId, $remember );
            do_action( 'wp_login', $user->user_login, $user );

            return new \WP_REST_Response( [ 'success' => true, 'redirect' => admin_url() ], 200 );

        } catch ( SovAuth_API_Exception $e ) {
            return $this->err( $e->apiCode, $e->getMessage(), $e->status );
        } catch ( \Throwable $e ) {
            return $this->err( 'backup_error', $e->getMessage(), 401 );
        }
    }

    /* ══════════════════════════════════════════════════════════
       GET /credentials
    ══════════════════════════════════════════════════════════ */

    public function credentials_list( \WP_REST_Request $req ): \WP_REST_Response {
        global $wpdb;
        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT id, credential_id, device_name, aaguid, created_at, last_used, sign_count
             FROM {$wpdb->prefix}sovauth_credentials
             WHERE user_id = %d ORDER BY created_at DESC",
            get_current_user_id()
        ) );
        return new \WP_REST_Response( $rows, 200 );
    }

    /* ══════════════════════════════════════════════════════════
       DELETE /credentials/{id}
    ══════════════════════════════════════════════════════════ */

    public function credentials_delete( \WP_REST_Request $req ): \WP_REST_Response {
        try {
            global $wpdb;
            $userId = get_current_user_id();
            $id     = (int) $req->get_param( 'id' );

            $row = $wpdb->get_row( $wpdb->prepare(
                "SELECT id FROM {$wpdb->prefix}sovauth_credentials WHERE id = %d AND user_id = %d",
                $id, $userId
            ) );
            if ( ! $row ) {
                throw new SovAuth_API_Exception( 'not_found', 'Credential not found.', 404 );
            }

            $count = (int) $wpdb->get_var( $wpdb->prepare(
                "SELECT COUNT(*) FROM {$wpdb->prefix}sovauth_credentials WHERE user_id = %d",
                $userId
            ) );
            if ( $count <= 1 ) {
                throw new SovAuth_API_Exception(
                    'last_credential',
                    'Cannot delete the last credential — add another device first.',
                    409
                );
            }

            $wpdb->delete( "{$wpdb->prefix}sovauth_credentials", [ 'id' => $id ] );
            return new \WP_REST_Response( [ 'success' => true ], 200 );

        } catch ( SovAuth_API_Exception $e ) {
            return $this->err( $e->apiCode, $e->getMessage(), $e->status );
        } catch ( \Throwable $e ) {
            return $this->err( 'server_error', $e->getMessage(), 500 );
        }
    }

    /* ══════════════════════════════════════════════════════════
       PRIVATE HELPERS
    ══════════════════════════════════════════════════════════ */

    /**
     * Resolve pending token → [ pendingData, pendingHash ].
     * FIX #6: throws SovAuth_API_Exception instead of wp_die().
     */
    private function resolvePendingData( string $pendingToken ): array {
        if ( strlen( $pendingToken ) !== 64 || ! ctype_xdigit( $pendingToken ) ) {
            throw new SovAuth_API_Exception( 'invalid_token', 'Invalid session token.', 400 );
        }
        $hash = hash( 'sha256', $pendingToken );
        $data = get_transient( 'sovauth_pending_' . $hash );
        if ( ! is_array( $data ) || empty( $data['username'] ) ) {
            throw new SovAuth_API_Exception( 'session_expired', 'Registration session expired. Please start over.', 403 );
        }
        return [ $data, $hash ];
    }

    /**
     * Store a verified credential in the DB.
     * FIX #4: require admin/user.php where wp_delete_user may be needed in cleanup.
     */
    private function storeCredential( int $userId, array $credData, string $deviceName, bool $isNewUser ): void {
        global $wpdb;
        $ok = $wpdb->insert( "{$wpdb->prefix}sovauth_credentials", [
            'user_id'       => $userId,
            'credential_id' => $credData['credential_id'],
            'public_key'    => $credData['public_key'],
            'sign_count'    => $credData['sign_count'],
            'device_name'   => sanitize_text_field( $deviceName ?: 'Primary Device' ),
            'aaguid'        => $credData['aaguid'],
            'created_at'    => current_time( 'mysql' ),
        ] );

        if ( ! $ok ) {
            // Credential save failed
            if ( $isNewUser ) {
                // Roll back the newly created user
                // FIX #4: explicit require before wp_delete_user
                require_once ABSPATH . 'wp-admin/includes/user.php';
                wp_delete_user( $userId );
            }
            throw new SovAuth_API_Exception( 'db_error', 'Failed to store credential.', 500 );
        }
    }

    /**
     * Enforce JS Proof of Work if Tor Mode is active.
     */
    private function enforcePoW( \WP_REST_Request $req ): void {
        if ( get_option( 'sovauth_tor_mode' ) !== 'yes' ) {
            return;
        }

        $header = $req->get_header( 'X-SovAuth-PoW' );
        if ( ! $header || ! str_contains( $header, ':' ) ) {
            throw new SovAuth_API_Exception( 'pow_missing', 'Proof of Work missing or invalid.', 403 );
        }

        [ $challenge, $nonce ] = explode( ':', $header, 2 );

        if ( wp_verify_nonce( $challenge, 'sovauth_pow' ) === false ) {
            throw new SovAuth_API_Exception( 'pow_expired', 'Proof of Work challenge expired. Please reload the page.', 403 );
        }

        $path = $req->get_route();
        $body = $req->get_body();
        $hash = hash( 'sha256', $challenge . $nonce . $path . $body );

        if ( ! str_starts_with( $hash, '00000' ) ) {
            throw new SovAuth_API_Exception( 'pow_invalid', 'Proof of Work is incorrect.', 403 );
        }
    }

    /**
     * Per-IP rate limiter.
     * FIX #6: throws SovAuth_API_Exception instead of wp_die().
     */
    private function ipRateLimit( string $action, int $limit, int $window ): void {
        if ( ! function_exists( 'sav_fs' ) || ! sav_fs()->can_use_premium_code() ) {
            return; // Rate limit is Premium only
        }
        if ( get_option( 'sovauth_tor_mode' ) === 'yes' ) {
            return; // IP tracking is disabled in Tor mode
        }
        $ip    = $this->clientIP();
        $key   = 'sovauth_rl_' . $action . '_' . md5( $ip );
        $count = (int) get_transient( $key );

        if ( $count >= $limit ) {
            throw new SovAuth_API_Exception( 'rate_limited', 'Too many requests. Please wait and try again.', 429 );
        }

        set_transient( $key, $count + 1, $window );
    }

    private function clientIP(): string {
        if ( get_option( 'sovauth_tor_mode' ) === 'yes' ) {
            return '127.0.0.1'; // Mask IP in Tor mode
        }
        // Prevent IP spoofing: default strictly to REMOTE_ADDR.
        // If behind a trusted proxy (e.g. Cloudflare), site admins should use a dedicated
        // proxy plugin or filter to safely resolve the real IP, rather than blindly trusting headers.
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        return apply_filters( 'sovauth_client_ip', filter_var( $ip, FILTER_VALIDATE_IP ) ?: '0.0.0.0' );
    }

    private function err( string $code, string $message, int $status ): \WP_REST_Response {
        return new \WP_REST_Response( [ 'code' => $code, 'message' => $message ], $status );
    }
}
