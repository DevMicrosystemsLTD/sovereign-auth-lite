<?php
/**
 * Sovereign Auth — WebAuthn / FIDO2 Handler
 *
 * FIXES v1.0.1:
 *  - residentKey changed from 'preferred' → 'required' so all created credentials
 *    are discoverable; avoids silent login failures on strict-discoverable authenticators
 *  - Registration options split into two methods:
 *      registrationOptions()        → existing/logged-in user adding a new device
 *      registrationOptionsPending() → new user (no WP user ID yet)
 *  - verifyAttestation() replaces verifyRegistration():
 *    extracts and returns credential data WITHOUT writing to DB (REST layer owns that)
 *
 * @see https://www.w3.org/TR/webauthn-3/
 */

defined( 'ABSPATH' ) || exit;

final class SovAuth_WebAuthn {

    private string $rpId;
    private string $origin;

public function __construct() {
        $parsed = wp_parse_url( get_site_url() );
        $this->rpId   = $parsed['host'] ?? $_SERVER['SERVER_NAME'];
        $port         = !empty($parsed['port']) ? ':' . $parsed['port'] : '';
        $this->origin = ($parsed['scheme'] ?? 'https') . '://' . $this->rpId . $port;
    }
    /* ══════════════════════════════════════════════════════════
       REGISTRATION OPTIONS
    ══════════════════════════════════════════════════════════ */

    /**
     * Options for an EXISTING logged-in user adding a new device.
     * Challenge stored by user_id.
     */
    public function registrationOptions( int $userId, string $username ): array {
        $challenge    = random_bytes( 32 );
        $challengeB64 = self::b64url( $challenge );

        set_transient( 'sovauth_reg_chal_u_' . $userId, $challengeB64, SOVAUTH_CHALLENGE_TTL );

        global $wpdb;
        $existing = $wpdb->get_col( $wpdb->prepare(
            "SELECT credential_id FROM {$wpdb->prefix}sovauth_credentials WHERE user_id = %d",
            $userId
        ) );

        return $this->buildOptions(
            $challengeB64,
            self::b64url( pack( 'N', $userId ) ),   // stable per-user bytes
            $username,
            array_map( fn( $id ) => [ 'type' => 'public-key', 'id' => $id ], $existing )
        );
    }

    /**
     * Options for a PENDING user (no WP user ID yet — created after WebAuthn).
     * Challenge stored by pendingToken hash.
     */
    public function registrationOptionsPending( string $username, string $pendingToken ): array {
        $challenge    = random_bytes( 32 );
        $challengeB64 = self::b64url( $challenge );
        $pendingHash  = hash( 'sha256', $pendingToken );

        set_transient( 'sovauth_reg_chal_p_' . $pendingHash, $challengeB64, SOVAUTH_CHALLENGE_TTL );

        return $this->buildOptions(
            $challengeB64,
            self::b64url( hex2bin( $pendingHash ) ), // deterministic 32-byte user.id handle
            $username,
            []
        );
    }

    /** Shared option builder. */
    private function buildOptions(
        string $challengeB64,
        string $userIdB64,
        string $username,
        array  $excludeCredentials
    ): array {
        return [
            'challenge'              => $challengeB64,
            'rp'                     => [
                'id'   => $this->rpId,
                'name' => get_bloginfo( 'name' ),
            ],
            'user'                   => [
                'id'          => $userIdB64,
                'name'        => $username,
                'displayName' => $username,
            ],
            'pubKeyCredParams'       => [
                [ 'type' => 'public-key', 'alg' => -7   ],   // ES256
                [ 'type' => 'public-key', 'alg' => -257 ],   // RS256
            ],
            'excludeCredentials'     => $excludeCredentials,
            'authenticatorSelection' => [
                'authenticatorAttachment' => 'platform',
                'userVerification'        => 'required',
                // FIX: was 'preferred' — must be 'required' to guarantee discoverable
                // credentials for the passwordless login flow
                'residentKey'             => 'required',
            ],
            'timeout'     => 60000,
            'attestation' => 'none',
        ];
    }

    /* ══════════════════════════════════════════════════════════
       ATTESTATION VERIFICATION  (no DB write — caller's job)
    ══════════════════════════════════════════════════════════ */

    /**
     * Verify a registration attestation and return extracted credential data.
     *
     * @param  array  $credential    Decoded JSON payload from the browser.
     * @param  int    $userId        > 0 for add-device flow; 0 for pending flow.
     * @param  string $pendingToken  Non-empty for pending flow.
     * @return array { credential_id, public_key, sign_count, aaguid }
     * @throws \RuntimeException on any verification failure.
     */
    public function verifyAttestation( array $credential, int $userId = 0, string $pendingToken = '' ): array {
        $response = $credential['response'] ?? throw new \RuntimeException( 'Missing response object' );

        /* 1 — clientDataJSON */
        $clientDataRaw = self::fromB64url( $response['clientDataJSON'] );
        $clientData    = json_decode( $clientDataRaw, true );

        if ( ( $clientData['type'] ?? '' ) !== 'webauthn.create' ) {
            throw new \RuntimeException( 'Invalid clientData.type' );
        }

        /* 2 — Verify challenge */
        if ( $pendingToken ) {
            $pendingHash  = hash( 'sha256', $pendingToken );
            $challengeKey = 'sovauth_reg_chal_p_' . $pendingHash;
        } else {
            $challengeKey = 'sovauth_reg_chal_u_' . $userId;
        }

        $stored = get_transient( $challengeKey );
        if ( ! $stored ) {
            throw new \RuntimeException( 'Challenge expired — restart registration' );
        }
        if ( ! hash_equals( $stored, $clientData['challenge'] ?? '' ) ) {
            throw new \RuntimeException( 'Challenge mismatch' );
        }
        delete_transient( $challengeKey );

        /* 3 — Origin */
        if ( rtrim( $clientData['origin'] ?? '', '/' ) !== $this->origin ) {
            throw new \RuntimeException( 'Origin mismatch' );
        }

        /* 4 — Decode attestationObject (CBOR) */
        $attObjRaw   = self::fromB64url( $response['attestationObject'] );
        $attestation = SovAuth_CBOR::decode( $attObjRaw );
        $authData    = $attestation['authData'] ?? throw new \RuntimeException( 'Missing authData in attestation' );

        /* 5 — Parse authData */
        $parsed = $this->parseAuthData( $authData );

        /* 6 — RP ID hash */
        if ( ! hash_equals( hash( 'sha256', $this->rpId, true ), $parsed['rpIdHash'] ) ) {
            throw new \RuntimeException( 'RP ID hash mismatch' );
        }

        /* 7 — UV flag (bit 2) — biometric must have been performed */
        if ( ! ( $parsed['flags'] & 0x04 ) ) {
            throw new \RuntimeException( 'User verification not performed — biometric required' );
        }

        /* 8 — Attested credential data must be present */
        if ( ! isset( $parsed['credentialId'], $parsed['coseKey'] ) ) {
            throw new \RuntimeException( 'Missing attested credential data in authData' );
        }

        /* 9 — Convert COSE → PEM */
        $publicKeyPEM = SovAuth_COSE::toPEM( $parsed['coseKey'] );
        $credentialId = self::b64url( $parsed['credentialId'] );

        return [
            'credential_id' => $credentialId,
            'public_key'    => $publicKeyPEM,
            'sign_count'    => $parsed['signCount'],
            'aaguid'        => $this->formatAaguid( $parsed['aaguid'] ?? '' ),
        ];
    }

    /* ══════════════════════════════════════════════════════════
       AUTHENTICATION OPTIONS
    ══════════════════════════════════════════════════════════ */

    public function authOptions(): array {
        $challenge    = random_bytes( 32 );
        $challengeB64 = self::b64url( $challenge );
        $sessionKey   = 'sovauth_auth_' . bin2hex( random_bytes( 12 ) );

        set_transient( $sessionKey, $challengeB64, SOVAUTH_CHALLENGE_TTL );

        return [
            'challenge'        => $challengeB64,
            'rpId'             => $this->rpId,
            'timeout'          => 60000,
            'userVerification' => 'required',
            'challengeKey'     => $sessionKey,
        ];
    }

    /* ══════════════════════════════════════════════════════════
       ASSERTION VERIFICATION
    ══════════════════════════════════════════════════════════ */

    /**
     * Verify WebAuthn assertion and return the authenticated WP user ID.
     *
     * @throws \RuntimeException on any failure.
     */
    public function verifyAuthentication( string $challengeKey, array $credential ): int {
        $response = $credential['response'] ?? throw new \RuntimeException( 'Missing response' );

        /* 1 — Challenge */
        $storedChallenge = get_transient( $challengeKey );
        if ( ! $storedChallenge ) {
            throw new \RuntimeException( 'Challenge expired — retry login' );
        }
        delete_transient( $challengeKey );

        /* 2 — clientDataJSON */
        $clientDataRaw = self::fromB64url( $response['clientDataJSON'] );
        $clientData    = json_decode( $clientDataRaw, true );

        if ( ( $clientData['type'] ?? '' ) !== 'webauthn.get' ) {
            throw new \RuntimeException( 'Invalid clientData.type' );
        }
        if ( ! hash_equals( $storedChallenge, $clientData['challenge'] ?? '' ) ) {
            throw new \RuntimeException( 'Challenge mismatch' );
        }

        /* 3 — Origin */
        if ( rtrim( $clientData['origin'] ?? '', '/' ) !== $this->origin ) {
            throw new \RuntimeException( 'Origin mismatch' );
        }

        /* 4 — Lookup credential */
        $credentialId = $credential['id'] ?? throw new \RuntimeException( 'Missing credential id' );
        global $wpdb;
        $row = $wpdb->get_row( $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}sovauth_credentials WHERE credential_id = %s",
            $credentialId
        ) );
        if ( ! $row ) {
            throw new \RuntimeException( 'Credential not found' );
        }

        /* 5 — Parse authData */
        $authDataRaw = self::fromB64url( $response['authenticatorData'] );
        $parsed      = $this->parseAuthData( $authDataRaw );

        /* 6 — RP ID hash */
        if ( ! hash_equals( hash( 'sha256', $this->rpId, true ), $parsed['rpIdHash'] ) ) {
            throw new \RuntimeException( 'RP ID hash mismatch' );
        }

        /* 7 — UV flag */
        if ( ! ( $parsed['flags'] & 0x04 ) ) {
            throw new \RuntimeException( 'User verification not performed' );
        }

        /* 8 — Sign count / replay protection */
        $newCount = $parsed['signCount'];
        if ( $newCount > 0 && $newCount <= (int) $row->sign_count ) {
            throw new \RuntimeException( 'Sign count regression — possible cloned authenticator' );
        }

        /* 9 — Signature */
        $clientDataHash = hash( 'sha256', $clientDataRaw, true );
        $signatureBase  = $authDataRaw . $clientDataHash;
        $signature      = self::fromB64url( $response['signature'] );

        $pubKey = openssl_pkey_get_public( $row->public_key );
        if ( $pubKey === false ) {
            throw new \RuntimeException( 'Failed to load stored public key' );
        }
        if ( openssl_verify( $signatureBase, $signature, $pubKey, OPENSSL_ALGO_SHA256 ) !== 1 ) {
            throw new \RuntimeException( 'Signature verification failed' );
        }

        /* 10 — Update counters */
        $wpdb->update(
            "{$wpdb->prefix}sovauth_credentials",
            [ 'sign_count' => $newCount, 'last_used' => current_time( 'mysql' ) ],
            [ 'id' => (int) $row->id ]
        );

        return (int) $row->user_id;
    }

    /* ══════════════════════════════════════════════════════════
       AUTHENTICATOR DATA PARSER
    ══════════════════════════════════════════════════════════ */

    private function parseAuthData( string $authData ): array {
        if ( strlen( $authData ) < 37 ) {
            throw new \RuntimeException( 'AuthData too short' );
        }
        $offset    = 0;
        $rpIdHash  = substr( $authData, $offset, 32 ); $offset += 32;
        $flags     = ord( $authData[$offset] );        $offset += 1;
        $signCount = unpack( 'N', substr( $authData, $offset, 4 ) )[1]; $offset += 4;

        $result = [ 'rpIdHash' => $rpIdHash, 'flags' => $flags, 'signCount' => $signCount ];

        if ( $flags & 0x40 ) {   // AT flag — attested credential data present
            if ( strlen( $authData ) < $offset + 18 ) {
                throw new \RuntimeException( 'AuthData truncated before credential data' );
            }
            $aaguid       = substr( $authData, $offset, 16 ); $offset += 16;
            $credIdLen    = unpack( 'n', substr( $authData, $offset, 2 ) )[1]; $offset += 2;
            $credentialId = substr( $authData, $offset, $credIdLen ); $offset += $credIdLen;
            $coseKey      = SovAuth_CBOR::decode( substr( $authData, $offset ) );

            $result['aaguid']       = $aaguid;
            $result['credentialId'] = $credentialId;
            $result['coseKey']      = $coseKey;
        }
        return $result;
    }

    /* ══════════════════════════════════════════════════════════
       HELPERS
    ══════════════════════════════════════════════════════════ */

    public static function b64url( string $bytes ): string {
        return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' );
    }

    public static function fromB64url( string $b64url ): string {
        $b64 = strtr( $b64url, '-_', '+/' );
        $pad = strlen( $b64 ) % 4;
        if ( $pad ) $b64 .= str_repeat( '=', 4 - $pad );
        $decoded = base64_decode( $b64, true );
        if ( $decoded === false ) {
            throw new \RuntimeException( 'Invalid base64url input' );
        }
        return $decoded;
    }

    private function formatAaguid( string $raw ): string {
        if ( strlen( $raw ) !== 16 ) return '';
        $h = bin2hex( $raw );
        return sprintf(
            '%s-%s-%s-%s-%s',
            substr( $h,  0, 8 ), substr( $h,  8, 4 ),
            substr( $h, 12, 4 ), substr( $h, 16, 4 ),
            substr( $h, 20, 12 )
        );
    }
}
