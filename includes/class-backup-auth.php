<?php
/**
 * Sovereign Auth — Backup Authentication (BIP-39 Recovery Phrase)
 *
 * Replaces the previous QR-code + PIN backup mechanism with a single
 * high-entropy, human-writable secret: a 12-word mnemonic phrase drawn
 * from the standard BIP-39 English wordlist (2048 words, 11 bits/word).
 *
 * IMPORTANT: this is NOT a cryptocurrency wallet seed. We reuse the BIP-39
 * *wordlist* and the "12 words, write them down" convention because it's a
 * proven, widely-understood UX pattern for human-managed high-entropy
 * secrets — but we deliberately skip the BIP-39 checksum word and the
 * PBKDF2/HMAC-SHA512 key-derivation steps, since nothing here derives a
 * cryptographic key. We only need a secret the server can verify, exactly
 * like a password.
 *
 *  SETUP (called once the WP user already exists, right after biometric
 *         registration succeeds — no separate user input required):
 *    1. 12 words are drawn independently and uniformly at random from the
 *       2048-word list via random_int() (CSPRNG) → 12 × 11 = 132 bits of
 *       entropy. (Real BIP-39 12-word phrases carry ~128 bits once the
 *       checksum word is accounted for, so this is at least as strong.)
 *    2. Two values are derived from the phrase and stored in usermeta —
 *       the RAW phrase is never persisted anywhere:
 *         a) SHA-256(phrase)                  → fast, deterministic
 *            "lookup hash". Safe to use for an indexed WHERE lookup
 *            specifically BECAUSE the phrase carries ~132 bits of
 *            entropy — the same reasoning the original 256-bit QR token
 *            relied on.
 *         b) password_hash(phrase, BCRYPT)     → slow, salted "verify
 *            hash". Defense-in-depth: even if the entropy assumption
 *            above were ever wrong (RNG bug, future weakness), the final
 *            authentication gate still costs an attacker a slow, salted
 *            hash per guess rather than a free SHA-256 comparison.
 *    3. The raw 12 words are returned to the caller ONCE for on-screen
 *       display. They cannot be recovered later — only regenerated via
 *       rotate(), which invalidates the old phrase.
 *
 *  VERIFY (recovery login — phrase alone, no separate username field):
 *    1. Normalize input (trim / collapse whitespace / lowercase).
 *    2. Reject anything that isn't exactly 12 known wordlist words before
 *       touching the database (cheap guard against garbage/abuse).
 *    3. SHA-256(phrase) → find the candidate user_id (same pattern the
 *       old QR token lookup used).
 *    4. Per-account lockout check (5 attempts / 15 min).
 *    5. password_verify(phrase, stored verify-hash) → login on success.
 *
 *  SECURITY:
 *    - DB breach reveals only hashes — the phrase cannot be reconstructed.
 *    - 5-attempt lockout per account, 15-minute cooldown (unchanged from
 *      the previous implementation).
 *    - REST-layer per-IP rate limiting still applies (see class-rest-api.php).
 *    - Word selection uses random_int(), PHP's CSPRNG — never rand()/mt_rand().
 */

defined( 'ABSPATH' ) || exit;

final class SovAuth_Backup_Auth {

    private const META_LOOKUP_HASH = '_sovauth_recovery_lookup_hash';
    private const META_VERIFY_HASH = '_sovauth_recovery_verify_hash';
    private const META_ATTEMPTS    = '_sovauth_recovery_attempts';
    private const MAX_ATTEMPTS     = 5;
    private const LOCKOUT_SECS     = 900;   // 15 minutes
    private const PHRASE_WORDS     = 12;
    private const HASH_COST        = 12;    // bcrypt work factor — matches the original PIN hashing cost

    /** @var string[]|null Lazily-loaded, memoized wordlist (2048 words). */
    private static ?array $wordlist     = null;
    /** @var array<string,bool>|null word => true, for O(1) membership checks. */
    private static ?array $wordlistFlip = null;

    /* ══════════════════════════════════════════════════════════
       SETUP
    ══════════════════════════════════════════════════════════ */

    /**
     * Generate and store a fresh recovery phrase for a user.
     *
     * Returns the RAW words — the caller MUST display them to the user
     * immediately. They are not stored server-side and cannot be
     * recovered later (only regenerated, which invalidates this one).
     *
     * @return string[]  Exactly 12 lowercase words, in display order.
     */
    public function setup( int $userId ): array {
        $words = $this->generatePhrase();
        $this->persist( $userId, $words );
        return $words;
    }

    /**
     * Regenerate the phrase, invalidating the previous one.
     *
     * @return string[]  The new 12-word phrase.
     */
    public function rotate( int $userId ): array {
        return $this->setup( $userId );
    }

    /* ══════════════════════════════════════════════════════════
       VERIFY
    ══════════════════════════════════════════════════════════ */

    /**
     * Verify a 12-word recovery phrase and return the user ID on success.
     *
     * @param  array|string $phrase  12 words, as an array (one per input
     *                                box) or a single whitespace-separated
     *                                string (textarea paste).
     * @return int  WordPress user ID.
     * @throws \RuntimeException on bad format, no match, or rate-limit.
     */
    public function verify( array|string $phrase ): int {
        $normalized = $this->normalize( $phrase );

        if ( ! $this->isWellFormed( $normalized ) ) {
            throw new \RuntimeException( 'Invalid recovery phrase format.' );
        }

        $lookupHash = hash( 'sha256', $normalized );

        /* 1 ── Find the user by lookup hash (constant-time via direct lookup,
                 same pattern the old QR-token system used) */
        global $wpdb;
        $userId = (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT user_id FROM {$wpdb->usermeta}
             WHERE meta_key = %s AND meta_value = %s
             LIMIT 1",
            self::META_LOOKUP_HASH,
            $lookupHash
        ) );

        if ( ! $userId ) {
            // Use a sleep to prevent timing-based enumeration
            usleep( random_int( 80000, 150000 ) );
            throw new \RuntimeException( 'Invalid recovery phrase.' );
        }

        /* 2 ── Rate limiting (per account) */
        $this->enforceRateLimit( $userId );

        /* 3 ── Verify against the slow, salted hash */
        $storedHash = get_user_meta( $userId, self::META_VERIFY_HASH, true );

        if ( ! $storedHash || ! password_verify( $normalized, $storedHash ) ) {
            $this->recordFailedAttempt( $userId );
            throw new \RuntimeException( 'Invalid recovery phrase.' );
        }

        /* 4 ── Re-hash if the bcrypt work factor has been upgraded */
        if ( password_needs_rehash( $storedHash, PASSWORD_BCRYPT, [ 'cost' => self::HASH_COST ] ) ) {
            update_user_meta(
                $userId,
                self::META_VERIFY_HASH,
                password_hash( $normalized, PASSWORD_BCRYPT, [ 'cost' => self::HASH_COST ] )
            );
        }

        /* 5 ── Clear failed attempt counter */
        delete_user_meta( $userId, self::META_ATTEMPTS );

        return $userId;
    }

    /* ══════════════════════════════════════════════════════════
       GENERATION & PERSISTENCE
    ══════════════════════════════════════════════════════════ */

    /**
     * Draw PHRASE_WORDS words independently and uniformly at random from
     * the BIP-39 English wordlist using a CSPRNG.
     *
     * @return string[]
     */
    private function generatePhrase(): array {
        $list  = $this->wordlist();
        $max   = count( $list ) - 1;
        $words = [];

        for ( $i = 0; $i < self::PHRASE_WORDS; $i++ ) {
            $words[] = $list[ random_int( 0, $max ) ];
        }

        return $words;
    }

    private function persist( int $userId, array $words ): void {
        $normalized = $this->normalize( $words );

        update_user_meta( $userId, self::META_LOOKUP_HASH, hash( 'sha256', $normalized ) );
        update_user_meta(
            $userId,
            self::META_VERIFY_HASH,
            password_hash( $normalized, PASSWORD_BCRYPT, [ 'cost' => self::HASH_COST ] )
        );
        delete_user_meta( $userId, self::META_ATTEMPTS );
    }

    /* ══════════════════════════════════════════════════════════
       NORMALIZATION & VALIDATION
    ══════════════════════════════════════════════════════════ */

    /**
     * Collapse a phrase (array of words, or a free-form pasted string)
     * into a single canonical "word1 word2 ... word12" form: trimmed,
     * lowercased, single-space-separated. Same normalization is applied
     * at setup time and at verify time so the two hashes always agree.
     */
    private function normalize( array|string $phrase ): string {
        $words = is_array( $phrase ) ? $phrase : preg_split( '/\s+/', trim( $phrase ) );
        $words = array_map(
            static fn( $w ): string => strtolower( trim( (string) $w ) ),
            $words ?: []
        );
        $words = array_filter( $words, static fn( string $w ): bool => $w !== '' );
        return implode( ' ', $words );
    }

    /**
     * Format guard: exactly PHRASE_WORDS words, all present in the
     * wordlist. Prevents an expensive DB lookup on obviously garbage input.
     */
    private function isWellFormed( string $normalized ): bool {
        if ( $normalized === '' ) {
            return false;
        }

        $words = explode( ' ', $normalized );
        if ( count( $words ) !== self::PHRASE_WORDS ) {
            return false;
        }

        $flip = $this->wordlistFlip();
        foreach ( $words as $word ) {
            if ( ! isset( $flip[ $word ] ) ) {
                return false;
            }
        }

        return true;
    }

    /* ══════════════════════════════════════════════════════════
       RATE LIMITING  (unchanged from the previous implementation)
    ══════════════════════════════════════════════════════════ */

    private function enforceRateLimit( int $userId ): void {
        $raw  = get_user_meta( $userId, self::META_ATTEMPTS, true );
        $data = $raw ? json_decode( $raw, true ) : null;

        if ( ! $data || ! isset( $data['count'], $data['since'] ) ) {
            return;
        }

        if ( $data['count'] >= self::MAX_ATTEMPTS ) {
            $elapsed = time() - (int) $data['since'];
            if ( $elapsed < self::LOCKOUT_SECS ) {
                $wait = self::LOCKOUT_SECS - $elapsed;
                throw new \RuntimeException(
                    "Too many failed attempts. Account locked for {$wait} more seconds."
                );
            }
            // Lockout expired — reset
            delete_user_meta( $userId, self::META_ATTEMPTS );
        }
    }

    private function recordFailedAttempt( int $userId ): void {
        $raw  = get_user_meta( $userId, self::META_ATTEMPTS, true );
        $data = $raw ? json_decode( $raw, true ) : null;

        if ( ! $data || ! isset( $data['count'] ) ) {
            $data = [ 'count' => 0, 'since' => time() ];
        }

        $data['count']++;
        update_user_meta( $userId, self::META_ATTEMPTS, wp_json_encode( $data ) );
    }

    /* ══════════════════════════════════════════════════════════
       UTILITIES
    ══════════════════════════════════════════════════════════ */

    /**
     * Check whether a user has a recovery phrase configured.
     */
    public function isConfigured( int $userId ): bool {
        return (bool) get_user_meta( $userId, self::META_LOOKUP_HASH, true );
    }

    /**
     * Lazily load + memoize the BIP-39 English wordlist (2048 words).
     *
     * @return string[]
     */
    private function wordlist(): array {
        if ( self::$wordlist === null ) {
            self::$wordlist = require __DIR__ . '/data/bip39-wordlist.php';
        }
        return self::$wordlist;
    }

    /**
     * word => true map, for O(1) membership checks.
     *
     * @return array<string,bool>
     */
    private function wordlistFlip(): array {
        if ( self::$wordlistFlip === null ) {
            self::$wordlistFlip = array_fill_keys( $this->wordlist(), true );
        }
        return self::$wordlistFlip;
    }
}
