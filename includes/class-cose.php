<?php
/**
 * Sovereign Auth — COSE Key → PEM Converter
 *
 * Converts COSE-encoded public keys (RFC 8152) returned by WebAuthn
 * authenticators into PEM strings consumable by PHP's openssl_verify().
 *
 * Supported algorithms:
 *   ES256 (ECDSA P-256 with SHA-256)  — most platform authenticators
 *   RS256 (RSASSA-PKCS1-v1.5 SHA-256) — TPM-based authenticators
 *
 * @see https://www.rfc-editor.org/rfc/rfc8152
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */

defined( 'ABSPATH' ) || exit;

final class SovAuth_COSE {

    /* ── COSE key-type constants ────────────────────────────── */
    private const KTY_EC2 = 2;
    private const KTY_RSA = 3;

    /* ── DER OIDs (raw bytes) ───────────────────────────────── */
    // id-ecPublicKey  1.2.840.10045.2.1
    private const OID_EC_PUBLIC_KEY = "\x2a\x86\x48\xce\x3d\x02\x01";
    // prime256v1      1.2.840.10045.3.1.7
    private const OID_P256          = "\x2a\x86\x48\xce\x3d\x03\x01\x07";
    // rsaEncryption   1.2.840.113549.1.1.1
    private const OID_RSA           = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";

    /* ── Public API ─────────────────────────────────────────── */

    /**
     * Convert a decoded COSE key map into a PEM public key string.
     *
     * @param  array<int, mixed> $coseKey  Decoded CBOR map.
     * @return string  PEM-encoded public key.
     * @throws \RuntimeException for unsupported key types.
     */
    public static function toPEM( array $coseKey ): string {
        $kty = (int) ( $coseKey[1] ?? throw new \RuntimeException( 'COSE: missing kty (key 1)' ) );

        $der = match ( $kty ) {
            self::KTY_EC2 => self::buildEC( $coseKey ),
            self::KTY_RSA => self::buildRSA( $coseKey ),
            default       => throw new \RuntimeException( "COSE: unsupported kty {$kty}" ),
        };

        return "-----BEGIN PUBLIC KEY-----\n"
             . chunk_split( base64_encode( $der ), 64, "\n" )
             . "-----END PUBLIC KEY-----\n";
    }

    /* ── EC P-256 ───────────────────────────────────────────── */

    private static function buildEC( array $key ): string {
        $x = $key[-2] ?? throw new \RuntimeException( 'COSE EC: missing x coordinate' );
        $y = $key[-3] ?? throw new \RuntimeException( 'COSE EC: missing y coordinate' );

        if ( strlen( $x ) !== 32 || strlen( $y ) !== 32 ) {
            throw new \RuntimeException( 'COSE EC: x/y must be 32 bytes each (P-256)' );
        }

        // Uncompressed EC point: 0x04 || x || y
        $point = "\x04" . $x . $y;

        // SubjectPublicKeyInfo { AlgorithmIdentifier { OID, OID }, BIT STRING }
        $algorithmId = self::derSeq(
            self::derOid( self::OID_EC_PUBLIC_KEY ) .
            self::derOid( self::OID_P256 )
        );

        return self::derSeq( $algorithmId . self::derBitString( $point ) );
    }

    /* ── RSA ────────────────────────────────────────────────── */

    private static function buildRSA( array $key ): string {
        $n = $key[-1] ?? throw new \RuntimeException( 'COSE RSA: missing modulus (n)' );
        $e = $key[-2] ?? throw new \RuntimeException( 'COSE RSA: missing exponent (e)' );

        // Some implementations encode e as CBOR uint; handle both
        if ( is_int( $e ) ) {
            $e = ltrim( pack( 'N', $e ), "\x00" );
        }

        $rsaPublicKey = self::derSeq(
            self::derInt( $n ) .
            self::derInt( $e )
        );

        $algorithmId = self::derSeq(
            self::derOid( self::OID_RSA ) . "\x05\x00"  // NULL params
        );

        return self::derSeq( $algorithmId . self::derBitString( $rsaPublicKey ) );
    }

    /* ── DER encoding primitives ────────────────────────────── */

    private static function derTag( int $tag, string $content ): string {
        $len = strlen( $content );
        if ( $len < 128 ) {
            return chr( $tag ) . chr( $len ) . $content;
        }
        if ( $len < 256 ) {
            return chr( $tag ) . "\x81" . chr( $len ) . $content;
        }
        return chr( $tag ) . "\x82" . chr( $len >> 8 ) . chr( $len & 0xFF ) . $content;
    }

    private static function derSeq( string $content ): string {
        return self::derTag( 0x30, $content );
    }

    private static function derOid( string $oidBytes ): string {
        return self::derTag( 0x06, $oidBytes );
    }

    /**
     * DER BIT STRING: 0x03 + length + 0x00 (unused bits) + data
     */
    private static function derBitString( string $data ): string {
        return self::derTag( 0x03, "\x00" . $data );
    }

    /**
     * DER INTEGER: strip leading 0x00 bytes; prepend 0x00 if high bit set (sign).
     */
    private static function derInt( string $data ): string {
        $data = ltrim( $data, "\x00" );
        if ( $data === '' ) {
            $data = "\x00";
        }
        if ( ord( $data[0] ) >= 0x80 ) {
            $data = "\x00" . $data;
        }
        return self::derTag( 0x02, $data );
    }
}
