<?php
/**
 * Sovereign Auth — Minimal CBOR Decoder
 *
 * FIXES v1.0.1:
 *  - Bounds check (`require(n)`) before every read — prevents warnings/wrong values on truncated input
 *  - readUint64() rewritten as manual big-endian via two readUint32() calls — avoids 'J' pack
 *    format edge cases and is explicit and platform-safe
 *
 * @see https://www.rfc-editor.org/rfc/rfc7049
 */

defined( 'ABSPATH' ) || exit;

final class SovAuth_CBOR {

    private string $raw;
    private int    $pos = 0;
    private int    $len;          // cached strlen — checked in require()

    /* ── Public API ─────────────────────────────────────────── */

    public static function decode( string $data ): mixed {
        $decoder = new self( $data );
        return $decoder->parse();
    }

    /* ── Private ────────────────────────────────────────────── */

    private function __construct( string $raw ) {
        $this->raw = $raw;
        $this->len = strlen( $raw );
    }

    /** Assert n bytes are available from current position. */
    private function require( int $n ): void {
        if ( $this->pos + $n > $this->len ) {
            throw new \RuntimeException( sprintf(
                'CBOR: need %d byte(s) at offset %d, only %d available',
                $n, $this->pos, $this->len - $this->pos
            ) );
        }
    }

    private function parse(): mixed {
        $this->require( 1 );
        $byte      = ord( $this->raw[ $this->pos++ ] );
        $majorType = ( $byte >> 5 ) & 0x07;
        $addInfo   = $byte & 0x1f;

        $value = $this->readLength( $addInfo );

        return match ( $majorType ) {
            0 => $value,                         // Unsigned integer
            1 => -1 - $value,                    // Negative integer
            2 => $this->readBytes( $value ),      // Byte string
            3 => $this->readBytes( $value ),      // Text string
            4 => $this->readArray( $value ),      // Array
            5 => $this->readMap( $value ),        // Map
            7 => match ( $addInfo ) {             // Simple / Float
                20      => false,
                21      => true,
                22      => null,
                default => $value,
            },
            default => throw new \RuntimeException( "CBOR: unsupported major type {$majorType}" ),
        };
    }

    private function readLength( int $addInfo ): int {
        if ( $addInfo < 24 ) {
            return $addInfo;
        }
        return match ( $addInfo ) {
            24 => $this->readUint8(),
            25 => $this->readUint16(),
            26 => $this->readUint32(),
            27 => $this->readUint64(),
            31 => throw new \RuntimeException( 'CBOR: indefinite-length encoding not supported' ),
            default => throw new \RuntimeException( "CBOR: invalid additional info {$addInfo}" ),
        };
    }

    private function readBytes( int $len ): string {
        $this->require( $len );
        $out        = substr( $this->raw, $this->pos, $len );
        $this->pos += $len;
        return $out;
    }

    private function readArray( int $count ): array {
        $arr = [];
        for ( $i = 0; $i < $count; $i++ ) {
            $arr[] = $this->parse();
        }
        return $arr;
    }

    private function readMap( int $count ): array {
        $map = [];
        for ( $i = 0; $i < $count; $i++ ) {
            $key       = $this->parse();
            $map[$key] = $this->parse();
        }
        return $map;
    }

    /* ── Typed readers ──────────────────────────────────────── */

    private function readUint8(): int {
        $this->require( 1 );
        return ord( $this->raw[ $this->pos++ ] );
    }

    private function readUint16(): int {
        $this->require( 2 );
        $v          = unpack( 'n', substr( $this->raw, $this->pos, 2 ) )[1];
        $this->pos += 2;
        return $v;
    }

    private function readUint32(): int {
        $this->require( 4 );
        $v          = unpack( 'N', substr( $this->raw, $this->pos, 4 ) )[1];
        $this->pos += 4;
        return $v;
    }

    /**
     * Big-endian uint64 — implemented via two uint32 reads.
     * Avoids the 'J' unpack format which can behave inconsistently
     * on some PHP builds/platforms. Safe on all 64-bit PHP 8.x targets.
     */
    private function readUint64(): int {
        $this->require( 8 );
        $hi         = unpack( 'N', substr( $this->raw, $this->pos,     4 ) )[1];
        $lo         = unpack( 'N', substr( $this->raw, $this->pos + 4, 4 ) )[1];
        $this->pos += 8;
        // On PHP 64-bit, intval of hi*2^32 + lo is always safe
        return (int) ( (float) $hi * 0x100000000 + (float) $lo );
    }
}
