<?php

declare(strict_types=1);

namespace Oki\People\Keys;

/**
 * A published RSA signing key, read into the PEM a verifier takes.
 *
 * Anything that is not an RS256 signing key of at least 2048 bits is passed
 * over rather than trusted.
 */
final class Jwk
{
    /** RS256 asks for 2048 bits at least. */
    private const int MINIMUM_BYTES = 256;

    /**
     * The key's `kid` and PEM, or null for any other kind of key.
     *
     * @param  array<mixed>  $jwk
     * @return array{non-empty-string, non-empty-string}|null
     */
    public static function read(array $jwk): ?array
    {
        $kid = $jwk['kid'] ?? null;
        $n = is_string($jwk['n'] ?? null) ? self::decode($jwk['n']) : null;
        $e = is_string($jwk['e'] ?? null) ? self::decode($jwk['e']) : null;

        if (
            ! is_string($kid) || $kid === ''
            || ($jwk['kty'] ?? null) !== 'RSA'
            || ($jwk['use'] ?? 'sig') !== 'sig'
            || ($jwk['alg'] ?? 'RS256') !== 'RS256'
            || $n === null || $e === null
            || strlen(ltrim($n, "\0")) < self::MINIMUM_BYTES
        ) {
            return null;
        }

        return [$kid, self::pem($n, $e)];
    }

    private static function decode(string $value): ?string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        return is_string($decoded) && $decoded !== '' ? $decoded : null;
    }

    /**
     * The modulus and exponent as a SubjectPublicKeyInfo, which is what PEM carries.
     *
     * @return non-empty-string
     */
    private static function pem(string $n, string $e): string
    {
        $rsa = self::der(0x30, self::integer($n).self::integer($e));
        $algorithm = self::der(0x30, self::der(0x06, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01").self::der(0x05, ''));
        $info = self::der(0x30, $algorithm.self::der(0x03, "\0".$rsa));

        return "-----BEGIN PUBLIC KEY-----\n"
            .chunk_split(base64_encode($info), 64, "\n")
            ."-----END PUBLIC KEY-----\n";
    }

    /** An unsigned big-endian integer, padded so its high bit does not read as a sign. */
    private static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\0");

        if ($bytes === '' || ord($bytes[0]) > 0x7F) {
            $bytes = "\0".$bytes;
        }

        return self::der(0x02, $bytes);
    }

    private static function der(int $tag, string $content): string
    {
        $length = strlen($content);

        if ($length < 0x80) {
            return chr($tag).chr($length).$content;
        }

        $encoded = ltrim(pack('N', $length), "\0");

        return chr($tag).chr(0x80 | strlen($encoded)).$encoded.$content;
    }
}
