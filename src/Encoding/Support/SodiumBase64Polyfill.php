<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Encoding\Support;

use Cline\JWT\Exceptions\CannotDecodeContent;
use Cline\JWT\Exceptions\InvalidBase64UrlContent;
use SodiumException;

use function base64_decode;
use function base64_encode;
use function function_exists;
use function is_string;
use function mb_rtrim;
use function sodium_base642bin;
use function sodium_bin2base64;
use function strtr;

/**
 * Internal compatibility layer for sodium-style Base64 helpers.
 *
 * The package prefers ext-sodium for exact JOSE-compatible Base64 handling but
 * falls back to core PHP transforms when sodium is unavailable. Exposing the same
 * constants and method signatures keeps encoder code simple while preserving
 * package-level decode exceptions.
 *
 * @author Brian Faust <brian@cline.sh>
 * @internal
 * @psalm-immutable
 */
final readonly class SodiumBase64Polyfill
{
    public const int SODIUM_BASE64_VARIANT_ORIGINAL = 1;

    public const int SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING = 3;

    public const int SODIUM_BASE64_VARIANT_URLSAFE = 5;

    public const int SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING = 7;

    /**
     * Encode binary data using the selected sodium Base64 variant.
     *
     * @return ($decoded is non-empty-string ? non-empty-string : string)
     */
    public static function bin2base64(string $decoded, int $variant): string
    {
        if (!function_exists('sodium_bin2base64')) {
            return self::bin2base64Fallback($decoded, $variant); // @codeCoverageIgnore
        }

        return sodium_bin2base64($decoded, $variant);
    }

    /**
     * Encode binary data without relying on ext-sodium.
     *
     * @return ($decoded is non-empty-string ? non-empty-string : string)
     */
    public static function bin2base64Fallback(string $decoded, int $variant): string
    {
        $encoded = base64_encode($decoded);

        if (
            $variant === self::SODIUM_BASE64_VARIANT_URLSAFE
            || $variant === self::SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING
        ) {
            $encoded = strtr($encoded, '+/', '-_');
        }

        if ($variant === self::SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING
        || $variant === self::SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING) {
            return mb_rtrim($encoded, '=');
        }

        return $encoded;
    }

    /**
     * Decode a Base64 string using the selected sodium Base64 variant.
     *
     * @throws CannotDecodeContent
     * @return ($encoded is non-empty-string ? non-empty-string : string)
     */
    public static function base642bin(string $encoded, int $variant): string
    {
        if (!function_exists('sodium_base642bin')) {
            return self::base642binFallback($encoded, $variant); // @codeCoverageIgnore
        }

        try {
            return sodium_base642bin($encoded, $variant, '');
        } catch (SodiumException) {
            throw InvalidBase64UrlContent::detected();
        }
    }

    /**
     * Decode a Base64 string without relying on ext-sodium.
     *
     * @throws CannotDecodeContent
     * @return ($encoded is non-empty-string ? non-empty-string : string)
     */
    public static function base642binFallback(string $encoded, int $variant): string
    {
        if (
            $variant === self::SODIUM_BASE64_VARIANT_URLSAFE
            || $variant === self::SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING
        ) {
            $encoded = strtr($encoded, '-_', '+/');
        }

        $decoded = base64_decode($encoded, true);

        if (!is_string($decoded)) {
            throw InvalidBase64UrlContent::detected();
        }

        return $decoded;
    }
}
