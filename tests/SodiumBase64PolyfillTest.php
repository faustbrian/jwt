<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests;

use Cline\JWT\Encoding\Support\SodiumBase64Polyfill;
use Cline\JWT\Exceptions\CannotDecodeContent;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

use const SODIUM_BASE64_VARIANT_ORIGINAL;
use const SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING;
use const SODIUM_BASE64_VARIANT_URLSAFE;
use const SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING;

use function mb_rtrim;
use function sodium_base642bin;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(SodiumBase64Polyfill::class)]
#[UsesClass(CannotDecodeContent::class)]
final class SodiumBase64PolyfillTest extends TestCase
{
    private const string B64 = 'I+o2tVq8ynY=';

    private const string B64URL = 'lZ-2HIl9dTz_Oy0nAb-2gvKdG0jhHJ36XB2rWAKj8Uo=';

    #[Test()]
    public function constants_match_extension_ones(): void
    {
        // @phpstan-ignore-next-line
        $this->assertSame(SODIUM_BASE64_VARIANT_ORIGINAL, SodiumBase64Polyfill::SODIUM_BASE64_VARIANT_ORIGINAL);
        // @phpstan-ignore-next-line
        $this->assertSame(SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING, SodiumBase64Polyfill::SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
        // @phpstan-ignore-next-line
        $this->assertSame(SODIUM_BASE64_VARIANT_URLSAFE, SodiumBase64Polyfill::SODIUM_BASE64_VARIANT_URLSAFE);
        // @phpstan-ignore-next-line
        $this->assertSame(SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING, SodiumBase64Polyfill::SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    #[Test()]
    #[DataProvider('base64Variants')]
    public function bin2base64(string $encoded, string $binary, int $variant): void
    {
        $this->assertSame($encoded, SodiumBase64Polyfill::bin2base64($binary, $variant));
        $this->assertSame($encoded, SodiumBase64Polyfill::bin2base64Fallback($binary, $variant));
    }

    #[Test()]
    #[DataProvider('base64Variants')]
    public function base642bin_fallback(string $encoded, string $binary, int $variant): void
    {
        $this->assertSame($binary, SodiumBase64Polyfill::base642bin($encoded, $variant));
        $this->assertSame($binary, SodiumBase64Polyfill::base642binFallback($encoded, $variant));
    }

    /**
     * @return iterable<array{string, string, int}>
     */
    public static function base64Variants(): iterable
    {
        $binary = sodium_base642bin(self::B64, SODIUM_BASE64_VARIANT_ORIGINAL, '');

        yield [self::B64, $binary, SODIUM_BASE64_VARIANT_ORIGINAL];

        yield [mb_rtrim(self::B64, '='), $binary, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING];

        $urlBinary = sodium_base642bin(self::B64URL, SODIUM_BASE64_VARIANT_URLSAFE, '');

        yield [self::B64URL, $urlBinary, SODIUM_BASE64_VARIANT_URLSAFE];

        yield [mb_rtrim(self::B64URL, '='), $urlBinary, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING];
    }

    #[Test()]
    #[DataProvider('invalidBase64')]
    public function sodium_base642_bin_raises_exception_on_invalid_base64(string $content, int $variant): void
    {
        $this->expectException(CannotDecodeContent::class);

        SodiumBase64Polyfill::base642bin($content, $variant);
    }

    #[Test()]
    #[DataProvider('invalidBase64')]
    public function fallback_base642_bin_raises_exception_on_invalid_base64(string $content, int $variant): void
    {
        $this->expectException(CannotDecodeContent::class);

        SodiumBase64Polyfill::base642binFallback($content, $variant);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function invalidBase64(): iterable
    {
        yield 'UTF-8 content' => ['ááá', SODIUM_BASE64_VARIANT_ORIGINAL];

        yield 'b64Url variant against original (padded)' => [
            self::B64URL,
            SODIUM_BASE64_VARIANT_ORIGINAL,
        ];

        yield 'b64Url variant against original (not padded)' => [
            mb_rtrim(self::B64URL, '='),
            SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING,
        ];
    }
}
