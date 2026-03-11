<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Token;

use Carbon\CarbonImmutable;
use Cline\JWT\Contracts\DecoderInterface;
use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Exceptions\InvalidTokenStructure;
use Cline\JWT\Token\Parser;
use Cline\JWT\Token\RegisteredClaims;

use function dataset;
use function expect;
use function test;

test('parser converts integer and float date claims to carbon instances', function (): void {
    $decoder = new class() implements DecoderInterface
    {
        public function jsonDecode(string $json): mixed
        {
            return match ($json) {
                'header' => ['alg' => 'none'],
                'claims' => [
                    RegisteredClaims::ISSUED_AT => 1_700_000_000,
                    RegisteredClaims::NOT_BEFORE => 1_700_000_000.123456,
                    RegisteredClaims::EXPIRATION_TIME => '1700000001.500000',
                ],
            };
        }

        public function base64UrlDecode(string $data): string
        {
            return match ($data) {
                'a' => 'header',
                'b' => 'claims',
                'c' => 'signature',
            };
        }
    };

    $token = new Parser($decoder)->parse('a.b.c');

    expect($token->claims()->issuedAt()?->format('U.u'))->toBe('1700000000.000000')
        ->and($token->claims()->notBefore()?->format('U.u'))->toBe('1700000000.123456')
        ->and($token->claims()->expiresAt()?->format('U.u'))->toBe('1700000001.500000');
});

dataset('invalid parser date values', [
    'array type' => [[], 'array'],
    'non numeric string' => ['invalid', 'invalid'],
]);

test('parser rejects invalid date claim payloads', function (mixed $value, string $message): void {
    $decoder = new readonly class($value) implements DecoderInterface
    {
        public function __construct(
            private mixed $value,
        ) {}

        public function jsonDecode(string $json): mixed
        {
            return match ($json) {
                'header' => ['alg' => 'none'],
                'claims' => [RegisteredClaims::ISSUED_AT => $this->value],
            };
        }

        public function base64UrlDecode(string $data): string
        {
            return match ($data) {
                'a' => 'header',
                'b' => 'claims',
                'c' => 'signature',
            };
        }
    };

    expect(fn (): TokenInterface => new Parser($decoder)->parse('a.b.c'))
        ->toThrow(InvalidTokenStructure::class, 'Value is not in the allowed date format: '.$message);
})->with('invalid parser date values');

test('parser rejects numeric strings that carbon cannot parse', function (): void {
    $decoder = new class() implements DecoderInterface
    {
        public function jsonDecode(string $json): mixed
        {
            return match ($json) {
                'header' => ['alg' => 'none'],
                'claims' => [RegisteredClaims::ISSUED_AT => '999999999999999999999999999999'],
            };
        }

        public function base64UrlDecode(string $data): string
        {
            return match ($data) {
                'a' => 'header',
                'b' => 'claims',
                'c' => 'signature',
            };
        }
    };

    expect(fn (): TokenInterface => new Parser($decoder)->parse('a.b.c'))
        ->toThrow(InvalidTokenStructure::class);
});

test('parser rejects non object carbon results when strict mode is disabled', function (): void {
    CarbonImmutable::useStrictMode(false);

    $decoder = new class() implements DecoderInterface
    {
        public function jsonDecode(string $json): mixed
        {
            return match ($json) {
                'header' => ['alg' => 'none'],
                'claims' => [RegisteredClaims::ISSUED_AT => '999999999999999999999999999999'],
            };
        }

        public function base64UrlDecode(string $data): string
        {
            return match ($data) {
                'a' => 'header',
                'b' => 'claims',
                'c' => 'signature',
            };
        }
    };

    try {
        expect(fn (): TokenInterface => new Parser($decoder)->parse('a.b.c'))
            ->toThrow(InvalidTokenStructure::class);
    } finally {
        CarbonImmutable::useStrictMode(true);
    }
});
