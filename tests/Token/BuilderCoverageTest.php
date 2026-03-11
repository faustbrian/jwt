<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Token;

use Cline\JWT\Contracts\EncoderInterface;
use Cline\JWT\Encoding\MicrosecondBasedDateConversion;
use Cline\JWT\Token\Builder;
use Cline\JWT\Token\RegisteredClaims;
use ReflectionClass;

use const JSON_THROW_ON_ERROR;

use function expect;
use function json_encode;
use function test;

test('permitted for resets malformed configured audience values before appending strings', function (): void {
    $encoder = new class() implements EncoderInterface
    {
        public function jsonEncode(mixed $data): string
        {
            return json_encode($data, JSON_THROW_ON_ERROR);
        }

        public function base64UrlEncode(string $data): string
        {
            return $data;
        }
    };

    $reflection = new ReflectionClass(Builder::class);
    $builder = $reflection->newInstanceWithoutConstructor();

    $encoderProperty = $reflection->getProperty('encoder');
    $formatterProperty = $reflection->getProperty('claimFormatter');
    $headersProperty = $reflection->getProperty('headers');
    $claimsProperty = $reflection->getProperty('claims');

    $encoderProperty->setValue($builder, $encoder);
    $formatterProperty->setValue($builder, new MicrosecondBasedDateConversion());
    $headersProperty->setValue($builder, ['typ' => 'JWT', 'alg' => 'custom']);
    $claimsProperty->setValue($builder, [RegisteredClaims::AUDIENCE => ['web', 123, 'api']]);

    $updated = $builder->permittedFor('api', 'mobile');
    $updatedClaims = $claimsProperty->getValue($updated);

    expect($updatedClaims[RegisteredClaims::AUDIENCE])->toBe(['web', 'api', 'mobile']);
});

test('permitted for resets non array configured audience values', function (): void {
    $builder = new ReflectionClass(Builder::class)->newInstanceWithoutConstructor();
    $reflection = new ReflectionClass(Builder::class);

    $reflection->getProperty('encoder')->setValue($builder, new class() implements EncoderInterface
    {
        public function jsonEncode(mixed $data): string
        {
            return json_encode($data, JSON_THROW_ON_ERROR);
        }

        public function base64UrlEncode(string $data): string
        {
            return $data;
        }
    });
    $reflection->getProperty('claimFormatter')->setValue($builder, new MicrosecondBasedDateConversion());
    $reflection->getProperty('headers')->setValue($builder, ['typ' => 'JWT', 'alg' => null]);
    $claimsProperty = $reflection->getProperty('claims');
    $claimsProperty->setValue($builder, [RegisteredClaims::AUDIENCE => 'web']);

    $updated = $builder->permittedFor('api');

    expect($claimsProperty->getValue($updated)[RegisteredClaims::AUDIENCE])->toBe(['api']);
});
