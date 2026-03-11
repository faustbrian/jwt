<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Token;

use Cline\JWT\Exceptions\InvalidProfileConfiguration;
use Cline\JWT\Token\RegisteredClaims;
use Cline\JWT\Token\RegisteredHeaders;
use ReflectionClass;

use function expect;
use function test;

test('registered constant holder classes expose expected grouped constants and are not instantiable', function (): void {
    $claimsClass = new ReflectionClass(RegisteredClaims::class);
    $headersClass = new ReflectionClass(RegisteredHeaders::class);

    expect(RegisteredClaims::ALL)->toContain(
        RegisteredClaims::AUDIENCE,
        RegisteredClaims::EXPIRATION_TIME,
        RegisteredClaims::ID,
        RegisteredClaims::ISSUED_AT,
        RegisteredClaims::ISSUER,
        RegisteredClaims::NOT_BEFORE,
        RegisteredClaims::SUBJECT,
    )->and(RegisteredClaims::DATE_CLAIMS)->toBe([
        RegisteredClaims::ISSUED_AT,
        RegisteredClaims::NOT_BEFORE,
        RegisteredClaims::EXPIRATION_TIME,
    ])->and(RegisteredHeaders::ALGORITHM)->toBe('alg')
        ->and(RegisteredHeaders::CONTENT_TYPE)->toBe('cty')
        ->and(RegisteredHeaders::KEY_ID)->toBe('kid')
        ->and(RegisteredHeaders::TYPE)->toBe('typ');

    expect($claimsClass->getConstructor()?->isPrivate())->toBeTrue()
        ->and($headersClass->getConstructor()?->isPrivate())->toBeTrue();

    $claimsInstance = $claimsClass->newInstanceWithoutConstructor();
    $headersInstance = $headersClass->newInstanceWithoutConstructor();

    $claimsClass->getConstructor()?->invoke($claimsInstance);
    $headersClass->getConstructor()?->invoke($headersInstance);
});

test('invalid profile configuration factory builds the expected message', function (): void {
    expect(InvalidProfileConfiguration::forProfile('api', 'bad signer')->getMessage())
        ->toBe('JWT profile "api" is invalid: bad signer');
});
