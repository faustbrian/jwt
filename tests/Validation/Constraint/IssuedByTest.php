<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Validation\Constraint;

use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Token\Claims;
use Cline\JWT\Token\Headers;
use Cline\JWT\Token\Plain;
use Cline\JWT\Token\RegisteredClaims;
use Cline\JWT\Token\Signature;
use Cline\JWT\Validation\Constraint\IssuedBy;

use function test;

test('assert should raise exception when issuer is not set', function (): void {
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token was not issued by the given issuers');

    new IssuedBy('test.com', 'test.net')->assert(issuedByToken());
});

test('assert should raise exception when issuer value does not match', function (): void {
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token was not issued by the given issuers');

    new IssuedBy('test.com', 'test.net')->assert(issuedByToken([RegisteredClaims::ISSUER => 'example.com']));
});

test('assert should raise exception when issuer type value does not match', function (): void {
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token was not issued by the given issuers');

    new IssuedBy('test.com', '123')->assert(issuedByToken([RegisteredClaims::ISSUER => 123]));
});

test('assert should not raise exception when issuer matches', function (): void {
    new IssuedBy('test.com', 'test.net')->assert(issuedByToken([RegisteredClaims::ISSUER => 'test.com']));

    $this->addToAssertionCount(1);
});

function issuedByToken(array $claims = [], array $headers = [], ?Signature $signature = null): Plain
{
    return new Plain(
        new Headers($headers, ''),
        new Claims($claims, ''),
        $signature ?? new Signature('sig+hash', 'sig+encoded'),
    );
}
