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
use Cline\JWT\Validation\Constraint\PermittedFor;

use function test;

test('assert should raise exception when audience is not set', function (): void {
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token is not allowed to be used by this audience');

    new PermittedFor('test.com')->assert(permittedForToken());
});

test('assert should raise exception when audience value does not match', function (): void {
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token is not allowed to be used by this audience');

    new PermittedFor('test.com')->assert(permittedForToken([RegisteredClaims::AUDIENCE => ['aa.com']]));
});

test('assert should raise exception when audience type does not match', function (): void {
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token is not allowed to be used by this audience');

    new PermittedFor('123')->assert(permittedForToken([RegisteredClaims::AUDIENCE => [123]]));
});

test('assert should not raise exception when audience matches', function (): void {
    new PermittedFor('test.com')->assert(
        permittedForToken([RegisteredClaims::AUDIENCE => ['aa.com', 'test.com']]),
    );

    $this->addToAssertionCount(1);
});

function permittedForToken(array $claims = [], array $headers = [], ?Signature $signature = null): Plain
{
    return new Plain(
        new Headers($headers, ''),
        new Claims($claims, ''),
        $signature ?? new Signature('sig+hash', 'sig+encoded'),
    );
}
