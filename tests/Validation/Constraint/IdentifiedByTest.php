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
use Cline\JWT\Validation\Constraint\IdentifiedBy;

use function test;

test('assert should raise exception when id is not set', function (): void {
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token is not identified with the expected ID');

    new IdentifiedBy('123456')->assert(identifiedByToken());
});

test('assert should raise exception when id does not match', function (): void {
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token is not identified with the expected ID');

    new IdentifiedBy('123456')->assert(identifiedByToken([RegisteredClaims::ID => 15]));
});

test('assert should not raise exception when id matches', function (): void {
    new IdentifiedBy('123456')->assert(identifiedByToken([RegisteredClaims::ID => '123456']));

    $this->addToAssertionCount(1);
});

function identifiedByToken(array $claims = [], array $headers = [], ?Signature $signature = null): Plain
{
    return new Plain(
        new Headers($headers, ''),
        new Claims($claims, ''),
        $signature ?? new Signature('sig+hash', 'sig+encoded'),
    );
}
