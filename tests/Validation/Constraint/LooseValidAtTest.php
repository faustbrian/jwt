<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Validation\Constraint;

use Carbon\CarbonImmutable;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Exceptions\LeewayCannotBeNegative;
use Cline\JWT\Token\Claims;
use Cline\JWT\Token\Headers;
use Cline\JWT\Token\Plain;
use Cline\JWT\Token\RegisteredClaims;
use Cline\JWT\Token\Signature;
use Cline\JWT\Validation\Constraint\LooseValidAt;
use DateInterval;

use function afterEach;
use function beforeEach;
use function test;

beforeEach(function (): void {
    $this->now = CarbonImmutable::parse('2021-07-10 00:00:00');
    CarbonImmutable::setTestNow($this->now);
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

test('construct should raise exception on negative leeway', function (): void {
    $leeway = new DateInterval('PT30S');
    $leeway->invert = 1;

    $this->expectException(LeewayCannotBeNegative::class);
    $this->expectExceptionMessage('Leeway cannot be negative');

    new LooseValidAt($leeway);
});

test('assert should raise exception when token is expired', function (): void {
    $now = $this->now;

    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token is expired');

    new LooseValidAt()->assert(looseValidAtToken([
        RegisteredClaims::ISSUED_AT => $now->modify('-20 seconds'),
        RegisteredClaims::NOT_BEFORE => $now->modify('-10 seconds'),
        RegisteredClaims::EXPIRATION_TIME => $now->modify('-10 seconds'),
    ]));
});

test('assert should raise exception when minimum time is not met', function (): void {
    $now = $this->now;

    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token cannot be used yet');

    new LooseValidAt()->assert(looseValidAtToken([
        RegisteredClaims::ISSUED_AT => $now->modify('-20 seconds'),
        RegisteredClaims::NOT_BEFORE => $now->modify('+40 seconds'),
        RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
    ]));
});

test('assert should raise exception when token was issued in the future', function (): void {
    $now = $this->now;

    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token was issued in the future');

    new LooseValidAt()->assert(looseValidAtToken([
        RegisteredClaims::ISSUED_AT => $now->modify('+20 seconds'),
        RegisteredClaims::NOT_BEFORE => $now->modify('+40 seconds'),
        RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
    ]));
});

test('assert should not raise exception when leeway is used', function (): void {
    $now = $this->now;

    new LooseValidAt(
        new DateInterval('PT6S'),
    )->assert(looseValidAtToken([
        RegisteredClaims::ISSUED_AT => $now->modify('+5 seconds'),
        RegisteredClaims::NOT_BEFORE => $now->modify('+5 seconds'),
        RegisteredClaims::EXPIRATION_TIME => $now->modify('-5 seconds'),
    ]));

    $this->addToAssertionCount(1);
});

test('assert should not raise exception when token is used in the right moment', function (): void {
    $constraint = new LooseValidAt();
    $now = $this->now;

    $constraint->assert(looseValidAtToken([
        RegisteredClaims::ISSUED_AT => $now->modify('-40 seconds'),
        RegisteredClaims::NOT_BEFORE => $now->modify('-20 seconds'),
        RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
    ]));

    $constraint->assert(looseValidAtToken([
        RegisteredClaims::ISSUED_AT => $now,
        RegisteredClaims::NOT_BEFORE => $now,
        RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
    ]));

    $this->addToAssertionCount(2);
});

test('assert should not raise exception when token does not have time claims', function (): void {
    new LooseValidAt()->assert(looseValidAtToken());

    $this->addToAssertionCount(1);
});

function looseValidAtToken(array $claims = [], array $headers = [], ?Signature $signature = null): Plain
{
    return new Plain(
        new Headers($headers, ''),
        new Claims($claims, ''),
        $signature ?? new Signature('sig+hash', 'sig+encoded'),
    );
}
