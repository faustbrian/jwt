<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Validation\Constraint;

use Carbon\CarbonImmutable;
use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Exceptions\LeewayCannotBeNegative;
use Cline\JWT\Token\Claims;
use Cline\JWT\Token\Headers;
use Cline\JWT\Token\Plain;
use Cline\JWT\Token\RegisteredClaims;
use Cline\JWT\Token\Signature;
use Cline\JWT\Validation\Constraint\StrictValidAt;
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

    new StrictValidAt($leeway);
});

test('assert should raise exception when token is expired', function (): void {
    $now = $this->now;

    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token is expired');

    new StrictValidAt()->assert(strictValidAtToken([
        RegisteredClaims::ISSUED_AT => $now->modify('-20 seconds'),
        RegisteredClaims::NOT_BEFORE => $now->modify('-10 seconds'),
        RegisteredClaims::EXPIRATION_TIME => $now->modify('-10 seconds'),
    ]));
});

test('assert should raise exception when minimum time is not met', function (): void {
    $now = $this->now;

    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token cannot be used yet');

    new StrictValidAt()->assert(strictValidAtToken([
        RegisteredClaims::ISSUED_AT => $now->modify('-20 seconds'),
        RegisteredClaims::NOT_BEFORE => $now->modify('+40 seconds'),
        RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
    ]));
});

test('assert should raise exception when token was issued in the future', function (): void {
    $now = $this->now;

    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token was issued in the future');

    new StrictValidAt()->assert(strictValidAtToken([
        RegisteredClaims::ISSUED_AT => $now->modify('+20 seconds'),
        RegisteredClaims::NOT_BEFORE => $now->modify('+40 seconds'),
        RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
    ]));
});

test('assert should not raise exception when leeway is used', function (): void {
    $now = $this->now;

    new StrictValidAt(
        new DateInterval('PT6S'),
    )->assert(strictValidAtToken([
        RegisteredClaims::ISSUED_AT => $now->modify('+5 seconds'),
        RegisteredClaims::NOT_BEFORE => $now->modify('+5 seconds'),
        RegisteredClaims::EXPIRATION_TIME => $now->modify('-5 seconds'),
    ]));

    $this->addToAssertionCount(1);
});

test('assert should not raise exception when token is used in the right moment', function (): void {
    $constraint = new StrictValidAt();
    $now = $this->now;

    $constraint->assert(strictValidAtToken([
        RegisteredClaims::ISSUED_AT => $now->modify('-40 seconds'),
        RegisteredClaims::NOT_BEFORE => $now->modify('-20 seconds'),
        RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
    ]));

    $constraint->assert(strictValidAtToken([
        RegisteredClaims::ISSUED_AT => $now,
        RegisteredClaims::NOT_BEFORE => $now,
        RegisteredClaims::EXPIRATION_TIME => $now->modify('+60 seconds'),
    ]));

    $this->addToAssertionCount(2);
});

test('assert should raise exception when token is not a plain token', function (): void {
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('You should pass a plain token');

    new StrictValidAt()->assert($this->createStub(TokenInterface::class));
});

test('assert should raise exception when iat claim is missing', function (): void {
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('"Issued At" claim missing');

    new StrictValidAt()->assert(strictValidAtToken());
});

test('assert should raise exception when nbf claim is missing', function (): void {
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('"Not Before" claim missing');

    new StrictValidAt()->assert(strictValidAtToken([
        RegisteredClaims::ISSUED_AT => $this->now->modify('-5 seconds'),
    ]));
});

test('assert should raise exception when exp claim is missing', function (): void {
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('"Expiration Time" claim missing');

    new StrictValidAt()->assert(strictValidAtToken([
        RegisteredClaims::ISSUED_AT => $this->now->modify('-5 seconds'),
        RegisteredClaims::NOT_BEFORE => $this->now->modify('-5 seconds'),
    ]));
});

function strictValidAtToken(array $claims = [], array $headers = [], ?Signature $signature = null): Plain
{
    return new Plain(
        new Headers($headers, ''),
        new Claims($claims, ''),
        $signature ?? new Signature('sig+hash', 'sig+encoded'),
    );
}
