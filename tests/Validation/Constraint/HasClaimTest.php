<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Validation\Constraint;

use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Exceptions\CannotValidateARegisteredClaim;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Token\Claims;
use Cline\JWT\Token\Headers;
use Cline\JWT\Token\Plain;
use Cline\JWT\Token\RegisteredClaims;
use Cline\JWT\Token\Signature;
use Cline\JWT\Validation\Constraint\HasClaim;

use function test;

test('registered claims cannot be validated using this constraint', function (string $claim): void {
    $this->expectException(CannotValidateARegisteredClaim::class);
    $this->expectExceptionMessage(
        'The claim "'.$claim.'" is a registered claim, another constraint must be used to validate its value',
    );

    new HasClaim($claim);
})->with(RegisteredClaims::ALL);

test('assert should raise exception when claim is not set', function (): void {
    $constraint = new HasClaim('claimId');

    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token does not have the claim "claimId"');

    $constraint->assert(hasClaimToken());
});

test('assert should raise exception when token is not a plain token', function (): void {
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('You should pass a plain token');

    new HasClaim('claimId')->assert($this->createStub(TokenInterface::class));
});

test('assert should not raise exception when claim matches', function (): void {
    new HasClaim('claimId')->assert(hasClaimToken(['claimId' => 'claimValue']));

    $this->addToAssertionCount(1);
});

function hasClaimToken(array $claims = [], array $headers = [], ?Signature $signature = null): Plain
{
    return new Plain(
        new Headers($headers, ''),
        new Claims($claims, ''),
        $signature ?? new Signature('sig+hash', 'sig+encoded'),
    );
}
