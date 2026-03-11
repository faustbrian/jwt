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
use Cline\JWT\Validation\Constraint\RelatedTo;

use function test;

test('assert should raise exception when subject is not set', function (): void {
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token is not related to the expected subject');

    new RelatedTo('user-auth')->assert(relatedToToken());
});

test('assert should raise exception when subject does not match', function (): void {
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('The token is not related to the expected subject');

    new RelatedTo('user-auth')->assert(relatedToToken([RegisteredClaims::SUBJECT => 'password-recovery']));
});

test('assert should not raise exception when subject matches', function (): void {
    new RelatedTo('user-auth')->assert(relatedToToken([RegisteredClaims::SUBJECT => 'user-auth']));

    $this->addToAssertionCount(1);
});

function relatedToToken(array $claims = [], array $headers = [], ?Signature $signature = null): Plain
{
    return new Plain(
        new Headers($headers, ''),
        new Claims($claims, ''),
        $signature ?? new Signature('sig+hash', 'sig+encoded'),
    );
}
