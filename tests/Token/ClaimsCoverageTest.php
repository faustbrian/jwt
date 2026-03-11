<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Token;

use Cline\JWT\Token\Claims;
use Cline\JWT\Token\RegisteredClaims;

use function expect;
use function test;

test('claims registered accessors return null or filtered defaults for invalid shapes', function (): void {
    $claims = new Claims([
        RegisteredClaims::AUDIENCE => 'web',
        RegisteredClaims::ISSUER => 123,
        RegisteredClaims::SUBJECT => 456,
        RegisteredClaims::ID => false,
        RegisteredClaims::ISSUED_AT => 'invalid',
        RegisteredClaims::NOT_BEFORE => 'invalid',
        RegisteredClaims::EXPIRATION_TIME => 'invalid',
    ], 'claims');

    expect($claims->audiences())->toBe([])
        ->and($claims->issuer())->toBeNull()
        ->and($claims->subject())->toBeNull()
        ->and($claims->identifier())->toBeNull()
        ->and($claims->issuedAt())->toBeNull()
        ->and($claims->notBefore())->toBeNull()
        ->and($claims->expiresAt())->toBeNull();
});

test('claims audience accessor filters non string list members', function (): void {
    $claims = new Claims([
        RegisteredClaims::AUDIENCE => ['web', 123, 'api'],
    ], 'claims');

    expect($claims->audiences())->toBe(['web', 'api']);
});

test('claims expose all values and positive has checks', function (): void {
    $claims = new Claims(['tenant' => 'acme'], 'claims');

    expect($claims->has('tenant'))->toBeTrue()
        ->and($claims->all())->toBe(['tenant' => 'acme']);
});
