<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Validation\Constraint;

use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Token\Claims;
use Cline\JWT\Token\Headers;
use Cline\JWT\Token\Plain;
use Cline\JWT\Token\Signature;
use Cline\JWT\Validation\Constraint\SignedWith;

use function beforeEach;
use function test;

beforeEach(function (): void {
    $this->signer = $this->createMock(SignerInterface::class);
    $this->signer->method('algorithmId')->willReturn('RS256');
    $this->key = InMemory::plainText('123');
    $this->signature = new Signature('1234', '5678');
});

test('assert should raise exception when token is not a plain token', function (): void {
    $this->signer->expects($this->never())->method($this->anything());

    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('You should pass a plain token');

    new SignedWith($this->signer, $this->key)->assert($this->createStub(TokenInterface::class));
});

test('assert should raise exception when signer is not the same', function (): void {
    $token = signedWithToken([], ['alg' => 'test'], $this->signature);

    $this->signer->expects($this->never())->method('verify');
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('Token signer mismatch');

    new SignedWith($this->signer, $this->key)->assert($token);
});

test('assert should raise exception when signature is invalid', function (): void {
    $token = signedWithToken([], ['alg' => 'RS256'], $this->signature);

    $this->signer->expects($this->once())
        ->method('verify')
        ->with($this->signature->hash(), $token->payload(), $this->key)
        ->willReturn(false);

    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('Token signature mismatch');

    new SignedWith($this->signer, $this->key)->assert($token);
});

test('assert should not raise exception when signature is valid', function (): void {
    $token = signedWithToken([], ['alg' => 'RS256'], $this->signature);

    $this->signer->expects($this->once())
        ->method('verify')
        ->with($this->signature->hash(), $token->payload(), $this->key)
        ->willReturn(true);

    new SignedWith($this->signer, $this->key)->assert($token);

    $this->addToAssertionCount(1);
});

function signedWithToken(array $claims = [], array $headers = [], ?Signature $signature = null): Plain
{
    return new Plain(
        new Headers($headers, ''),
        new Claims($claims, ''),
        $signature ?? new Signature('sig+hash', 'sig+encoded'),
    );
}
