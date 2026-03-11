<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Validation\Constraint;

use Carbon\CarbonImmutable;
use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Contracts\UnencryptedTokenInterface;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\IssueTokenRequest;
use Cline\JWT\JwtFacade;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Validation\Constraint\SignedWithUntilDate;
use Tests\Signer\FakeSigner;

use function afterEach;
use function test;

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

test('assert should raise exception when constraint usage is not valid anymore', function (): void {
    $now = CarbonImmutable::parse('2023-11-19 22:45:10');
    CarbonImmutable::setTestNow($now);

    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('This constraint was only usable until 2023-11-19T21:45:10+00:00');

    new SignedWithUntilDate(
        new FakeSigner('1'),
        InMemory::plainText('a'),
        $now->modify('-1 hour'),
    )->assert(issueSignedWithUntilDateToken(
        new FakeSigner('1'),
        InMemory::plainText('a'),
    ));
});

test('assert should raise exception when token is not a plain token', function (): void {
    $now = CarbonImmutable::parse('2023-11-19 22:45:10');
    CarbonImmutable::setTestNow($now);

    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('You should pass a plain token');

    new SignedWithUntilDate(
        new FakeSigner('1'),
        InMemory::plainText('a'),
        $now,
    )->assert($this->createStub(TokenInterface::class));
});

test('assert should raise exception when signer is not the same', function (): void {
    $now = CarbonImmutable::parse('2023-11-19 22:45:10');
    $key = InMemory::plainText('a');

    CarbonImmutable::setTestNow($now);
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('Token signer mismatch');

    new SignedWithUntilDate(
        new FakeSigner('1'),
        $key,
        $now,
    )
        ->assert(issueSignedWithUntilDateToken(
            new FakeSigner('2'),
            $key,
        ));
});

test('assert should raise exception when signature is invalid', function (): void {
    $now = CarbonImmutable::parse('2023-11-19 22:45:10');
    $signer = new FakeSigner('1');

    CarbonImmutable::setTestNow($now);
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage('Token signature mismatch');

    new SignedWithUntilDate($signer, InMemory::plainText('a'), $now)
        ->assert(issueSignedWithUntilDateToken($signer, InMemory::plainText('b')));
});

test('assert should not raise exception when signature is valid', function (): void {
    $now = CarbonImmutable::parse('2023-11-19 22:45:10');
    $signer = new FakeSigner('1');
    $key = InMemory::plainText('a');

    CarbonImmutable::setTestNow($now);

    new SignedWithUntilDate($signer, $key, $now)->assert(issueSignedWithUntilDateToken($signer, $key));

    $this->addToAssertionCount(1);
});

test('clock should be optional', function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::parse('2023-11-19 22:45:10'));

    $signer = new FakeSigner('1');
    $key = InMemory::plainText('a');

    new SignedWithUntilDate($signer, $key, CarbonImmutable::now()->addSeconds(10))
        ->assert(issueSignedWithUntilDateToken($signer, $key));

    $this->addToAssertionCount(1);
});

function issueSignedWithUntilDateToken(
    SignerInterface $signer,
    KeyInterface $key,
    ?IssueTokenRequest $request = null,
): UnencryptedTokenInterface {
    return new JwtFacade()->issue($signer, $key, $request ?? new IssueTokenRequest());
}
