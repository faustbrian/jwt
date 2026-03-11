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
use Cline\JWT\Contracts\UnencryptedTokenInterface;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\IssueTokenRequest;
use Cline\JWT\JwtFacade;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Validation\Constraint\SignedWithOneInSet;
use Cline\JWT\Validation\Constraint\SignedWithUntilDate;
use Tests\Signer\FakeSigner;

use const PHP_EOL;

use function afterEach;
use function test;

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

test('exception should be raised when signature is not verified by all constraints', function (): void {
    $now = CarbonImmutable::parse('2023-11-19 22:20:00');
    $signer = new FakeSigner('123');

    CarbonImmutable::setTestNow($now);
    $this->expectException(ConstraintViolation::class);
    $this->expectExceptionMessage(
        'It was not possible to verify the signature of the token, reasons:'
        .PHP_EOL.'- Token signature mismatch'
        .PHP_EOL.'- This constraint was only usable until 2023-11-19T22:18:00+00:00',
    );

    new SignedWithOneInSet(
        new SignedWithUntilDate($signer, InMemory::plainText('b'), $now),
        new SignedWithUntilDate($signer, InMemory::plainText('c'), $now->modify('-2 minutes')),
    )->assert(issueSignedWithOneInSetToken($signer, InMemory::plainText('a')));
});

test('assert should not raise exceptions when signature is verified by at least one constraint', function (): void {
    $now = CarbonImmutable::parse('2023-11-19 22:20:00');
    $signer = new FakeSigner('123');

    CarbonImmutable::setTestNow($now);

    new SignedWithOneInSet(
        new SignedWithUntilDate($signer, InMemory::plainText('b'), $now),
        new SignedWithUntilDate($signer, InMemory::plainText('c'), $now->modify('-2 minutes')),
        new SignedWithUntilDate($signer, InMemory::plainText('a'), $now),
    )->assert(issueSignedWithOneInSetToken($signer, InMemory::plainText('a')));

    $this->addToAssertionCount(1);
});

function issueSignedWithOneInSetToken(
    SignerInterface $signer,
    KeyInterface $key,
    ?IssueTokenRequest $request = null,
): UnencryptedTokenInterface {
    return new JwtFacade()->issue($signer, $key, $request ?? new IssueTokenRequest());
}
