<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Signer\Hmac;

use Cline\JWT\Exceptions\InvalidKeyProvided;
use Cline\JWT\Signer\Hmac\Sha384;
use Cline\JWT\Signer\Key\InMemory;

use function expect;
use function hash_equals;
use function hash_hmac;
use function mb_strlen;
use function random_bytes;
use function test;

test('algorithm id must be correct', function (): void {
    expect(
        new Sha384()->algorithmId(),
    )->toBe('HS384');
});

test('sign must return a hash according with the algorithm', function (): void {
    $secret = random_bytes(48);
    $expectedHash = hash_hmac('sha384', 'test', $secret, true);
    $signature = new Sha384()->sign('test', InMemory::plainText($secret));

    expect(hash_equals($expectedHash, $signature))->toBeTrue();
});

test('verify must return true when content was signed with the same key', function (): void {
    $secret = random_bytes(48);
    $signature = hash_hmac('sha384', 'test', $secret, true);

    expect(
        new Sha384()->verify($signature, 'test', InMemory::plainText($secret)),
    )->toBeTrue();
});

test('verify must return true when content was signed with a different key', function (): void {
    $signature = hash_hmac('sha384', 'test', random_bytes(48), true);

    expect(
        new Sha384()->verify($signature, 'test', InMemory::plainText(random_bytes(48))),
    )->toBeFalse();
});

test('key must fulfill minimum length requirement', function (): void {
    $secret = random_bytes(47);

    $this->expectException(InvalidKeyProvided::class);
    $this->expectExceptionMessage(
        'Key provided is shorter than 384 bits, only '.(mb_strlen($secret, '8bit') * 8).' bits provided',
    );

    new Sha384()->sign('test', InMemory::plainText($secret));
});
