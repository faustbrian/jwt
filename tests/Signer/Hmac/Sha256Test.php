<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Signer\Hmac;

use Cline\JWT\Exceptions\InvalidKeyProvided;
use Cline\JWT\Signer\Hmac\Sha256;
use Cline\JWT\Signer\Key\InMemory;

use function expect;
use function hash_equals;
use function hash_hmac;
use function mb_strlen;
use function random_bytes;
use function test;

test('algorithm id must be correct', function (): void {
    expect(
        new Sha256()->algorithmId(),
    )->toBe('HS256');
});

test('sign must return a hash according with the algorithm', function (): void {
    $secret = random_bytes(32);
    $expectedHash = hash_hmac('sha256', 'test', $secret, true);
    $signature = new Sha256()->sign('test', InMemory::plainText($secret));

    expect(hash_equals($expectedHash, $signature))->toBeTrue();
});

test('verify must return true when content was signed with the same key', function (): void {
    $secret = random_bytes(32);
    $signature = hash_hmac('sha256', 'test', $secret, true);

    expect(
        new Sha256()->verify($signature, 'test', InMemory::plainText($secret)),
    )->toBeTrue();
});

test('verify must return true when content was signed with a different key', function (): void {
    $signature = hash_hmac('sha256', 'test', random_bytes(32), true);

    expect(
        new Sha256()->verify($signature, 'test', InMemory::plainText(random_bytes(32))),
    )->toBeFalse();
});

test('key must fulfill minimum length requirement', function (): void {
    $secret = random_bytes(31);

    $this->expectException(InvalidKeyProvided::class);
    $this->expectExceptionMessage(
        'Key provided is shorter than 256 bits, only '.(mb_strlen($secret, '8bit') * 8).' bits provided',
    );

    new Sha256()->sign('test', InMemory::plainText($secret));
});
