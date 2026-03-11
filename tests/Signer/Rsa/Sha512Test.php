<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Signer\Rsa;

use Cline\JWT\Exceptions\InvalidKeyProvided;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Signer\Rsa\Sha512;
use OpenSSLAsymmetricKey;
use Tests\Keys;

use const OPENSSL_ALGO_SHA512;
use const PHP_EOL;

use function afterEach;
use function expect;
use function openssl_error_string;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;
use function test;
use function uses;

uses(Keys::class);

afterEach(function (): void {
    while (openssl_error_string()) {
    }
});

test('algorithm id must be correct', function (): void {
    expect(
        new Sha512()->algorithmId(),
    )->toBe('RS512');
});

test('signature algorithm must be correct', function (): void {
    expect(
        new Sha512()->algorithm(),
    )->toBe(OPENSSL_ALGO_SHA512);
});

test('sign should return a valid openssl signature', function (): void {
    $payload = 'testing';
    $signature = new Sha512()->sign($payload, $this::$rsaKeys['private']);
    $publicKey = openssl_pkey_get_public($this::$rsaKeys['public']->contents());

    expect($publicKey)->toBeInstanceOf(OpenSSLAsymmetricKey::class);
    expect(openssl_verify($payload, $signature, $publicKey, OPENSSL_ALGO_SHA512))->toBe(1);
});

test('sign should raise an exception when key is not parseable', function (): void {
    $this->expectException(InvalidKeyProvided::class);
    $this->expectExceptionMessage('It was not possible to parse your key, reason:'.PHP_EOL.'* error:');

    new Sha512()->sign('testing', InMemory::plainText('blablabla'));
});

test('all open ssl errors should be on the error message', function (): void {
    openssl_pkey_get_private('blahblah');

    $this->expectException(InvalidKeyProvided::class);
    $this->expectExceptionMessageMatches('/^.* reason:('.PHP_EOL.'\* error:.*){2,}/');

    new Sha512()->sign('testing', InMemory::plainText('blablabla'));
});

test('sign should raise an exception when key type is not rsa', function (): void {
    $this->expectException(InvalidKeyProvided::class);
    $this->expectExceptionMessage('The type of the provided key is not "RSA", "EC" provided');

    new Sha512()->sign('testing', $this::$ecdsaKeys['private']);
});

test('sign should raise an exception when key length is below minimum', function (): void {
    $this->expectException(InvalidKeyProvided::class);
    $this->expectExceptionMessage('Key provided is shorter than 2048 bits, only 512 bits provided');

    new Sha512()->sign('testing', $this::$rsaKeys['private_short']);
});

test('verify should return true when signature is valid', function (): void {
    $payload = 'testing';
    $privateKey = openssl_pkey_get_private($this::$rsaKeys['private']->contents());
    $signature = '';

    expect($privateKey)->toBeInstanceOf(OpenSSLAsymmetricKey::class);
    openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA512);

    expect(
        new Sha512()->verify($signature, $payload, $this::$rsaKeys['public']),
    )->toBeTrue();
});

test('verify should raise an exception when key is not parseable', function (): void {
    $this->expectException(InvalidKeyProvided::class);
    $this->expectExceptionMessage('It was not possible to parse your key, reason:'.PHP_EOL.'* error:');

    new Sha512()->verify('testing', 'testing', InMemory::plainText('blablabla'));
});

test('verify should raise an exception when key type is not rsa', function (): void {
    $this->expectException(InvalidKeyProvided::class);
    $this->expectExceptionMessage('It was not possible to parse your key');

    new Sha512()->verify('testing', 'testing', $this::$ecdsaKeys['private']);
});
