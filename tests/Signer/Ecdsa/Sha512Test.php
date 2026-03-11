<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Signer\Ecdsa;

use Cline\JWT\Exceptions\InvalidKeyProvided;
use Cline\JWT\Signer\Ecdsa\MultibyteStringConverter;
use Cline\JWT\Signer\Ecdsa\Sha512;
use OpenSSLAsymmetricKey;
use Tests\Keys;

use const OPENSSL_ALGO_SHA512;

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
    expect(ecdsaSha512Signer()->algorithmId())->toBe('ES512');
});

test('signature algorithm must be correct', function (): void {
    expect(ecdsaSha512Signer()->algorithm())->toBe(OPENSSL_ALGO_SHA512);
});

test('point length must be correct', function (): void {
    expect(ecdsaSha512Signer()->pointLength())->toBe(132);
});

test('expected key length must be correct', function (): void {
    expect(ecdsaSha512Signer()->expectedKeyLength())->toBe(521);
});

test('sign should return the a hash based on the open ssl signature', function (): void {
    $payload = 'testing';
    $signer = ecdsaSha512Signer();
    $signature = $signer->sign($payload, $this::$ecdsaKeys['private_ec512']);
    $publicKey = openssl_pkey_get_public($this::$ecdsaKeys['public_ec512']->contents());

    expect($publicKey)->toBeInstanceOf(OpenSSLAsymmetricKey::class);
    expect(openssl_verify(
        $payload,
        ecdsaSha512Points()->toAsn1($signature, $signer->pointLength()),
        $publicKey,
        OPENSSL_ALGO_SHA512,
    ))->toBe(1);
});

test('sign should raise an exception when key length is not the expected one', function (string $keyId, int $keyLength): void {
    expect($this::$ecdsaKeys)->toHaveKey($keyId);

    $this->expectException(InvalidKeyProvided::class);
    $this->expectExceptionMessage(
        'The length of the provided key is different than 521 bits, '.$keyLength.' bits provided',
    );

    ecdsaSha512Signer()->sign('testing', $this::$ecdsaKeys[$keyId]);
})->with([
    '256 bits' => ['private', 256],
    '384 bits' => ['private_ec384', 384],
]);

test('sign should raise an exception when key type is not ec', function (): void {
    $this->expectException(InvalidKeyProvided::class);
    $this->expectExceptionMessage('The type of the provided key is not "EC", "RSA" provided');

    ecdsaSha512Signer()->sign('testing', $this::$rsaKeys['private']);
});

test('verify should delegate to ecdsa signer using public key', function (): void {
    $payload = 'testing';
    $privateKey = openssl_pkey_get_private($this::$ecdsaKeys['private_ec512']->contents());
    $signer = ecdsaSha512Signer();
    $signature = '';

    expect($privateKey)->toBeInstanceOf(OpenSSLAsymmetricKey::class);
    openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA512);

    expect($signer->verify(
        ecdsaSha512Points()->fromAsn1($signature, $signer->pointLength()),
        $payload,
        $this::$ecdsaKeys['public_ec512'],
    ))->toBeTrue();
});

function ecdsaSha512Points(): MultibyteStringConverter
{
    return new MultibyteStringConverter();
}

function ecdsaSha512Signer(): Sha512
{
    return new Sha512(ecdsaSha512Points());
}
