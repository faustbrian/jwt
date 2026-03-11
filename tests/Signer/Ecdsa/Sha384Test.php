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
use Cline\JWT\Signer\Ecdsa\Sha384;
use OpenSSLAsymmetricKey;
use Tests\Keys;

use const OPENSSL_ALGO_SHA384;

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
    expect(ecdsaSha384Signer()->algorithmId())->toBe('ES384');
});

test('signature algorithm must be correct', function (): void {
    expect(ecdsaSha384Signer()->algorithm())->toBe(OPENSSL_ALGO_SHA384);
});

test('point length must be correct', function (): void {
    expect(ecdsaSha384Signer()->pointLength())->toBe(96);
});

test('expected key length must be correct', function (): void {
    expect(ecdsaSha384Signer()->expectedKeyLength())->toBe(384);
});

test('sign should return the a hash based on the open ssl signature', function (): void {
    $payload = 'testing';
    $signer = ecdsaSha384Signer();
    $signature = $signer->sign($payload, $this::$ecdsaKeys['private_ec384']);
    $publicKey = openssl_pkey_get_public($this::$ecdsaKeys['public_ec384']->contents());

    expect($publicKey)->toBeInstanceOf(OpenSSLAsymmetricKey::class);
    expect(openssl_verify(
        $payload,
        ecdsaSha384Points()->toAsn1($signature, $signer->pointLength()),
        $publicKey,
        OPENSSL_ALGO_SHA384,
    ))->toBe(1);
});

test('sign should raise an exception when key length is not the expected one', function (string $keyId, int $keyLength): void {
    expect($this::$ecdsaKeys)->toHaveKey($keyId);

    $this->expectException(InvalidKeyProvided::class);
    $this->expectExceptionMessage(
        'The length of the provided key is different than 384 bits, '.$keyLength.' bits provided',
    );

    ecdsaSha384Signer()->sign('testing', $this::$ecdsaKeys[$keyId]);
})->with([
    '256 bits' => ['private', 256],
    '521 bits' => ['private_ec512', 521],
]);

test('sign should raise an exception when key type is not ec', function (): void {
    $this->expectException(InvalidKeyProvided::class);
    $this->expectExceptionMessage('The type of the provided key is not "EC", "RSA" provided');

    ecdsaSha384Signer()->sign('testing', $this::$rsaKeys['private']);
});

test('verify should delegate to ecdsa signer using public key', function (): void {
    $payload = 'testing';
    $privateKey = openssl_pkey_get_private($this::$ecdsaKeys['private_ec384']->contents());
    $signer = ecdsaSha384Signer();
    $signature = '';

    expect($privateKey)->toBeInstanceOf(OpenSSLAsymmetricKey::class);
    openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA384);

    expect($signer->verify(
        ecdsaSha384Points()->fromAsn1($signature, $signer->pointLength()),
        $payload,
        $this::$ecdsaKeys['public_ec384'],
    ))->toBeTrue();
});

function ecdsaSha384Points(): MultibyteStringConverter
{
    return new MultibyteStringConverter();
}

function ecdsaSha384Signer(): Sha384
{
    return new Sha384(ecdsaSha384Points());
}
