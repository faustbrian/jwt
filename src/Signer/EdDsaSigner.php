<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Signer;

use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Exceptions\InvalidKeyProvided;
use Cline\JWT\Exceptions\UnparseableKeyProvided;
use SodiumException;

use function sodium_crypto_sign_detached;
use function sodium_crypto_sign_verify_detached;

/**
 * Ed25519-based detached signer for the `EdDSA` JWT algorithm.
 *
 * Unlike the OpenSSL-backed RSA and ECDSA implementations, this signer delegates
 * directly to libsodium. It expects callers to supply raw Ed25519 key material in
 * memory and translates any sodium-level key parsing failures into the package's
 * {@see InvalidKeyProvided} exception so validation semantics stay consistent
 * across all signer families.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class EdDsaSigner implements SignerInterface
{
    /**
     * Return the JOSE algorithm identifier recorded in JWT headers.
     */
    public function algorithmId(): string
    {
        return 'EdDSA';
    }

    /**
     * Produce a detached Ed25519 signature for the canonical JWT payload.
     *
     * @throws InvalidKeyProvided When sodium rejects the provided secret key.
     */
    public function sign(string $payload, KeyInterface $key): string
    {
        try {
            return sodium_crypto_sign_detached($payload, $key->contents());
        } catch (SodiumException $sodiumException) {
            throw UnparseableKeyProvided::because($sodiumException->getMessage(), $sodiumException);
        }
    }

    /**
     * Verify a detached Ed25519 signature against the payload and public key.
     *
     * @throws InvalidKeyProvided When sodium rejects the provided public key.
     */
    public function verify(string $expected, string $payload, KeyInterface $key): bool
    {
        try {
            return sodium_crypto_sign_verify_detached($expected, $payload, $key->contents());
        } catch (SodiumException $sodiumException) {
            throw UnparseableKeyProvided::because($sodiumException->getMessage(), $sodiumException);
        }
    }
}
