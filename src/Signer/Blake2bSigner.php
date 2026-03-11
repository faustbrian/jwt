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
use Cline\JWT\Exceptions\TooShortKeyProvided;

use function hash_equals;
use function sodium_crypto_generichash;
use function strlen;

/**
 * JWT signer backed by libsodium's BLAKE2b generic hash.
 *
 * This implementation behaves like an HMAC-style symmetric signer: the same
 * secret key is used to create and verify the signature, and callers are
 * expected to provide sufficiently strong shared key material. The signer
 * advertises a non-standard `BLAKE2B` algorithm identifier for ecosystems that
 * coordinate this algorithm out of band.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Blake2bSigner implements SignerInterface
{
    private const int MINIMUM_KEY_LENGTH_IN_BITS = 256;

    /**
     * Return the JOSE-style identifier written into the token header.
     */
    public function algorithmId(): string
    {
        return 'BLAKE2B';
    }

    /**
     * Create a BLAKE2b MAC for the payload using the shared secret key.
     *
     * Keys shorter than 256 bits are rejected up front to avoid weak symmetric
     * configurations entering the token pipeline.
     *
     * @throws InvalidKeyProvided
     */
    public function sign(string $payload, KeyInterface $key): string
    {
        $actualKeyLength = 8 * strlen($key->contents());

        if ($actualKeyLength < self::MINIMUM_KEY_LENGTH_IN_BITS) {
            throw TooShortKeyProvided::expectedLength(self::MINIMUM_KEY_LENGTH_IN_BITS, $actualKeyLength);
        }

        return sodium_crypto_generichash($payload, $key->contents());
    }

    /**
     * Verify the payload by recomputing the keyed hash and comparing it in constant time.
     *
     * @throws InvalidKeyProvided
     */
    public function verify(string $expected, string $payload, KeyInterface $key): bool
    {
        return hash_equals($expected, $this->sign($payload, $key));
    }
}
