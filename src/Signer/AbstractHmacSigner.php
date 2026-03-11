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
use function hash_hmac;
use function strlen;

/**
 * Shared implementation for symmetric HMAC-based JWT signers.
 *
 * Concrete subclasses only need to describe the hash algorithm and minimum key
 * length for their variant. This base class centralizes key-size enforcement,
 * raw binary signature generation, and constant-time verification so all HMAC
 * signers behave consistently.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
abstract readonly class AbstractHmacSigner implements SignerInterface
{
    /**
     * Sign the payload with the configured HMAC algorithm after validating key strength.
     *
     * @throws InvalidKeyProvided
     */
    final public function sign(string $payload, KeyInterface $key): string
    {
        $actualKeyLength = 8 * strlen($key->contents());
        $expectedKeyLength = $this->minimumBitsLengthForKey();

        if ($actualKeyLength < $expectedKeyLength) {
            throw TooShortKeyProvided::expectedLength($expectedKeyLength, $actualKeyLength);
        }

        return hash_hmac($this->algorithm(), $payload, $key->contents(), true);
    }

    /**
     * Verify a signature by recomputing the HMAC and comparing it in constant time.
     *
     * @throws InvalidKeyProvided
     */
    final public function verify(string $expected, string $payload, KeyInterface $key): bool
    {
        return hash_equals($expected, $this->sign($payload, $key));
    }

    /**
     * Return the hash name understood by `hash_hmac()`.
     *
     * @return non-empty-string
     */
    abstract public function algorithm(): string;

    /**
     * Return the minimum acceptable key length in bits for this variant.
     *
     * @return positive-int
     */
    abstract public function minimumBitsLengthForKey(): int;
}
