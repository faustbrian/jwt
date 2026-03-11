<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Signer;

use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Exceptions\IncompatibleKeyTypeProvided;
use Cline\JWT\Exceptions\TooShortKeyProvided;
use Cline\JWT\Signer\Support\OpenSSL;

use const OPENSSL_KEYTYPE_RSA;

/**
 * Shared OpenSSL-backed implementation for RSA JWT signers.
 *
 * Concrete RSA variants only need to supply the JOSE algorithm identifier and the
 * OpenSSL digest constant. This base class centralizes the common signing and
 * verification flow plus enforcement of RSA key type and minimum modulus size.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
abstract readonly class AbstractRsaSigner extends OpenSSL
{
    private const int MINIMUM_KEY_LENGTH = 2_048;

    /**
     * Sign the canonical JWT payload with the configured RSA private key.
     */
    final public function sign(string $payload, KeyInterface $key): string
    {
        return $this->createSignature($key, $payload);
    }

    /**
     * Verify the JWT signature using the configured RSA public key.
     */
    final public function verify(string $expected, string $payload, KeyInterface $key): bool
    {
        return $this->verifySignature($expected, $payload, $key);
    }

    /**
     * Ensure the resolved OpenSSL key is RSA and meets the minimum modulus length.
     */
    final protected function guardAgainstIncompatibleKey(int $type, int $lengthInBits): void
    {
        if ($type !== OPENSSL_KEYTYPE_RSA) {
            throw IncompatibleKeyTypeProvided::expectedType(
                self::KEY_TYPE_MAP[OPENSSL_KEYTYPE_RSA],
                self::KEY_TYPE_MAP[$type] ?? 'unknown',
            );
        }

        if ($lengthInBits < self::MINIMUM_KEY_LENGTH) {
            throw TooShortKeyProvided::expectedLength(self::MINIMUM_KEY_LENGTH, $lengthInBits);
        }
    }
}
