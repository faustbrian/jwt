<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Signer;

use Cline\JWT\Contracts\Signer\Ecdsa\SignatureConverterInterface;
use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Exceptions\IncompatibleKeyLengthProvided;
use Cline\JWT\Exceptions\IncompatibleKeyTypeProvided;
use Cline\JWT\Signer\Ecdsa\MultibyteStringConverter;
use Cline\JWT\Signer\Support\OpenSSL;

use const OPENSSL_KEYTYPE_EC;

/**
 * Base signer for ECDSA-backed JWT algorithms.
 *
 * OpenSSL emits and expects ASN.1 DER signatures, while JWT compact tokens carry
 * fixed-width concatenated R and S points. This base class composes the shared
 * OpenSSL behavior with a signature converter so concrete curve variants only
 * need to publish their expected key size and point width.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
abstract readonly class AbstractEcdsaSigner extends OpenSSL
{
    /**
     * @param SignatureConverterInterface $converter Converter used to translate between OpenSSL and JWT formats
     */
    public function __construct(
        private SignatureConverterInterface $converter = new MultibyteStringConverter(),
    ) {}

    /**
     * Sign the payload with OpenSSL and normalize the resulting signature for JWT transport.
     */
    final public function sign(string $payload, KeyInterface $key): string
    {
        return $this->converter->fromAsn1(
            $this->createSignature($key, $payload),
            $this->pointLength(),
        );
    }

    /**
     * Convert the JWT signature back to ASN.1 and verify it with OpenSSL.
     */
    final public function verify(string $expected, string $payload, KeyInterface $key): bool
    {
        return $this->verifySignature(
            $this->converter->toAsn1($expected, $this->pointLength()),
            $payload,
            $key,
        );
    }

    /**
     * Return the exact EC key size, in bits, required by this signer variant.
     *
     * @return positive-int
     */
    abstract public function expectedKeyLength(): int;

    /**
     * Return the width, in bytes, of each R/S point in the JWT signature payload.
     *
     * @return positive-int
     */
    abstract public function pointLength(): int;

    /**
     * Ensure the OpenSSL key is an EC key with the exact curve width this signer expects.
     */
    final protected function guardAgainstIncompatibleKey(int $type, int $lengthInBits): void
    {
        if ($type !== OPENSSL_KEYTYPE_EC) {
            throw IncompatibleKeyTypeProvided::expectedType(
                self::KEY_TYPE_MAP[OPENSSL_KEYTYPE_EC],
                self::KEY_TYPE_MAP[$type] ?? 'unknown',
            );
        }

        $expectedKeyLength = $this->expectedKeyLength();

        if ($lengthInBits !== $expectedKeyLength) {
            throw IncompatibleKeyLengthProvided::expectedLength($expectedKeyLength, $lengthInBits);
        }
    }
}
