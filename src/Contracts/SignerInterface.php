<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts;

use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Exceptions\CannotSignPayload;
use Cline\JWT\Exceptions\ConversionFailed;
use Cline\JWT\Exceptions\InvalidKeyProvided;
use NoDiscard;

/**
 * Signing and verification contract for JWT signature algorithms.
 *
 * Implementations sit at the boundary between token assembly and the underlying
 * cryptographic primitive. They are responsible for advertising the JOSE `alg`
 * identifier that will be written into the token header, producing the raw
 * signature bytes for a payload, and verifying a previously emitted signature
 * against the same payload and key material.
 *
 * The interface is intentionally low level: callers provide the already encoded
 * signing input and the resolved key so implementations can focus on algorithm
 * correctness rather than token orchestration.
 *
 * @immutable
 * @author Brian Faust <brian@cline.sh>
 */
interface SignerInterface
{
    /**
     * Get the JOSE algorithm identifier published for this signer.
     *
     * The returned value is written into the token header before signing and is
     * later used by validators to ensure the token was produced with the expected
     * cryptographic algorithm.
     *
     * @return non-empty-string
     */
    public function algorithmId(): string;

    /**
     * Sign the encoded JWT payload with the provided key material.
     *
     * The payload is the canonical `base64url(header).base64url(claims)` string
     * assembled by the token builder. Implementations must return the raw binary
     * signature bytes, leaving any base64url transport encoding to higher layers.
     *
     * @param non-empty-string $payload
     *
     * @throws CannotSignPayload  When payload signing fails.
     * @throws InvalidKeyProvided When the supplied key is empty, malformed, or
     *                            incompatible with the signer.
     * @throws ConversionFailed   When signature could not be converted.
     *
     * @return non-empty-string
     */
    #[NoDiscard()]
    public function sign(string $payload, KeyInterface $key): string;

    /**
     * Verify a previously generated signature against the payload and key.
     *
     * Implementations must apply the same algorithm-specific normalization used
     * during signing so verification semantics remain symmetric across HMAC, RSA,
     * ECDSA, and other supported algorithms.
     *
     * @param non-empty-string $expected
     * @param non-empty-string $payload
     *
     * @throws InvalidKeyProvided When the supplied key is empty, malformed, or
     *                            incompatible with the signer.
     * @throws ConversionFailed   When signature could not be converted.
     */
    #[NoDiscard()]
    public function verify(string $expected, string $payload, KeyInterface $key): bool;
}
