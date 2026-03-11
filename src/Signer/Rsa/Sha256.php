<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Signer\Rsa;

use Cline\JWT\Signer\AbstractRsaSigner;

use const OPENSSL_ALGO_SHA256;

/**
 * RSA PKCS#1 signer for the `RS256` JWT algorithm.
 *
 * The shared {@see AbstractRsaSigner} implementation performs all OpenSSL key
 * validation and signature work. This specialization exists to bind that flow
 * to the SHA-256 digest and the `RS256` header value expected by interoperable
 * JWT consumers.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Sha256 extends AbstractRsaSigner
{
    /**
     * Advertise the JOSE algorithm header value written into issued tokens.
     */
    public function algorithmId(): string
    {
        return 'RS256';
    }

    /**
     * Select the OpenSSL digest constant used for signing and verification.
     */
    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }
}
