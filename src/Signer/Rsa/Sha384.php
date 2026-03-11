<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Signer\Rsa;

use Cline\JWT\Signer\AbstractRsaSigner;

use const OPENSSL_ALGO_SHA384;

/**
 * RSA PKCS#1 signer for the `RS384` JWT algorithm.
 *
 * This class contributes only the algorithm metadata specific to the SHA-384
 * RSA profile. Everything else, including OpenSSL key validation and minimum
 * RSA key-length enforcement, is inherited from {@see AbstractRsaSigner}.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Sha384 extends AbstractRsaSigner
{
    /**
     * Advertise the JOSE algorithm header value written into issued tokens.
     */
    public function algorithmId(): string
    {
        return 'RS384';
    }

    /**
     * Select the OpenSSL digest constant used for signing and verification.
     */
    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA384;
    }
}
