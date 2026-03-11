<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Signer\Rsa;

use Cline\JWT\Signer\AbstractRsaSigner;

use const OPENSSL_ALGO_SHA512;

/**
 * RSA PKCS#1 signer for the `RS512` JWT algorithm.
 *
 * This concrete type supplies the JOSE algorithm identifier and OpenSSL digest
 * constant consumed by {@see AbstractRsaSigner}. The inherited implementation
 * handles key parsing, RSA key-type enforcement, and the package-wide minimum
 * modulus length requirement, while this class anchors the variant to SHA-512.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Sha512 extends AbstractRsaSigner
{
    /**
     * Advertise the JOSE algorithm header value written into issued tokens.
     */
    public function algorithmId(): string
    {
        return 'RS512';
    }

    /**
     * Select the OpenSSL digest constant used for signing and verification.
     */
    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA512;
    }
}
