<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Signer\Ecdsa;

use Cline\JWT\Signer\AbstractEcdsaSigner;

use const OPENSSL_ALGO_SHA256;

/**
 * ECDSA signer for the `ES256` JWT algorithm.
 *
 * This variant wires the shared {@see AbstractEcdsaSigner} behavior to the
 * P-256 curve and SHA-256 digest. The concrete metadata here determines both
 * the JOSE `alg` header value and the exact signature width expected when
 * converting between OpenSSL's ASN.1 output and JWT's concatenated R/S format.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Sha256 extends AbstractEcdsaSigner
{
    /**
     * Advertise the JOSE algorithm header value written into issued tokens.
     */
    public function algorithmId(): string
    {
        return 'ES256';
    }

    /**
     * Select the OpenSSL digest constant used with the EC private/public key.
     */
    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }

    /**
     * Return the combined byte length of the fixed-width R and S coordinates.
     */
    public function pointLength(): int
    {
        return 64;
    }

    /**
     * Require the 256-bit EC key length associated with the P-256 curve.
     */
    public function expectedKeyLength(): int
    {
        return 256;
    }
}
