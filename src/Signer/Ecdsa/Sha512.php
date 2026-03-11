<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Signer\Ecdsa;

use Cline\JWT\Signer\AbstractEcdsaSigner;

use const OPENSSL_ALGO_SHA512;

/**
 * ECDSA signer for the `ES512` JWT algorithm.
 *
 * The inherited {@see AbstractEcdsaSigner} handles OpenSSL signing plus the
 * conversion between ASN.1 signatures and the fixed-width JWA wire format.
 * This specialization binds that flow to the P-521 curve profile used by
 * `ES512`, including the expected OpenSSL key size and R/S point length.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Sha512 extends AbstractEcdsaSigner
{
    /**
     * Advertise the JOSE algorithm header value written into issued tokens.
     */
    public function algorithmId(): string
    {
        return 'ES512';
    }

    /**
     * Select the OpenSSL digest constant used with the EC private/public key.
     */
    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA512;
    }

    /**
     * Return the combined byte length of the fixed-width R and S coordinates.
     */
    public function pointLength(): int
    {
        return 132;
    }

    /**
     * Require the 521-bit EC key length associated with the P-521 curve.
     */
    public function expectedKeyLength(): int
    {
        // ES512 means ECDSA using P-521 and SHA-512.
        // The key size is indeed 521 bits.
        return 521;
    }
}
