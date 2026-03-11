<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Signer\Ecdsa;

use Cline\JWT\Signer\AbstractEcdsaSigner;

use const OPENSSL_ALGO_SHA384;

/**
 * ECDSA signer for the `ES384` JWT algorithm.
 *
 * This class fixes the abstract ECDSA signer to the P-384 curve profile. The
 * inherited implementation delegates cryptographic work to OpenSSL and performs
 * ASN.1/JWA signature conversion, while this concrete variant supplies the
 * digest, JOSE header value, and exact coordinate sizing rules for `ES384`.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Sha384 extends AbstractEcdsaSigner
{
    /**
     * Advertise the JOSE algorithm header value written into issued tokens.
     */
    public function algorithmId(): string
    {
        return 'ES384';
    }

    /**
     * Select the OpenSSL digest constant used with the EC private/public key.
     */
    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA384;
    }

    /**
     * Return the combined byte length of the fixed-width R and S coordinates.
     */
    public function pointLength(): int
    {
        return 96;
    }

    /**
     * Require the 384-bit EC key length associated with the P-384 curve.
     */
    public function expectedKeyLength(): int
    {
        return 384;
    }
}
