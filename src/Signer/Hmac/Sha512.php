<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Signer\Hmac;

use Cline\JWT\Signer\AbstractHmacSigner;

/**
 * Shared-secret signer for the `HS512` JWT algorithm.
 *
 * The inherited {@see AbstractHmacSigner} performs constant-time verification
 * and rejects undersized secrets before computing the MAC. This concrete class
 * exists to publish the `HS512` JOSE algorithm identifier, the SHA-512 digest
 * name, and the minimum symmetric key length expected for that profile.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Sha512 extends AbstractHmacSigner
{
    /**
     * Advertise the JOSE algorithm header value written into issued tokens.
     */
    public function algorithmId(): string
    {
        return 'HS512';
    }

    /**
     * Select the hash extension digest used to compute the MAC.
     */
    public function algorithm(): string
    {
        return 'sha512';
    }

    /**
     * Require a secret at least as long as the algorithm's advertised strength.
     */
    public function minimumBitsLengthForKey(): int
    {
        return 512;
    }
}
