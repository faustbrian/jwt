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
 * Shared-secret signer for the `HS384` JWT algorithm.
 *
 * This specialization binds {@see AbstractHmacSigner} to SHA-384. It inherits
 * constant-time verification and minimum-secret enforcement while publishing the
 * JOSE algorithm identifier and digest name needed for interoperable tokens.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Sha384 extends AbstractHmacSigner
{
    /**
     * Advertise the JOSE algorithm header value written into issued tokens.
     */
    public function algorithmId(): string
    {
        return 'HS384';
    }

    /**
     * Select the hash extension digest used to compute the MAC.
     */
    public function algorithm(): string
    {
        return 'sha384';
    }

    /**
     * Require a secret at least as long as the algorithm's advertised strength.
     */
    public function minimumBitsLengthForKey(): int
    {
        return 384;
    }
}
