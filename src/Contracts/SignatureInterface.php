<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts;

/**
 * Value-object contract for the signature segment of a parsed JWT.
 *
 * Implementations preserve both the raw signature bytes and the transport-safe
 * base64url representation used in compact JWT serialization. This split lets
 * validators work with cryptographic bytes while consumers that need to rebuild
 * the compact token can reuse the original encoded segment without re-encoding.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface SignatureInterface
{
    /**
     * Get the raw signature bytes used for cryptographic verification.
     *
     * @return non-empty-string
     */
    public function hash(): string;

    /**
     * Get the compact JWT representation of the signature segment.
     *
     * This should be the exact base64url-encoded value that appears after the
     * second dot in the token string.
     *
     * @return non-empty-string
     */
    public function toString(): string;
}
