<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts;

/**
 * Token contract for standard signed JWTs that expose a signature segment.
 *
 * This extends the generic token contract with accessors that are only valid
 * for unencrypted compact JWTs: the decoded claims set, the decoded signature,
 * and the canonical signing payload. It is the shape expected by signature and
 * time-based validation constraints after parsing.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface UnencryptedTokenInterface extends TokenInterface
{
    /**
     * Get the decoded claims payload carried by the token.
     */
    public function claims(): ClaimsInterface;

    /**
     * Get the decoded signature segment for verification workflows.
     */
    public function signature(): SignatureInterface;

    /**
     * Get the canonical payload string used for signature verification.
     *
     * This is typically the concatenation of the encoded header and encoded
     * claims segments joined by a dot, matching the input passed to the signer.
     *
     * @return non-empty-string
     */
    public function payload(): string;
}
