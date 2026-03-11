<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Token;

use Cline\JWT\Contracts\SignatureInterface;

/**
 * Immutable representation of a JWT signature segment.
 *
 * The object preserves both the raw signature bytes used for verification and the
 * encoded compact representation used when rebuilding the token string.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Signature implements SignatureInterface
{
    /**
     * @param non-empty-string $hash    Raw signature bytes
     * @param non-empty-string $encoded Base64Url-encoded signature segment
     */
    public function __construct(
        private string $hash,
        private string $encoded,
    ) {}

    /**
     * Return the raw signature bytes used for cryptographic verification.
     *
     * @return non-empty-string
     */
    public function hash(): string
    {
        return $this->hash;
    }

    /**
     * Return the compact token representation of the signature segment.
     *
     * @return non-empty-string
     */
    public function toString(): string
    {
        return $this->encoded;
    }
}
