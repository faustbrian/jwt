<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts;

use Cline\JWT\Exceptions\CannotEncodeContent;
use NoDiscard;

/**
 * Encodes structured JWT data into transport-safe string representations.
 *
 * Implementations centralize the package's JSON and base64url encoding rules so
 * builders, parsers, and formatter pipelines share consistent serialization
 * behavior. This keeps RFC-specific details in one abstraction and makes it
 * possible to swap encoding strategies without rewriting token orchestration.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface EncoderInterface
{
    /**
     * Serialize arbitrary data to a JSON string suitable for a JWT segment.
     *
     * Implementations must surface encoding errors explicitly instead of
     * returning partial output so token generation never silently emits corrupt
     * headers or claims.
     *
     * @throws CannotEncodeContent When something goes wrong while encoding.
     *
     * @return non-empty-string
     */
    #[NoDiscard()]
    public function jsonEncode(mixed $data): string;

    /**
     * Encode bytes using the base64url variant required by compact JWTs.
     *
     * The return value is suitable for token transport and should omit padding
     * characters per the JWT and RFC 4648 requirements.
     *
     * @see http://tools.ietf.org/html/rfc4648#section-5
     *
     * @return ($data is non-empty-string ? non-empty-string : string)
     */
    #[NoDiscard()]
    public function base64UrlEncode(string $data): string;
}
