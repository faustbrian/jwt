<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts;

use Cline\JWT\Exceptions\CannotDecodeContent;
use Cline\JWT\Exceptions\InvalidTokenStructure;
use Cline\JWT\Exceptions\UnsupportedHeaderFound;
use NoDiscard;

/**
 * Parses compact JWT strings into the package's token value objects.
 *
 * A parser is responsible for splitting the three compact token segments,
 * decoding the header and claims payloads, validating structural invariants,
 * and returning a token representation that validators and consumers can
 * inspect. Signature verification is intentionally outside this contract so
 * parsing and validation can evolve independently.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface ParserInterface
{
    /**
     * Parse a compact JWT string into a token object graph.
     *
     * Implementations must reject malformed compact serialization, invalid JSON
     * payloads, and unsupported header combinations before returning a token.
     *
     * @param non-empty-string $jwt
     *
     * @throws CannotDecodeContent    When something goes wrong while decoding.
     * @throws InvalidTokenStructure  When token string structure is invalid.
     * @throws UnsupportedHeaderFound When parsed token has an unsupported header.
     */
    #[NoDiscard()]
    public function parse(string $jwt): TokenInterface;
}
