<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

use Cline\JWT\Contracts\ExceptionInterface;
use JsonException;
use RuntimeException;

/**
 * Signals that token headers or claims could not be serialized for output.
 *
 * This exception sits in the encoding stage of token issuance, after claims have
 * been assembled but before signing occurs. It wraps low-level JSON failures so
 * callers receive a package-specific exception while preserving the underlying
 * serializer error as the previous exception.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class CannotEncodeContent extends RuntimeException implements ExceptionInterface
{
    /**
     * Create an exception for JSON serialization failures.
     *
     * Builder and encoder implementations call this when header or claim payloads
     * cannot be converted into the canonical JSON representation required by JWT.
     */
    public static function jsonIssues(JsonException $previous): self
    {
        return new self(message: 'Error while encoding to JSON', previous: $previous);
    }
}
