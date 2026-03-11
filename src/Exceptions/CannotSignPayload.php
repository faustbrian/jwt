<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

use Cline\JWT\Contracts\ExceptionInterface;
use InvalidArgumentException;

/**
 * Signals that a signer failed while producing the JWT signature segment.
 *
 * This exception wraps algorithm-specific signing errors in a package-level
 * exception so builder and facade callers can treat signature generation
 * failures consistently regardless of whether the underlying signer uses
 * OpenSSL, Sodium, or another extension.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class CannotSignPayload extends InvalidArgumentException implements ExceptionInterface
{
    /**
     * Create an exception for a signer-provided failure message.
     *
     * The original signer error text is appended verbatim so downstream code can
     * log or surface the precise crypto failure without depending on the signer
     * implementation that produced it.
     */
    public static function errorHappened(string $error): self
    {
        return new self('There was an error while creating the signature:'.$error);
    }
}
