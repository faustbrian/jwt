<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

use Cline\JWT\Contracts\ExceptionInterface;
use RuntimeException;

/**
 * Signals that a requested named JWT profile does not exist in the repository.
 *
 * Profiles encapsulate signer, key, and validation defaults for common issuing
 * and parsing flows. This exception is raised when a caller asks the facade for
 * a profile name that the configured repository cannot resolve, preventing the
 * runtime from silently falling back to an unintended configuration.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class JwtProfileNotFound extends RuntimeException implements ExceptionInterface
{
    /**
     * Create an exception for an unknown profile name.
     *
     * @param string $name Name originally requested from the repository
     */
    public static function named(string $name): self
    {
        return new self('JWT profile "'.$name.'" is not defined');
    }
}
