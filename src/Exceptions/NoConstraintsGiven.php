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
 * Signals that validation was requested without any constraints to enforce.
 *
 * The validator treats an empty constraint list as a configuration error rather
 * than silently succeeding, because calling validation APIs without rules is
 * almost always an integration bug that would otherwise weaken token checks.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class NoConstraintsGiven extends RuntimeException implements ExceptionInterface, JwtException
{
    /**
     * Create an exception for validation calls that omitted every constraint.
     */
    public static function forValidation(): self
    {
        return new self('No constraint given.');
    }
}
