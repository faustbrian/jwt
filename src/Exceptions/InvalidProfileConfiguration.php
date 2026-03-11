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
 * Signals that a named JWT profile could not be normalized into a usable
 * runtime configuration.
 *
 * Profile repositories throw this when required signer, key, or constraint
 * configuration is missing or internally inconsistent. The exception keeps
 * package bootstrapping failures tied to the offending profile name.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidProfileConfiguration extends InvalidArgumentException implements ExceptionInterface
{
    /**
     * Create an exception for a specific profile and human-readable reason.
     */
    public static function forProfile(string $profile, string $reason): self
    {
        return new self('JWT profile "'.$profile.'" is invalid: '.$reason);
    }
}
