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

use function sprintf;

/**
 * Signals misuse of the generic claim API for registered JWT claims.
 *
 * Builder consumers are expected to use the dedicated fluent methods for
 * standard claims so the package can preserve typing and normalization rules
 * for values such as timestamps and audience lists.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class RegisteredClaimGiven extends InvalidArgumentException implements ExceptionInterface
{
    private const string DEFAULT_MESSAGE = 'Builder#withClaim() is meant to be used for non-registered claims, '
        .'check the documentation on how to set claim "%s"';

    /**
     * Create an exception for attempts to set a registered claim through the
     * generic custom-claim entry point.
     *
     * @param non-empty-string $name
     */
    public static function forClaim(string $name): self
    {
        return new self(sprintf(self::DEFAULT_MESSAGE, $name));
    }
}
