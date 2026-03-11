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
 * Signals that a generic claim constraint was aimed at a registered JWT claim.
 *
 * Registered claims such as `iss`, `sub`, `aud`, and temporal claims have
 * dedicated constraint types because they require semantics beyond plain equality
 * checks. This exception protects that API boundary and steers callers toward
 * the specialized validation rule that encodes the correct behavior.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class CannotValidateARegisteredClaim extends InvalidArgumentException implements ExceptionInterface
{
    /**
     * Create an exception naming the registered claim that was misrouted.
     *
     * Used by generic `HasClaim*` constraints to reject claim names that should
     * instead be validated by dedicated registered-claim constraints.
     *
     * @param non-empty-string $claim
     */
    public static function create(string $claim): self
    {
        return new self(
            'The claim "'.$claim.'" is a registered claim, another constraint must be used to validate its value',
        );
    }
}
