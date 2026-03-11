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
 * Signals that validation leeway was configured with an impossible value.
 *
 * Time-based constraints accept leeway only as a non-negative grace period.
 * Throwing a dedicated exception keeps invalid configuration errors separate
 * from runtime token failures and makes the invariant explicit in public APIs.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class LeewayCannotBeNegative extends InvalidArgumentException implements ExceptionInterface
{
    /**
     * Create an exception for callers attempting to use a negative leeway.
     */
    public static function create(): self
    {
        return new self('Leeway cannot be negative');
    }
}
