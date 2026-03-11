<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

/**
 * Signals that a registered JWT date claim could not be normalized to a timestamp.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class UnparseableDateClaimValue extends InvalidTokenStructure
{
    public static function fromValue(string $value): self
    {
        return new self('Value is not in the allowed date format: '.$value);
    }
}
