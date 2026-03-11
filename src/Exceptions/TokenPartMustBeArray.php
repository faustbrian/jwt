<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

/**
 * Signals that a decoded token part was not an associative array with string keys.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class TokenPartMustBeArray extends InvalidTokenStructure
{
    public static function forPart(string $part): self
    {
        return new self($part.' must be an array with non-empty-string keys');
    }
}
