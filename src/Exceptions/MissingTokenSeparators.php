<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

/**
 * Signals that a compact JWT string does not contain the required two separators.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingTokenSeparators extends InvalidTokenStructure
{
    public static function detected(): self
    {
        return new self('The JWT string must have two dots');
    }
}
