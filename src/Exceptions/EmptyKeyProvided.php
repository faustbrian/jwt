<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

/**
 * Signals that the caller supplied an empty key payload.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class EmptyKeyProvided extends InvalidKeyProvided
{
    public static function detected(): self
    {
        return new self('Key cannot be empty');
    }
}
