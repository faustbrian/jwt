<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

use Throwable;

/**
 * Signals that the provided key contents could not be parsed by the crypto backend.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class UnparseableKeyProvided extends InvalidKeyProvided
{
    public static function because(string $details, ?Throwable $previous = null): self
    {
        return new self('It was not possible to parse your key, reason:'.$details, previous: $previous);
    }
}
