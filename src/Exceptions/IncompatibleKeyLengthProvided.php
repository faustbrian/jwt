<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

/**
 * Signals that the provided key length does not match the exact size required.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class IncompatibleKeyLengthProvided extends InvalidKeyProvided
{
    public static function expectedLength(int $expectedLength, int $actualLength): self
    {
        return new self(
            'The length of the provided key is different than '.$expectedLength.' bits, '
            .$actualLength.' bits provided',
        );
    }
}
