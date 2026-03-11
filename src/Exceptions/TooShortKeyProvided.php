<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

/**
 * Signals that the provided secret key is shorter than the minimum safe size.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class TooShortKeyProvided extends InvalidKeyProvided
{
    public static function expectedLength(int $expectedLength, int $actualLength): self
    {
        return new self('Key provided is shorter than '.$expectedLength.' bits,'
            .' only '.$actualLength.' bits provided');
    }
}
