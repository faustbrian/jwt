<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

/**
 * Signals that a DER-encoded signature member was not encoded as an ASN.1 integer.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidAsn1Integer extends ConversionFailed
{
    public static function detected(): self
    {
        return new self('Invalid data. Should contain an integer.');
    }
}
