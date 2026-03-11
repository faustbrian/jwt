<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

/**
 * Signals that a DER-encoded signature did not begin with the ASN.1 sequence marker.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidAsn1StartSequence extends ConversionFailed
{
    public static function detected(): self
    {
        return new self('Invalid data. Should start with a sequence.');
    }
}
