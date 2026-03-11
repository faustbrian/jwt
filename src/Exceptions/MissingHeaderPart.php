<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

/**
 * Signals that a compact JWT string omitted the header segment.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingHeaderPart extends InvalidTokenStructure
{
    public static function detected(): self
    {
        return new self('The JWT string is missing the Header part');
    }
}
