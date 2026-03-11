<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

use JsonException;

/**
 * Signals that JSON payload decoding failed after Base64Url decoding succeeded.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidJsonContent extends CannotDecodeContent
{
    public static function detected(JsonException $previous): self
    {
        return new self(message: 'Error while decoding from JSON', previous: $previous);
    }
}
