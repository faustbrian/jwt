<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

/**
 * Signals that a JWT segment contained invalid Base64Url characters.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidBase64UrlContent extends CannotDecodeContent
{
    public static function detected(): self
    {
        return new self('Error while decoding from Base64Url, invalid base64 characters detected');
    }
}
