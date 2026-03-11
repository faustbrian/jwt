<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

use AssertionError;
use Cline\JWT\Contracts\ExceptionInterface;

/**
 * Signals that the configured parser contract returned an unexpected token type.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class ParserMustReturnUnencryptedToken extends AssertionError implements ExceptionInterface, JwtException
{
    public static function enforced(): self
    {
        return new self('Parser must return an unencrypted token instance.');
    }
}
