<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

use Cline\JWT\Contracts\ExceptionInterface;
use InvalidArgumentException;

/**
 * Signals that a parsed token requires JOSE features this package does not implement.
 *
 * The parser only accepts unsecured JWT structure and signature verification
 * flows supported by this package. Header values that would require nested
 * encryption or other unsupported JOSE processing are rejected with this
 * exception before the token is treated as trustworthy.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class UnsupportedHeaderFound extends InvalidArgumentException implements ExceptionInterface
{
    /**
     * Create an exception for encrypted-token headers.
     *
     * The current runtime does not support JWE decryption, so any `enc`-style
     * header signal is treated as a hard parse failure rather than ignored.
     */
    public static function encryption(): self
    {
        return new self('Encryption is not supported yet');
    }
}
