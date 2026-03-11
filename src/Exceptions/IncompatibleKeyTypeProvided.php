<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

/**
 * Signals that the provided key type does not match the active signer.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class IncompatibleKeyTypeProvided extends InvalidKeyProvided
{
    public static function expectedType(string $expectedType, string $actualType): self
    {
        return new self(
            'The type of the provided key is not "'.$expectedType
            .'", "'.$actualType.'" provided',
        );
    }
}
