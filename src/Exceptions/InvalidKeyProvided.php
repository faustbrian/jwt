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
 * Signals that signer key material could not be accepted by the JWT runtime.
 *
 * This exception is raised while normalizing caller-provided key input into the
 * package's immutable key value objects. It centralizes all key-shape failures
 * so higher-level signing and verification code can fail with consistent,
 * user-facing diagnostics regardless of whether the problem was parsing,
 * algorithm compatibility, length requirements, or an empty payload.
 *
 * @author Brian Faust <brian@cline.sh>
 */
abstract class InvalidKeyProvided extends InvalidArgumentException implements ExceptionInterface, JwtException {}
