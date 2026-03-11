<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

use Cline\JWT\Contracts\ExceptionInterface;
use RuntimeException;

/**
 * Signals that inbound JWT segments could not be decoded into structured data.
 *
 * This exception belongs to the parsing stage and covers failures before a token
 * can be validated, including malformed Base64Url segments and invalid JSON
 * payloads. It wraps serializer errors where possible so the parse pipeline
 * stays within the package's exception contract.
 *
 * @author Brian Faust <brian@cline.sh>
 */
abstract class CannotDecodeContent extends RuntimeException implements ExceptionInterface, JwtException {}
