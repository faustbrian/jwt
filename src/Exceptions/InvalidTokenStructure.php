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
 * Describes syntactic or shape errors encountered while parsing JWT input.
 *
 * Parser code throws this when the compact token string does not satisfy the
 * package's structural requirements before any signature or claim validation
 * begins. The named constructors map to distinct parse stages so callers can
 * distinguish malformed transport data from semantic validation failures.
 *
 * @author Brian Faust <brian@cline.sh>
 */
abstract class InvalidTokenStructure extends InvalidArgumentException implements ExceptionInterface, JwtException {}
