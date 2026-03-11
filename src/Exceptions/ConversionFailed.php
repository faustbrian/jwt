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
 * Signals that ECDSA signature conversion could not complete safely.
 *
 * The package converts between DER-encoded signatures and the JOSE compact
 * representation expected inside JWTs. These failures indicate malformed input
 * or structural violations discovered while traversing ASN.1-encoded signature
 * bytes, and they stop verification before an invalid signature is misread.
 *
 * @author Brian Faust <brian@cline.sh>
 */
abstract class ConversionFailed extends InvalidArgumentException implements ExceptionInterface, JwtException {}
