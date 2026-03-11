<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

use Throwable;

/**
 * Marker interface for all package exceptions exposed by JWT.
 *
 * Consumers can catch this contract to handle any package-level failure without
 * depending on a long list of concrete exception classes.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface JwtException extends Throwable {}
