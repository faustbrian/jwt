<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts;

use Cline\JWT\Exceptions\JwtException;
use Throwable;

/**
 * Marker interface implemented by all package-level JWT exceptions.
 *
 * This lets consumers catch JWT-specific failures without depending on a long
 * list of concrete exception types while still preserving the original
 * throwable contracts for more targeted handling when needed.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface ExceptionInterface extends JwtException, Throwable {}
