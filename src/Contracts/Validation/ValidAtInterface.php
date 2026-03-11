<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts\Validation;

/**
 * Marker contract for constraints that validate token time windows.
 *
 * High-level parse APIs depend on this dedicated interface so temporal validation
 * cannot be omitted accidentally when composing common verification flows.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface ValidAtInterface extends ConstraintInterface {}
