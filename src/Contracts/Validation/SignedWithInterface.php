<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts\Validation;

/**
 * Marker contract for constraints that validate token signatures.
 *
 * Separating signature constraints from generic constraints lets higher-level APIs
 * require cryptographic verification explicitly in their method signatures.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface SignedWithInterface extends ConstraintInterface {}
