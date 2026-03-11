<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts\Validation;

use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Exceptions\ConstraintViolation;

/**
 * Contract for a single JWT validation rule.
 *
 * Constraints are intentionally side-effect free and communicate failure by
 * throwing ConstraintViolation so validators can either aggregate or short-circuit
 * them depending on the calling API.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface ConstraintInterface
{
    /**
     * Assert that the token satisfies this validation rule.
     *
     * @throws ConstraintViolation
     */
    public function assert(TokenInterface $token): void;
}
