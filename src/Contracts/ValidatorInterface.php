<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts;

use Cline\JWT\Contracts\Validation\ConstraintInterface;
use Cline\JWT\Exceptions\NoConstraintsGiven;
use Cline\JWT\Exceptions\RequiredConstraintsViolated;
use NoDiscard;

/**
 * Applies validation constraints to parsed JWT instances.
 *
 * Validators coordinate the package's constraint pipeline after parsing but
 * before application code trusts the token's claims. They are expected to
 * execute every provided constraint against the token and either aggregate the
 * resulting failures for an exception-based workflow or collapse the result to
 * a boolean for branch-oriented consumers.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface ValidatorInterface
{
    /**
     * Assert that the token satisfies every supplied constraint.
     *
     * Implementations should fail fast only when no constraints were supplied.
     * Otherwise they are expected to evaluate the full constraint set so the
     * caller receives a complete picture of all validation failures.
     *
     * @throws RequiredConstraintsViolated
     * @throws NoConstraintsGiven
     */
    public function assert(TokenInterface $token, ConstraintInterface ...$constraints): void;

    /**
     * Determine whether the token satisfies every supplied constraint.
     *
     * This is the non-throwing counterpart to {@see self::assert()}, intended
     * for call sites that only need a pass/fail decision. Supplying no
     * constraints is still considered a caller error rather than an automatic
     * success.
     *
     * @throws NoConstraintsGiven
     */
    #[NoDiscard()]
    public function validate(TokenInterface $token, ConstraintInterface ...$constraints): bool;
}
