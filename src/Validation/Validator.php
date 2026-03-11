<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Validation;

use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Contracts\Validation\ConstraintInterface;
use Cline\JWT\Contracts\ValidatorInterface;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Exceptions\NoConstraintsGiven;
use Cline\JWT\Exceptions\RequiredConstraintsViolated;

use function throw_if;

/**
 * Coordinates ordered execution of validation constraints for parsed tokens.
 *
 * The validator provides two modes: `assert()` collects every violation and throws a
 * composite exception, while `validate()` short-circuits to a boolean result for
 * callers that only need pass/fail semantics. Both paths reject empty constraint
 * lists because validating nothing usually indicates a configuration mistake.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Validator implements ValidatorInterface
{
    /**
     * Assert that the token satisfies every provided constraint.
     *
     * Violations are accumulated so callers receive the full set of failures in one
     * pass instead of fixing them iteratively one at a time.
     *
     * @throws NoConstraintsGiven
     * @throws RequiredConstraintsViolated
     */
    public function assert(TokenInterface $token, ConstraintInterface ...$constraints): void
    {
        throw_if($constraints === [], NoConstraintsGiven::forValidation());

        $violations = [];

        foreach ($constraints as $constraint) {
            $this->checkConstraint($constraint, $token, $violations);
        }

        if ($violations !== []) {
            throw RequiredConstraintsViolated::fromViolations(...$violations);
        }
    }

    /**
     * Return whether the token satisfies every provided constraint.
     *
     * Unlike `assert()`, this method stops at the first violation and converts the
     * failure into `false`, which is useful when the caller does not need detailed
     * diagnostics.
     *
     * @throws NoConstraintsGiven
     */
    public function validate(TokenInterface $token, ConstraintInterface ...$constraints): bool
    {
        throw_if($constraints === [], NoConstraintsGiven::forValidation());

        try {
            foreach ($constraints as $constraint) {
                $constraint->assert($token);
            }

            return true;
        } catch (ConstraintViolation) {
            return false;
        }
    }

    /**
     * Execute a single constraint and append any resulting violation to the buffer.
     *
     * @param array<ConstraintViolation> $violations
     */
    private function checkConstraint(
        ConstraintInterface $constraint,
        TokenInterface $token,
        array &$violations,
    ): void {
        try {
            $constraint->assert($token);
        } catch (ConstraintViolation $constraintViolation) {
            $violations[] = $constraintViolation;
        }
    }
}
