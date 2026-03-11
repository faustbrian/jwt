<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Validation\Constraint;

use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Contracts\Validation\SignedWithInterface;
use Cline\JWT\Exceptions\ConstraintViolation;

use const PHP_EOL;

/**
 * Composite signature constraint that accepts the first successful verifier in a set.
 *
 * This is primarily useful during key or algorithm rotation when a consumer must
 * trust several verification strategies at the same time. Each nested constraint is
 * tried in order, and the aggregated failure message preserves every rejection reason
 * to make operational debugging easier when none of them succeed.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class SignedWithOneInSet implements SignedWithInterface
{
    /** @var array<SignedWithInterface> */
    private array $constraints;

    /**
     * @param SignedWithInterface ...$constraints Ordered signature constraints to try
     */
    public function __construct(SignedWithInterface ...$constraints)
    {
        $this->constraints = $constraints;
    }

    /**
     * Assert that at least one nested signature constraint accepts the token.
     *
     * The first successful verifier short-circuits the chain. If all fail, their
     * messages are appended into a single composite violation to surface why each
     * candidate signer or key was rejected.
     *
     * @throws ConstraintViolation
     */
    public function assert(TokenInterface $token): void
    {
        $errorMessage = 'It was not possible to verify the signature of the token, reasons:';

        foreach ($this->constraints as $constraint) {
            try {
                $constraint->assert($token);

                return;
            } catch (ConstraintViolation $violation) {
                $errorMessage .= PHP_EOL.'- '.$violation->getMessage();
            }
        }

        throw ConstraintViolation::error($errorMessage, $this);
    }
}
