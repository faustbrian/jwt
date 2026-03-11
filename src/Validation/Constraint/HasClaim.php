<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Validation\Constraint;

use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Contracts\UnencryptedTokenInterface;
use Cline\JWT\Contracts\Validation\ConstraintInterface;
use Cline\JWT\Exceptions\CannotValidateARegisteredClaim;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Token\RegisteredClaims;

use function in_array;

/**
 * Constraint that requires a custom, non-registered claim to be present.
 *
 * This exists for extension claims only. Registered JWT claims have dedicated
 * constraints with semantics tailored to their RFC meaning, so the constructor
 * rejects attempts to validate them through this generic path.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class HasClaim implements ConstraintInterface
{
    /**
     * @param non-empty-string $claim Custom claim name that must exist on the token
     */
    public function __construct(
        private string $claim,
    ) {
        if (in_array($claim, RegisteredClaims::ALL, true)) {
            throw CannotValidateARegisteredClaim::create($claim);
        }
    }

    /**
     * Assert the presence of the configured custom claim on a plain token payload.
     *
     * @throws ConstraintViolation
     */
    public function assert(TokenInterface $token): void
    {
        if (!$token instanceof UnencryptedTokenInterface) {
            throw ConstraintViolation::error('You should pass a plain token', $this);
        }

        $claims = $token->claims();

        if (!$claims->has($this->claim)) {
            throw ConstraintViolation::error('The token does not have the claim "'.$this->claim.'"', $this);
        }
    }
}
