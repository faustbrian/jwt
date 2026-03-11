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
 * Constraint that requires a custom claim to exist and match an exact value.
 *
 * This is intended for extension claims whose meaning is application-defined.
 * Registered claims are excluded because their validation usually involves
 * canonical JWT semantics rather than raw equality checks.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class HasClaimWithValue implements ConstraintInterface
{
    /**
     * @param non-empty-string $claim Custom claim name that must exist and match exactly
     */
    public function __construct(
        private string $claim,
        private mixed $expectedValue,
    ) {
        if (in_array($claim, RegisteredClaims::ALL, true)) {
            throw CannotValidateARegisteredClaim::create($claim);
        }
    }

    /**
     * Assert that the configured custom claim exists and is strictly equal to the expected value.
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

        if ($claims->get($this->claim) !== $this->expectedValue) {
            throw ConstraintViolation::error(
                'The claim "'.$this->claim.'" does not have the expected value',
                $this,
            );
        }
    }
}
