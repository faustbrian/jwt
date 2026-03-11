<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Validation\Constraint;

use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Contracts\Validation\ConstraintInterface;
use Cline\JWT\Exceptions\ConstraintViolation;

/**
 * Constraint that allows a token only when its issuer matches one of several trusted issuers.
 *
 * Multiple issuers are accepted to support rolling issuer identifiers, environment
 * aliases, or federation setups where several producers are equally valid.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class IssuedBy implements ConstraintInterface
{
    /** @var array<non-empty-string> */
    private array $issuers;

    /**
     * @param non-empty-string ...$issuers Allowed issuer values for the `iss` claim
     */
    public function __construct(string ...$issuers)
    {
        $this->issuers = $issuers;
    }

    /**
     * Assert that the token issuer matches at least one configured issuer.
     *
     * @throws ConstraintViolation
     */
    public function assert(TokenInterface $token): void
    {
        if (!$token->hasBeenIssuedBy(...$this->issuers)) {
            throw ConstraintViolation::error(
                'The token was not issued by the given issuers',
                $this,
            );
        }
    }
}
