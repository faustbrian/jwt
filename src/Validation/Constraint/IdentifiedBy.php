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
 * Constraint that binds a token to an expected JWT ID (`jti`) value.
 *
 * This is typically used for replay protection, token registry lookups, or other
 * workflows where the token identifier carries domain significance beyond the raw
 * signature.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class IdentifiedBy implements ConstraintInterface
{
    /**
     * @param non-empty-string $id Expected JWT identifier
     */
    public function __construct(
        private string $id,
    ) {}

    /**
     * Assert that the token exposes the configured JWT identifier.
     *
     * @throws ConstraintViolation
     */
    public function assert(TokenInterface $token): void
    {
        if (!$token->isIdentifiedBy($this->id)) {
            throw ConstraintViolation::error(
                'The token is not identified with the expected ID',
                $this,
            );
        }
    }
}
