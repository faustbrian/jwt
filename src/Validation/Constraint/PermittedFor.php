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
 * Constraint that requires a token audience list to include a specific consumer identifier.
 *
 * Use this to prevent tokens minted for one audience from being replayed against a
 * different service, client, or subsystem.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class PermittedFor implements ConstraintInterface
{
    /**
     * @param non-empty-string $audience Audience value that must appear in the token's `aud` claim
     */
    public function __construct(
        private string $audience,
    ) {}

    /**
     * Assert that the token is permitted for the configured audience.
     *
     * @throws ConstraintViolation
     */
    public function assert(TokenInterface $token): void
    {
        if (!$token->isPermittedFor($this->audience)) {
            throw ConstraintViolation::error(
                'The token is not allowed to be used by this audience',
                $this,
            );
        }
    }
}
