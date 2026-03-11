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
 * Constraint that binds a token to an expected subject (`sub`) value.
 *
 * Use this when a token should only represent one principal or resource identity
 * and subject mismatch must fail validation immediately.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class RelatedTo implements ConstraintInterface
{
    /**
     * @param non-empty-string $subject Expected subject value
     */
    public function __construct(
        private string $subject,
    ) {}

    /**
     * Assert that the token subject matches the configured subject exactly.
     *
     * @throws ConstraintViolation
     */
    public function assert(TokenInterface $token): void
    {
        if (!$token->isRelatedTo($this->subject)) {
            throw ConstraintViolation::error(
                'The token is not related to the expected subject',
                $this,
            );
        }
    }
}
