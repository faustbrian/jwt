<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts;

use Carbon\CarbonInterface;

/**
 * Read-only view over a token's claim set.
 *
 * Implementations expose both raw accessors and typed helpers for the registered
 * claims most callers care about. This keeps validation and application code from
 * duplicating registered-claim name strings throughout the package.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface ClaimsInterface
{
    /**
     * Return a claim value or the provided default when it is missing.
     *
     * @param non-empty-string $name
     */
    public function get(string $name, mixed $default = null): mixed;

    /**
     * Return whether the claim exists in the payload.
     *
     * @param non-empty-string $name
     */
    public function has(string $name): bool;

    /**
     * Return the full claim map as stored on the token.
     *
     * @return array<non-empty-string, mixed>
     */
    public function all(): array;

    /**
     * Return the normalized audience list from the `aud` claim.
     *
     * @return array<non-empty-string>
     */
    public function audiences(): array;

    /**
     * Return the issuer (`iss`) claim when present.
     */
    public function issuer(): ?string;

    /**
     * Return the subject (`sub`) claim when present.
     */
    public function subject(): ?string;

    /**
     * Return the JWT ID (`jti`) claim when present.
     */
    public function identifier(): ?string;

    /**
     * Return the issued-at (`iat`) claim as a Carbon instance when present.
     */
    public function issuedAt(): ?CarbonInterface;

    /**
     * Return the not-before (`nbf`) claim as a Carbon instance when present.
     */
    public function notBefore(): ?CarbonInterface;

    /**
     * Return the expiration (`exp`) claim as a Carbon instance when present.
     */
    public function expiresAt(): ?CarbonInterface;

    /**
     * Return the encoded compact representation of the claims segment.
     */
    public function toString(): string;
}
