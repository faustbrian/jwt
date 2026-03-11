<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Token;

use Carbon\CarbonInterface;
use Cline\JWT\Contracts\ClaimsInterface;

use function array_filter;
use function array_key_exists;
use function array_values;
use function is_array;
use function is_string;

/**
 * Immutable read model over a decoded JWT claims payload.
 *
 * The claims object preserves the original encoded segment for token rebuilding
 * while also exposing typed helpers for the registered claims used most often by
 * validators and application code.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Claims implements ClaimsInterface
{
    /**
     * @param array<non-empty-string, mixed> $claims Decoded claim map
     */
    public function __construct(
        private array $claims,
        private string $encoded,
    ) {}

    /**
     * Return a claim value or the provided default when it is absent.
     */
    public function get(string $name, mixed $default = null): mixed
    {
        return $this->claims[$name] ?? $default;
    }

    /**
     * Return whether the claims payload contains the named claim.
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->claims);
    }

    /**
     * Return the complete decoded claim map.
     */
    public function all(): array
    {
        return $this->claims;
    }

    /**
     * Return the normalized audience list from the `aud` claim.
     *
     * Non-list or non-string values are discarded so callers always receive a clean
     * list of audience identifiers.
     */
    public function audiences(): array
    {
        $audiences = $this->get(RegisteredClaims::AUDIENCE, []);

        if (!is_array($audiences)) {
            return [];
        }

        /** @var array<non-empty-string> */
        return array_values(array_filter($audiences, is_string(...)));
    }

    /**
     * Return the issuer (`iss`) claim when it is a string.
     */
    public function issuer(): ?string
    {
        $issuer = $this->get(RegisteredClaims::ISSUER);

        return is_string($issuer) ? $issuer : null;
    }

    /**
     * Return the subject (`sub`) claim when it is a string.
     */
    public function subject(): ?string
    {
        $subject = $this->get(RegisteredClaims::SUBJECT);

        return is_string($subject) ? $subject : null;
    }

    /**
     * Return the JWT ID (`jti`) claim when it is a string.
     */
    public function identifier(): ?string
    {
        $identifier = $this->get(RegisteredClaims::ID);

        return is_string($identifier) ? $identifier : null;
    }

    /**
     * Return the issued-at (`iat`) claim when it has been decoded to Carbon.
     */
    public function issuedAt(): ?CarbonInterface
    {
        $issuedAt = $this->get(RegisteredClaims::ISSUED_AT);

        return $issuedAt instanceof CarbonInterface ? $issuedAt : null;
    }

    /**
     * Return the not-before (`nbf`) claim when it has been decoded to Carbon.
     */
    public function notBefore(): ?CarbonInterface
    {
        $notBefore = $this->get(RegisteredClaims::NOT_BEFORE);

        return $notBefore instanceof CarbonInterface ? $notBefore : null;
    }

    /**
     * Return the expiration (`exp`) claim when it has been decoded to Carbon.
     */
    public function expiresAt(): ?CarbonInterface
    {
        $expiresAt = $this->get(RegisteredClaims::EXPIRATION_TIME);

        return $expiresAt instanceof CarbonInterface ? $expiresAt : null;
    }

    /**
     * Return the original encoded claims segment from the compact token.
     */
    public function toString(): string
    {
        return $this->encoded;
    }
}
