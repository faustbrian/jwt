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
use Cline\JWT\Contracts\HeadersInterface;
use Cline\JWT\Contracts\SignatureInterface;
use Cline\JWT\Contracts\UnencryptedTokenInterface;

use function in_array;

/**
 * Immutable representation of a standard signed, unencrypted JWT.
 *
 * The token keeps decoded header, claim, and signature value objects together and
 * implements the semantic helpers consumed by validation constraints. Missing
 * temporal claims are treated permissively here; stricter behavior is layered on
 * by constraints such as StrictValidAt.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Plain implements UnencryptedTokenInterface
{
    /**
     * Create a plain token from already-decoded parts.
     */
    public function __construct(
        private HeadersInterface $headers,
        private ClaimsInterface $claims,
        private SignatureInterface $signature,
    ) {}

    /**
     * Return the decoded JOSE header segment.
     */
    public function headers(): HeadersInterface
    {
        return $this->headers;
    }

    /**
     * Return the decoded JWT claims payload.
     */
    public function claims(): ClaimsInterface
    {
        return $this->claims;
    }

    /**
     * Return the decoded signature segment.
     */
    public function signature(): SignatureInterface
    {
        return $this->signature;
    }

    /**
     * Return the canonical signing payload (`header.claims`).
     */
    public function payload(): string
    {
        return $this->headers->toString().'.'.$this->claims->toString();
    }

    /**
     * Return whether the configured audience appears in the token's audience list.
     */
    public function isPermittedFor(string $audience): bool
    {
        return in_array($audience, $this->claims->audiences(), true);
    }

    /**
     * Return whether the token JWT ID matches the expected identifier.
     */
    public function isIdentifiedBy(string $id): bool
    {
        return $this->claims->identifier() === $id;
    }

    /**
     * Return whether the token subject matches the expected value.
     */
    public function isRelatedTo(string $subject): bool
    {
        return $this->claims->subject() === $subject;
    }

    /**
     * Return whether the token issuer matches any configured issuer.
     */
    public function hasBeenIssuedBy(string ...$issuers): bool
    {
        return in_array($this->claims->issuer(), $issuers, true);
    }

    /**
     * Return whether the token was issued at or before the supplied instant.
     *
     * Missing `iat` claims are treated as unconstrained here.
     */
    public function hasBeenIssuedBefore(CarbonInterface $now): bool
    {
        $issuedAt = $this->claims->issuedAt();

        return !($issuedAt instanceof CarbonInterface) || $now >= $issuedAt;
    }

    /**
     * Return whether the token is active by the supplied instant.
     *
     * Missing `nbf` claims are treated as unconstrained here.
     */
    public function isMinimumTimeBefore(CarbonInterface $now): bool
    {
        $notBefore = $this->claims->notBefore();

        return !($notBefore instanceof CarbonInterface) || $now >= $notBefore;
    }

    /**
     * Return whether the token has expired by the supplied instant.
     *
     * Missing `exp` claims are treated as non-expiring here.
     */
    public function isExpired(CarbonInterface $now): bool
    {
        $expiresAt = $this->claims->expiresAt();

        if (!$expiresAt instanceof CarbonInterface) {
            return false;
        }

        return $now >= $expiresAt;
    }

    /**
     * Return the compact serialized JWT string.
     */
    public function toString(): string
    {
        return $this->headers->toString().'.'
             .$this->claims->toString().'.'
             .$this->signature->toString();
    }
}
