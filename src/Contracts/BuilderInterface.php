<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Contracts;

use Carbon\CarbonInterface;
use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Exceptions\CannotEncodeContent;
use Cline\JWT\Exceptions\CannotSignPayload;
use Cline\JWT\Exceptions\ConversionFailed;
use Cline\JWT\Exceptions\InvalidKeyProvided;
use Cline\JWT\Exceptions\RegisteredClaimGiven;
use NoDiscard;

/**
 * Immutable fluent builder for assembling signed JWTs.
 *
 * Builders collect header and claim state before producing an
 * {@see UnencryptedTokenInterface}. Implementations are expected to return a
 * new instance for every mutator so call sites can safely reuse partially
 * configured builders without worrying about shared mutable state.
 *
 * The contract separates registration of RFC-defined claims from arbitrary
 * application claims so callers get explicit, type-aware methods for common
 * JWT fields while still retaining an escape hatch for custom data.
 *
 * @immutable
 * @author Brian Faust <brian@cline.sh>
 */
interface BuilderInterface
{
    /**
     * Add one or more audience values to the token.
     *
     * Implementations should preserve existing audience entries and avoid
     * introducing duplicates when the same audience is supplied multiple times.
     *
     * @param non-empty-string ...$audiences
     */
    #[NoDiscard()]
    public function permittedFor(string ...$audiences): self;

    /**
     * Set the absolute expiration instant for the token.
     */
    #[NoDiscard()]
    public function expiresAt(CarbonInterface $expiration): self;

    /**
     * Set the registered JWT ID (`jti`) claim.
     *
     * @param non-empty-string $id
     */
    #[NoDiscard()]
    public function identifiedBy(string $id): self;

    /**
     * Set the issued-at (`iat`) instant for the token.
     */
    #[NoDiscard()]
    public function issuedAt(CarbonInterface $issuedAt): self;

    /**
     * Set the issuer (`iss`) claim identifying the token authority.
     *
     * @param non-empty-string $issuer
     */
    #[NoDiscard()]
    public function issuedBy(string $issuer): self;

    /**
     * Set the not-before (`nbf`) instant for the token.
     *
     * Consumers use this claim to reject tokens that are structurally valid but
     * should not be accepted until a later time.
     */
    #[NoDiscard()]
    public function canOnlyBeUsedAfter(CarbonInterface $notBefore): self;

    /**
     * Set the subject (`sub`) claim the token refers to.
     *
     * @param non-empty-string $subject
     */
    #[NoDiscard()]
    public function relatedTo(string $subject): self;

    /**
     * Add or replace a JOSE header value.
     *
     * Implementations may allow callers to override optional headers, but they
     * are still responsible for ensuring required signing headers such as `alg`
     * are populated when the final token is emitted.
     *
     * @param non-empty-string $name
     */
    #[NoDiscard()]
    public function withHeader(string $name, mixed $value): self;

    /**
     * Add or replace an application-specific claim.
     *
     * Registered RFC claims must use the dedicated fluent methods so builders
     * can preserve typing and semantic intent for those fields.
     *
     * @param non-empty-string $name
     *
     * @throws RegisteredClaimGiven When trying to set a registered claim.
     */
    #[NoDiscard()]
    public function withClaim(string $name, mixed $value): self;

    /**
     * Produce a signed compact JWT from the current builder state.
     *
     * Implementations must encode headers and claims, inject the signer's
     * algorithm identifier into the JOSE header, and sign the canonical payload
     * with the provided key before returning the resulting token object.
     *
     * @throws CannotEncodeContent When data cannot be converted to JSON.
     * @throws CannotSignPayload   When payload signing fails.
     * @throws InvalidKeyProvided  When issue key is invalid/incompatible.
     * @throws ConversionFailed    When signature could not be converted.
     */
    #[NoDiscard()]
    public function getToken(SignerInterface $signer, KeyInterface $key): UnencryptedTokenInterface;
}
