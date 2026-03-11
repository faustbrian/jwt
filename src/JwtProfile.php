<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT;

use Cline\JWT\Contracts\NowProviderInterface;
use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Contracts\Validation\ConstraintInterface;
use Cline\JWT\Contracts\Validation\SignedWithInterface;
use Cline\JWT\Contracts\Validation\ValidAtInterface;
use Cline\JWT\Validation\Constraint\IssuedBy;
use Cline\JWT\Validation\Constraint\PermittedFor;
use Cline\JWT\Validation\Constraint\SignedWith;
use Cline\JWT\Validation\Constraint\StrictValidAt;
use DateInterval;

/**
 * Immutable named bundle of issuance defaults and validation rules for JWT workflows.
 *
 * A profile packages the signer, keys, temporal policy, issuer, audiences, and
 * default custom payload fragments that should travel together. This lets consumers
 * reference a stable logical profile name instead of re-specifying cryptographic and
 * validation settings at every call site.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class JwtProfile
{
    /**
     * Create a profile from already-resolved cryptographic primitives and defaults.
     *
     * @param array<non-empty-string>        $audiences
     * @param array<non-empty-string, mixed> $headers
     * @param array<non-empty-string, mixed> $claims
     */
    public function __construct(
        private string $name,
        private SignerInterface $signer,
        private KeyInterface $signingKey,
        private KeyInterface $verificationKey,
        private ?DateInterval $timeToLive = null,
        private ?DateInterval $leeway = null,
        private ?string $issuer = null,
        private array $audiences = [],
        private array $headers = [],
        private array $claims = [],
    ) {}

    /**
     * Return the logical profile name used for repository lookup and diagnostics.
     */
    public function name(): string
    {
        return $this->name;
    }

    /**
     * Return the signer used when issuing tokens for this profile.
     */
    public function signer(): SignerInterface
    {
        return $this->signer;
    }

    /**
     * Return the private or shared key used to sign issued tokens.
     */
    public function signingKey(): KeyInterface
    {
        return $this->signingKey;
    }

    /**
     * Return the key consumers should use when verifying profile-issued tokens.
     */
    public function verificationKey(): KeyInterface
    {
        return $this->verificationKey;
    }

    /**
     * Build the default issuance request implied by this profile.
     *
     * The request contains issuer, TTL, audiences, headers, and custom claims, but
     * leaves per-token identifiers and subject values for the caller to supply.
     */
    public function issueRequest(): IssueTokenRequest
    {
        $request = new IssueTokenRequest();

        if ($this->issuer !== null && $this->issuer !== '') {
            $request = $request->issuedBy($this->issuer);
        }

        if ($this->timeToLive instanceof DateInterval) {
            $request = $request->expiresAfter($this->timeToLive);
        }

        if ($this->audiences !== []) {
            $request = $request->permittedFor(...$this->audiences);
        }

        foreach ($this->headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        foreach ($this->claims as $name => $value) {
            $request = $request->withClaim($name, $value);
        }

        return $request;
    }

    /**
     * Create the signature constraint that matches this profile's verifier settings.
     */
    public function signatureConstraint(): SignedWithInterface
    {
        return new SignedWith($this->signer, $this->verificationKey);
    }

    /**
     * Create the temporal constraint configured for this profile.
     *
     * Profiles always use strict temporal validation so production-issued tokens
     * must carry the full set of registered time claims.
     */
    public function validAtConstraint(NowProviderInterface $nowProvider): ValidAtInterface
    {
        return new StrictValidAt($this->leeway, $nowProvider);
    }

    /**
     * Create the additional issuer and audience constraints implied by this profile.
     *
     * Signature and temporal validation are handled separately because they require
     * runtime collaborators.
     *
     * @return array<ConstraintInterface>
     */
    public function validationConstraints(): array
    {
        $constraints = [];

        if ($this->issuer !== null && $this->issuer !== '') {
            $constraints[] = new IssuedBy($this->issuer);
        }

        foreach ($this->audiences as $audience) {
            $constraints[] = new PermittedFor($audience);
        }

        return $constraints;
    }
}
