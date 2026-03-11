<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT;

use Carbon\CarbonInterface;
use Cline\JWT\Contracts\BuilderInterface;
use DateInterval;
use NoDiscard;

use function array_diff;
use function array_merge;
use function array_values;

/**
 * Immutable token issuance blueprint consumed by {@see JwtFacade::issue()}.
 *
 * Collects both registered JWT claims and arbitrary custom headers or claims
 * before they are applied to a concrete {@see BuilderInterface}. The request
 * intentionally defers timestamp resolution until application time so callers
 * can compose a request once and issue multiple tokens against a deterministic
 * "now" supplied by the runtime configuration.
 *
 * Merge and wither operations preserve immutability. When merged, explicit
 * values from the incoming request override scalar fields while headers and
 * claims are appended with later keys winning. Audience values are deduplicated
 * in insertion order so downstream builders receive a stable audience list.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class IssueTokenRequest
{
    /**
     * @param array<non-empty-string, mixed> $headers   Custom JOSE header values to append after required headers
     * @param array<non-empty-string, mixed> $claims    Non-registered claims to append after registered claims are resolved
     * @param array<non-empty-string>        $audiences Audience values to emit as the `aud` claim when present
     */
    public function __construct(
        private array $headers = [],
        private array $claims = [],
        private array $audiences = [],
        private ?string $identifier = null,
        private ?string $issuer = null,
        private ?string $subject = null,
        private ?CarbonInterface $issuedAt = null,
        private ?CarbonInterface $notBefore = null,
        private ?CarbonInterface $expiresAt = null,
        private ?DateInterval $timeToLive = null,
    ) {}

    /**
     * Set the JWT ID (`jti`) claim for replay detection or token lookup.
     */
    #[NoDiscard()]
    public function identifiedBy(string $identifier): self
    {
        return new self(
            $this->headers,
            $this->claims,
            $this->audiences,
            $identifier,
            $this->issuer,
            $this->subject,
            $this->issuedAt,
            $this->notBefore,
            $this->expiresAt,
            $this->timeToLive,
        );
    }

    /**
     * Set the issuer (`iss`) claim expected by downstream validation rules.
     */
    #[NoDiscard()]
    public function issuedBy(string $issuer): self
    {
        return new self(
            $this->headers,
            $this->claims,
            $this->audiences,
            $this->identifier,
            $issuer,
            $this->subject,
            $this->issuedAt,
            $this->notBefore,
            $this->expiresAt,
            $this->timeToLive,
        );
    }

    /**
     * Set the subject (`sub`) claim identifying the principal represented by the token.
     */
    #[NoDiscard()]
    public function relatedTo(string $subject): self
    {
        return new self(
            $this->headers,
            $this->claims,
            $this->audiences,
            $this->identifier,
            $this->issuer,
            $subject,
            $this->issuedAt,
            $this->notBefore,
            $this->expiresAt,
            $this->timeToLive,
        );
    }

    /**
     * Append one or more audiences to the request without duplicating existing values.
     *
     * Audience order is preserved so callers can merge configuration defaults with
     * per-token audiences and still get deterministic output.
     *
     * @param non-empty-string ...$audiences
     */
    #[NoDiscard()]
    public function permittedFor(string ...$audiences): self
    {
        $toAppend = array_diff($audiences, $this->audiences);

        /** @var array<non-empty-string> $mergedAudiences */
        $mergedAudiences = array_values(array_merge($this->audiences, $toAppend));

        return new self(
            $this->headers,
            $this->claims,
            $mergedAudiences,
            $this->identifier,
            $this->issuer,
            $this->subject,
            $this->issuedAt,
            $this->notBefore,
            $this->expiresAt,
            $this->timeToLive,
        );
    }

    /**
     * Fix the issued-at (`iat`) timestamp instead of resolving it from runtime "now".
     */
    #[NoDiscard()]
    public function issuedAt(CarbonInterface $issuedAt): self
    {
        return new self(
            $this->headers,
            $this->claims,
            $this->audiences,
            $this->identifier,
            $this->issuer,
            $this->subject,
            $issuedAt,
            $this->notBefore,
            $this->expiresAt,
            $this->timeToLive,
        );
    }

    /**
     * Fix the not-before (`nbf`) timestamp that gates when the token becomes usable.
     */
    #[NoDiscard()]
    public function canOnlyBeUsedAfter(CarbonInterface $notBefore): self
    {
        return new self(
            $this->headers,
            $this->claims,
            $this->audiences,
            $this->identifier,
            $this->issuer,
            $this->subject,
            $this->issuedAt,
            $notBefore,
            $this->expiresAt,
            $this->timeToLive,
        );
    }

    /**
     * Fix the expiration (`exp`) timestamp explicitly.
     *
     * An explicit expiration wins over any previously configured TTL.
     */
    #[NoDiscard()]
    public function expiresAt(CarbonInterface $expiresAt): self
    {
        return new self(
            $this->headers,
            $this->claims,
            $this->audiences,
            $this->identifier,
            $this->issuer,
            $this->subject,
            $this->issuedAt,
            $this->notBefore,
            $expiresAt,
        );
    }

    /**
     * Configure a relative time-to-live used when no absolute expiration is set.
     *
     * Calling this clears any previously configured absolute expiration so that the
     * TTL becomes the active expiration strategy.
     */
    #[NoDiscard()]
    public function expiresAfter(DateInterval $timeToLive): self
    {
        return new self(
            $this->headers,
            $this->claims,
            $this->audiences,
            $this->identifier,
            $this->issuer,
            $this->subject,
            $this->issuedAt,
            $this->notBefore,
            null,
            $timeToLive,
        );
    }

    /**
     * Add a custom JOSE header when the header name is non-empty.
     *
     * Empty names are ignored to keep the request reusable in defensive call sites
     * that may forward optional configuration.
     */
    #[NoDiscard()]
    public function withHeader(string $name, mixed $value): self
    {
        if ($name === '') {
            return $this;
        }

        $headers = $this->headers;
        $headers[$name] = $value;

        return new self(
            $headers,
            $this->claims,
            $this->audiences,
            $this->identifier,
            $this->issuer,
            $this->subject,
            $this->issuedAt,
            $this->notBefore,
            $this->expiresAt,
            $this->timeToLive,
        );
    }

    /**
     * Add a custom claim when the claim name is non-empty.
     *
     * Registered claims are handled through the dedicated withers above so this
     * method only models extension claims.
     */
    #[NoDiscard()]
    public function withClaim(string $name, mixed $value): self
    {
        if ($name === '') {
            return $this;
        }

        $claims = $this->claims;
        $claims[$name] = $value;

        return new self(
            $this->headers,
            $claims,
            $this->audiences,
            $this->identifier,
            $this->issuer,
            $this->subject,
            $this->issuedAt,
            $this->notBefore,
            $this->expiresAt,
            $this->timeToLive,
        );
    }

    /**
     * Materialize this request into a concrete builder state.
     *
     * Resolution order is:
     * 1. Use the explicit issued-at value or runtime "now"
     * 2. Use the explicit not-before value or fall back to issued-at
     * 3. Use the explicit expiration value or derive one from TTL
     * 4. Apply optional registered claims when they are non-empty
     * 5. Append custom headers and claims last
     *
     * If neither an explicit expiration nor TTL exists, a default five-minute TTL
     * is used. Custom claims are delegated to the builder, so any builder-level
     * guards against reserved claim names still apply here.
     */
    public function applyTo(BuilderInterface $builder, CarbonInterface $now): BuilderInterface
    {
        $issuedAt = $this->issuedAt ?? $now;
        $notBefore = $this->notBefore ?? $issuedAt;
        $expiresAt = $this->expiresAt ?? $issuedAt->copy()->add($this->timeToLive ?? new DateInterval('PT5M'));

        $builder = $builder
            ->issuedAt($issuedAt)
            ->canOnlyBeUsedAfter($notBefore)
            ->expiresAt($expiresAt);

        if ($this->identifier !== null && $this->identifier !== '') {
            $builder = $builder->identifiedBy($this->identifier);
        }

        if ($this->issuer !== null && $this->issuer !== '') {
            $builder = $builder->issuedBy($this->issuer);
        }

        if ($this->subject !== null && $this->subject !== '') {
            $builder = $builder->relatedTo($this->subject);
        }

        if ($this->audiences !== []) {
            $builder = $builder->permittedFor(...$this->audiences);
        }

        foreach ($this->headers as $name => $value) {
            $builder = $builder->withHeader($name, $value);
        }

        foreach ($this->claims as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        return $builder;
    }

    /**
     * Merge this request with another request, producing a new effective blueprint.
     *
     * The incoming request wins for scalar fields when it provides a non-null value.
     * Header and claim maps are merged with later keys overwriting earlier ones, and
     * audiences are appended while preserving unique values.
     */
    #[NoDiscard()]
    public function merge(self $request): self
    {
        return new self(
            headers: [...$this->headers, ...$request->headers],
            claims: [...$this->claims, ...$request->claims],
            audiences: [...$this->audiences, ...array_diff($request->audiences, $this->audiences)],
            identifier: $request->identifier ?? $this->identifier,
            issuer: $request->issuer ?? $this->issuer,
            subject: $request->subject ?? $this->subject,
            issuedAt: $request->issuedAt ?? $this->issuedAt,
            notBefore: $request->notBefore ?? $this->notBefore,
            expiresAt: $request->expiresAt ?? $this->expiresAt,
            timeToLive: $request->timeToLive ?? $this->timeToLive,
        );
    }
}
