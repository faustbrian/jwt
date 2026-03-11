<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Token;

use Carbon\CarbonInterface;
use Cline\JWT\Contracts\BuilderInterface;
use Cline\JWT\Contracts\ClaimsFormatterInterface;
use Cline\JWT\Contracts\EncoderInterface;
use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Contracts\UnencryptedTokenInterface;
use Cline\JWT\Exceptions\CannotEncodeContent;
use Cline\JWT\Exceptions\RegisteredClaimGiven;
use Cline\JWT\Token\RegisteredClaims;
use NoDiscard;

use function array_diff;
use function array_filter;
use function array_merge;
use function array_values;
use function in_array;
use function is_array;
use function is_string;

/**
 * Immutable fluent builder for assembling signed JWTs before emission.
 *
 * The builder collects JOSE headers and claims in their rich PHP form, applies a
 * formatter immediately before encoding, and finally asks the selected signer to
 * produce the signature segment. Every mutator returns a fresh instance so partial
 * builder state can be reused safely across issuance flows.
 *
 * @immutable
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Builder implements BuilderInterface
{
    /**
     * @param array<non-empty-string, mixed> $headers
     * @param array<non-empty-string, mixed> $claims
     */
    private function __construct(
        private EncoderInterface $encoder,
        private ClaimsFormatterInterface $claimFormatter,
        private array $headers = ['typ' => 'JWT', 'alg' => null],
        private array $claims = [],
    ) {}

    /**
     * Create a new empty builder with the default `typ=JWT` header scaffolded in.
     */
    #[NoDiscard()]
    public static function new(EncoderInterface $encoder, ClaimsFormatterInterface $claimFormatter): self
    {
        return new self($encoder, $claimFormatter);
    }

    /**
     * Append unique audience values to the registered `aud` claim.
     */
    public function permittedFor(string ...$audiences): BuilderInterface
    {
        $configured = $this->claims[RegisteredClaims::AUDIENCE] ?? [];

        if (!is_array($configured)) {
            $configured = [];
        }

        /** @var array<non-empty-string> $configured */
        $configured = array_values(array_filter($configured, is_string(...)));
        $toAppend = array_diff($audiences, $configured);

        return $this->newWithClaim(RegisteredClaims::AUDIENCE, array_merge($configured, $toAppend));
    }

    /**
     * Set the expiration (`exp`) claim.
     */
    public function expiresAt(CarbonInterface $expiration): BuilderInterface
    {
        return $this->newWithClaim(RegisteredClaims::EXPIRATION_TIME, $expiration);
    }

    /**
     * Set the JWT ID (`jti`) claim.
     */
    public function identifiedBy(string $id): BuilderInterface
    {
        return $this->newWithClaim(RegisteredClaims::ID, $id);
    }

    /**
     * Set the issued-at (`iat`) claim.
     */
    public function issuedAt(CarbonInterface $issuedAt): BuilderInterface
    {
        return $this->newWithClaim(RegisteredClaims::ISSUED_AT, $issuedAt);
    }

    /**
     * Set the issuer (`iss`) claim.
     */
    public function issuedBy(string $issuer): BuilderInterface
    {
        return $this->newWithClaim(RegisteredClaims::ISSUER, $issuer);
    }

    /**
     * Set the not-before (`nbf`) claim.
     */
    public function canOnlyBeUsedAfter(CarbonInterface $notBefore): BuilderInterface
    {
        return $this->newWithClaim(RegisteredClaims::NOT_BEFORE, $notBefore);
    }

    /**
     * Set the subject (`sub`) claim.
     */
    public function relatedTo(string $subject): BuilderInterface
    {
        return $this->newWithClaim(RegisteredClaims::SUBJECT, $subject);
    }

    /**
     * Add or replace a JOSE header value on a cloned builder instance.
     */
    public function withHeader(string $name, mixed $value): BuilderInterface
    {
        $headers = $this->headers;
        $headers[$name] = $value;

        return new self(
            $this->encoder,
            $this->claimFormatter,
            $headers,
            $this->claims,
        );
    }

    /**
     * Add or replace a custom claim while guarding registered claim names.
     *
     * @throws RegisteredClaimGiven
     */
    public function withClaim(string $name, mixed $value): BuilderInterface
    {
        if (in_array($name, RegisteredClaims::ALL, true)) {
            throw RegisteredClaimGiven::forClaim($name);
        }

        return $this->newWithClaim($name, $value);
    }

    /**
     * Encode the current builder state, sign it, and return the resulting token.
     *
     * The signer's algorithm identifier is injected into the JOSE header just
     * before encoding so callers do not need to manage `alg` manually.
     */
    public function getToken(SignerInterface $signer, KeyInterface $key): UnencryptedTokenInterface
    {
        $headers = $this->headers;
        $headers['alg'] = $signer->algorithmId();

        $encodedHeaders = $this->encode($headers);
        $encodedClaims = $this->encode($this->claimFormatter->formatClaims($this->claims));

        $signature = $signer->sign($encodedHeaders.'.'.$encodedClaims, $key);
        $encodedSignature = $this->encoder->base64UrlEncode($signature);

        return new Plain(
            new Headers($headers, $encodedHeaders),
            new Claims($this->claims, $encodedClaims),
            new Signature($signature, $encodedSignature),
        );
    }

    /**
     * Clone the builder with one claim value changed.
     *
     * @param non-empty-string $name
     */
    private function newWithClaim(string $name, mixed $value): BuilderInterface
    {
        $claims = $this->claims;
        $claims[$name] = $value;

        return new self(
            $this->encoder,
            $this->claimFormatter,
            $this->headers,
            $claims,
        );
    }

    /**
     * JSON-encode and Base64Url-encode a token segment in one step.
     *
     * @param array<non-empty-string, mixed> $items
     *
     * @throws CannotEncodeContent When data cannot be converted to JSON.
     */
    private function encode(array $items): string
    {
        return $this->encoder->base64UrlEncode(
            $this->encoder->jsonEncode($items),
        );
    }
}
