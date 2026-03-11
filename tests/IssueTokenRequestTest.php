<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Cline\JWT\Contracts\BuilderInterface;
use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Contracts\UnencryptedTokenInterface;
use Cline\JWT\IssueTokenRequest;
use Cline\JWT\Token\RegisteredClaims;
use Cline\JWT\Token\RegisteredHeaders;
use Tests\Exceptions\TestStubMethodWasCalled;

beforeEach(function (): void {
    $this->builder = new class() implements BuilderInterface
    {
        public array $calls = [];

        public array $headers = [];

        public array $claims = [];

        public array $audiences = [];

        public function permittedFor(string ...$audiences): self
        {
            $this->calls[] = ['permittedFor', $audiences];
            $this->audiences = $audiences;

            return $this;
        }

        public function expiresAt(CarbonInterface $expiration): self
        {
            $this->calls[] = ['expiresAt', $expiration];
            $this->claims['exp'] = $expiration;

            return $this;
        }

        public function identifiedBy(string $id): self
        {
            $this->calls[] = ['identifiedBy', $id];
            $this->claims['jti'] = $id;

            return $this;
        }

        public function issuedAt(CarbonInterface $issuedAt): self
        {
            $this->calls[] = ['issuedAt', $issuedAt];
            $this->claims['iat'] = $issuedAt;

            return $this;
        }

        public function issuedBy(string $issuer): self
        {
            $this->calls[] = ['issuedBy', $issuer];
            $this->claims['iss'] = $issuer;

            return $this;
        }

        public function canOnlyBeUsedAfter(CarbonInterface $notBefore): self
        {
            $this->calls[] = ['canOnlyBeUsedAfter', $notBefore];
            $this->claims['nbf'] = $notBefore;

            return $this;
        }

        public function relatedTo(string $subject): self
        {
            $this->calls[] = ['relatedTo', $subject];
            $this->claims['sub'] = $subject;

            return $this;
        }

        public function withHeader(string $name, mixed $value): self
        {
            $this->calls[] = ['withHeader', $name, $value];
            $this->headers[$name] = $value;

            return $this;
        }

        public function withClaim(string $name, mixed $value): self
        {
            $this->calls[] = ['withClaim', $name, $value];
            $this->claims[$name] = $value;

            return $this;
        }

        public function getToken(SignerInterface $signer, KeyInterface $key): UnencryptedTokenInterface
        {
            throw TestStubMethodWasCalled::notNeeded();
        }
    };
});

test('withers return new immutable requests and ignore empty custom names', function (): void {
    $issuedAt = CarbonImmutable::parse('2025-01-01 12:00:00');
    $notBefore = $issuedAt->addMinute();
    $expiresAt = $issuedAt->addMinutes(5);
    $ttl = new DateInterval('PT10M');

    $base = new IssueTokenRequest();
    $request = $base
        ->identifiedBy('token-1')
        ->issuedBy('https://issuer.test')
        ->relatedTo('user-1')
        ->permittedFor('web', 'admin', 'web')
        ->issuedAt($issuedAt)
        ->canOnlyBeUsedAfter($notBefore)
        ->expiresAt($expiresAt)
        ->expiresAfter($ttl)
        ->withHeader('', 'ignored')
        ->withHeader('kid', 'key-1')
        ->withClaim('', 'ignored')
        ->withClaim('tenant', 'acme');

    expect($request)->not->toBe($base);

    $request->applyTo($this->builder, $issuedAt);

    expect($this->builder->claims['jti'])->toBe('token-1')
        ->and($this->builder->claims['iss'])->toBe('https://issuer.test')
        ->and($this->builder->claims['sub'])->toBe('user-1')
        ->and($this->builder->claims['tenant'])->toBe('acme')
        ->and($this->builder->headers['kid'])->toBe('key-1')
        ->and($this->builder->headers)->not->toHaveKey('')
        ->and($this->builder->claims)->not->toHaveKey('')
        ->and($this->builder->audiences)->toBe(['web', 'admin', 'web'])
        ->and($this->builder->claims['exp']->equalTo($issuedAt->copy()->add($ttl)))->toBeTrue();
});

test('applyTo uses explicit timestamps and falls back to defaults when absent', function (): void {
    $now = CarbonImmutable::parse('2025-03-01 10:00:00');
    $issuedAt = $now->subMinute();
    $request = new IssueTokenRequest()
        ->issuedAt($issuedAt)
        ->canOnlyBeUsedAfter($issuedAt->addSecond())
        ->expiresAt($issuedAt->addMinutes(2));

    $request->applyTo($this->builder, $now);

    expect($this->builder->claims['iat']->equalTo($issuedAt))->toBeTrue()
        ->and($this->builder->claims['nbf']->equalTo($issuedAt->addSecond()))->toBeTrue()
        ->and($this->builder->claims['exp']->equalTo($issuedAt->addMinutes(2)))->toBeTrue();

    $builder = clone $this->builder;
    $freshRequest = new IssueTokenRequest();
    $freshRequest->applyTo($builder, $now);

    expect($builder->claims['iat']->equalTo($now))->toBeTrue()
        ->and($builder->claims['nbf']->equalTo($now))->toBeTrue()
        ->and($builder->claims['exp']->equalTo($now->copy()->add(
            new DateInterval('PT5M'),
        )))->toBeTrue();
});

test('merge combines maps, preserves unique audiences, and lets incoming scalar values win', function (): void {
    $base = new IssueTokenRequest()
        ->identifiedBy('base-id')
        ->issuedBy('base-issuer')
        ->relatedTo('base-subject')
        ->permittedFor('web', 'admin')
        ->withHeader('kid', 'base')
        ->withClaim('tenant', 'base');

    $incoming = new IssueTokenRequest()
        ->identifiedBy('next-id')
        ->issuedBy('next-issuer')
        ->relatedTo('next-subject')
        ->permittedFor('admin', 'mobile')
        ->withHeader('typ', 'JWT')
        ->withClaim('scope', 'write');

    $merged = $base->merge($incoming);

    $merged->applyTo($this->builder, CarbonImmutable::parse('2025-01-01 00:00:00'));

    expect($this->builder->claims['jti'])->toBe('next-id')
        ->and($this->builder->claims['iss'])->toBe('next-issuer')
        ->and($this->builder->claims['sub'])->toBe('next-subject')
        ->and($this->builder->claims['tenant'])->toBe('base')
        ->and($this->builder->claims['scope'])->toBe('write')
        ->and($this->builder->headers['kid'])->toBe('base')
        ->and($this->builder->headers['typ'])->toBe('JWT')
        ->and($this->builder->audiences)->toBe(['web', 'admin', 'mobile']);
});

test('registered constants utility classes expose constant sets and reject normal construction', function (): void {
    expect(RegisteredClaims::ALL)->toContain(
        RegisteredClaims::AUDIENCE,
        RegisteredClaims::EXPIRATION_TIME,
        RegisteredClaims::ID,
        RegisteredClaims::ISSUED_AT,
        RegisteredClaims::ISSUER,
        RegisteredClaims::NOT_BEFORE,
        RegisteredClaims::SUBJECT,
    )->and(RegisteredClaims::DATE_CLAIMS)->toBe([
        RegisteredClaims::ISSUED_AT,
        RegisteredClaims::NOT_BEFORE,
        RegisteredClaims::EXPIRATION_TIME,
    ])->and(RegisteredHeaders::ALGORITHM)->toBe('alg')
        ->and(RegisteredHeaders::CONTENT_TYPE)->toBe('cty')
        ->and(RegisteredHeaders::KEY_ID)->toBe('kid')
        ->and(RegisteredHeaders::TYPE)->toBe('typ');

    $claimsConstructor = new ReflectionClass(RegisteredClaims::class)->getConstructor();
    $headersConstructor = new ReflectionClass(RegisteredHeaders::class)->getConstructor();

    expect($claimsConstructor)->not->toBeNull()
        ->and($headersConstructor)->not->toBeNull()
        ->and($claimsConstructor?->isPrivate())->toBeTrue()
        ->and($headersConstructor?->isPrivate())->toBeTrue();
});
